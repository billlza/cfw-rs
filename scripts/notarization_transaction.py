#!/usr/bin/env python3
"""Run the durable app-notarization and atomic publication transaction.

The build shell owns compilation and inside-out signing.  This module takes the
already signed Host app and owns the first irreversible remote side effect:
notary submission.  A build/lane attempt is claimed exactly once, the exact
submitted app and archive survive every failure, untrusted command output is
only parsed in memory, and the public ``signed`` directory appears in one
non-overwriting rename after every verification and manifest is complete.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Callable
import uuid

if __package__:
    from .candidate_artifact_binding import (
        TOOLCHAIN_METADATA_ORDER,
        derive_candidate_toolchain_metadata,
    )
    from .gatekeeper_assessment import (
        capture as capture_gatekeeper,
        validate_evidence as validate_gatekeeper_evidence,
    )
    from .hash_artifact import build_manifest, write_new_manifest
    from .release_build_identity import canonical_build_version
    from .repository_source_identity import current_identity
    from .verify_notary_log import (
        NotaryLogError,
        validate_documents,
        validate_normalized_documents,
    )
    from .verify_artifact_manifest import MAX_MANIFEST_BYTES
    from .validate_notary_archive import (
        NotaryArchiveError,
        validate_notarization_zip,
    )
else:
    from candidate_artifact_binding import (
        TOOLCHAIN_METADATA_ORDER,
        derive_candidate_toolchain_metadata,
    )
    from gatekeeper_assessment import (
        capture as capture_gatekeeper,
        validate_evidence as validate_gatekeeper_evidence,
    )
    from hash_artifact import build_manifest, write_new_manifest
    from release_build_identity import canonical_build_version
    from repository_source_identity import current_identity
    from verify_notary_log import (
        NotaryLogError,
        validate_documents,
        validate_normalized_documents,
    )
    from verify_artifact_manifest import MAX_MANIFEST_BYTES
    from validate_notary_archive import (
        NotaryArchiveError,
        validate_notarization_zip,
    )


VERSION = "0.4.0"
EXPECTED_TEAM_ID = "YKUPL7Z869"
ATTEMPT_DOCUMENT = "cfw-notarization-attempt-v1"
EVENT_DOCUMENT = "cfw-notarization-event-v1"
SUBMISSION_DOCUMENT = "cfw-notarization-submission-receipt-v1"
RECEIPT_DOCUMENT = "cfw-notarization-publish-ready-receipt-v1"
RENAME_EXCL = 0x00000004
RENAME_NOFOLLOW_ANY = 0x00000010
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DEPLOYMENT_TARGET_RE = re.compile(r"^[0-9]+\.[0-9]+$")
TOOLCHAIN_METADATA_KEYS = set(TOOLCHAIN_METADATA_ORDER)
FINAL_INVENTORY_TEMPLATE = {
    "Clash for Mac.app",
    "Clash for Mac.app.manifest.json",
    "notarization.json",
    "notarization-log.json",
    "gatekeeper.json",
}
_SINGLE_SIGNATURE_DIAGNOSTIC_PREFIX = "Only one signature found in "
_SINGLE_SIGNATURE_DIAGNOSTIC_SUFFIX = ", skipping dual signature check\n"
_KNOWN_NOTARY_FALSE_POSITIVE_LONG_ERROR = (
    "Gatekeeper rejected this file. If there isn't a more descriptive error "
    "elsewhere in this output, please file a Feedback through Feedback "
    "Assistant.app so we can continue to improve syspolicy_check. Please include "
    "the app bundle you are checking and a sysdiagnose taken immediately after "
    "running syspolicy_check."
)
_MISSING_TICKET_LONG_ERROR = (
    "A Notarization ticket is not stapled to this application."
)
_MISSING_TICKET_ADVICE = (
    "If this application has already been uploaded to the Apple notary service, "
    "please make sure to attach the ticket with the `stapler staple` command. If "
    "not, please upload to the Apple notary service using Xcode or via "
    "`notarytool`. "
)


class TransactionError(RuntimeError):
    """The notarization transaction failed without claiming success."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        terminal_state: str = "failed",
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.terminal_state = terminal_state
        self.exit_code = exit_code


class DuplicateKeyError(ValueError):
    """A command returned a JSON object with repeated fields."""


class CommandRole(Enum):
    NOTARY_READINESS = "notary-readiness"
    NOTARY_READINESS_CORROBORATION = "notary-readiness-corroboration"
    SUBMIT = "submit"
    WAIT = "wait"
    FETCH_LOG = "fetch-log"
    STAPLE = "staple"
    STAPLE_VALIDATE = "staple-validate"
    FINAL_VERIFY = "final-verify"
    DISTRIBUTION_CHECK = "distribution-check"


class PreSubmissionPolicyMode(Enum):
    NATIVE = "native"
    MACOS_27_26A5388G_COMPATIBILITY = "macos-27-26A5388g-compatibility"


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class HostSystemIdentity:
    product_name: str
    product_version: str
    build_version: str
    kernel_name: str
    kernel_release: str
    architecture: str


KNOWN_MACOS_27_COMPATIBILITY_IDENTITY = HostSystemIdentity(
    product_name="macOS",
    product_version="27.0",
    build_version="26A5388g",
    kernel_name="Darwin",
    kernel_release="27.0.0",
    architecture="arm64",
)


@dataclass(frozen=True)
class PersistedEvidenceSnapshot:
    gatekeeper: dict[str, Any]
    notarization_sha256: str
    notary_log_sha256: str
    gatekeeper_sha256: str


@dataclass(frozen=True)
class TransactionContext:
    repository: Path
    build_kind: str
    build_number: str
    staged_app: Path
    native_products: Path
    notary_profile: str
    repository_commit: str
    release_source_sha256: str
    deployment_target: str
    toolchain_metadata: dict[str, str]

    @property
    def candidate_base(self) -> Path:
        return self.repository / "target/candidates/0.4.0"

    @property
    def build_root(self) -> Path:
        if self.build_kind == "validation":
            return self.candidate_base / "validation" / self.build_number
        return self.candidate_base / "release-build" / self.build_number

    @property
    def attempt_root(self) -> Path:
        return (
            self.candidate_base
            / "notary-attempts"
            / self.build_kind
            / self.build_number
        )

    @property
    def final_root(self) -> Path:
        if self.build_kind == "validation":
            return self.build_root / "signed"
        return self.candidate_base / "signed"

    @property
    def artifact_kind(self) -> str:
        if self.build_kind == "validation":
            return "notarized-validation-candidate-v1"
        return "notarized-release-v1"

    @property
    def archive_name(self) -> str:
        return f"Clash.for.Mac_{VERSION}_{self.build_number}_notary.zip"

    @property
    def source_identity(self) -> dict[str, str]:
        return {
            "repositoryCommit": self.repository_commit,
            "releaseSourceSha256": self.release_source_sha256,
        }


CommandRunner = Callable[[CommandRole, list[str], float], CommandResult]
ArchiveBuilder = Callable[[Path, Path], None]
ArchiveValidator = Callable[[Path, Path], None]
GatekeeperCapture = Callable[[Path, str], dict[str, Any]]
ManifestWriter = Callable[[Path, Path, dict[str, str]], None]
ManifestVerifier = Callable[[Path, Path, dict[str, str]], None]
SourceIdentityReader = Callable[[Path], dict[str, str]]
ToolchainMetadataReader = Callable[[Path], dict[str, str]]
Publisher = Callable[[Path, Path], None]
Clock = Callable[[], str]
AttemptIdFactory = Callable[[], str]
HostSystemIdentityReader = Callable[[], HostSystemIdentity]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON field: {key}")
        value[key] = child
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def _transaction_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _hash_regular_file(path: Path) -> tuple[str, int]:
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise TransactionError(
            "unsafe_file",
            f"transaction file must be a single-link regular file: {path.name}",
        )
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _transaction_file_identity(metadata) != _transaction_file_identity(opened):
            raise TransactionError("file_race", f"file changed while opening: {path.name}")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise TransactionError(
                "unsafe_file", f"opened transaction file is unsafe: {path.name}"
            )
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise TransactionError(
                    "file_race", f"file changed while hashing: {path.name}"
                )
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TransactionError(
                "file_race", f"file changed while hashing: {path.name}"
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _transaction_file_identity(opened) != _transaction_file_identity(after)
        or after.st_nlink != 1
    ):
        raise TransactionError("file_race", f"file changed while hashing: {path.name}")
    try:
        rebound = os.lstat(path)
    except OSError as error:
        raise TransactionError(
            "file_race", f"file changed after hashing: {path.name}"
        ) from error
    if _transaction_file_identity(opened) != _transaction_file_identity(rebound):
        raise TransactionError("file_race", f"file changed after hashing: {path.name}")
    return digest.hexdigest(), opened.st_size


def _sha256_file(path: Path) -> str:
    return _hash_regular_file(path)[0]


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_regular_file(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TransactionError(
                "unsafe_fsync_target", f"fsync target is not a regular file: {path.name}"
            )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_tree(root: Path) -> None:
    _require_real_directory(root, private=True)
    directories: list[Path] = []

    def walk_error(error: OSError) -> None:
        raise TransactionError(
            "publish_tree_walk_failed", "cannot enumerate the complete publish tree"
        ) from error

    for current, names, files in os.walk(
        root,
        topdown=True,
        onerror=walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        directories.append(current_path)
        names[:] = [
            name
            for name in names
            if not (current_path / name).is_symlink()
        ]
        for name in files:
            path = current_path / name
            metadata = os.lstat(path)
            if stat.S_ISREG(metadata.st_mode):
                _fsync_regular_file(path)
            elif not stat.S_ISLNK(metadata.st_mode):
                raise TransactionError(
                    "unsafe_publish_entry",
                    f"publish tree contains an unsupported entry: {path.name}",
                )
    for directory in reversed(directories):
        _fsync_directory(directory)


def _require_real_directory(
    path: Path,
    *,
    private: bool = False,
    trusted: bool = False,
) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise TransactionError("missing_directory", f"directory is absent: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise TransactionError("unsafe_directory", f"path is not a real directory: {path}")
    if trusted or private:
        if metadata.st_uid != os.geteuid():
            raise TransactionError("unsafe_owner", f"directory owner differs: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise TransactionError(
                "unsafe_mode", f"directory is group/world writable: {path}"
            )
    if private:
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise TransactionError("unsafe_mode", f"private directory mode is not 0700: {path}")


def _mkdir_private(path: Path, *, exclusive: bool) -> None:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError as error:
        if exclusive:
            raise TransactionError(
                "attempt_exists",
                "this lane/build already has a notarization attempt and must not be resubmitted",
            ) from error
        _require_real_directory(path, private=True)
        return
    except OSError as error:
        raise TransactionError(
            "mkdir_failed", f"cannot create private directory: {path}"
        ) from error
    _require_real_directory(path, private=True)
    _fsync_directory(path.parent)


def _write_json_exclusive(path: Path, value: object) -> None:
    encoded = _canonical_json(value)
    try:
        write_new_manifest(path, encoded)
    except (OSError, ValueError) as error:
        raise TransactionError(
            "evidence_write_failed", f"cannot persist transaction evidence: {path.name}"
        ) from error


def _read_regular_bytes(path: Path, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise TransactionError("evidence_missing", f"evidence is absent: {path.name}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        raise TransactionError(
            "unsafe_evidence", f"evidence is not a bounded regular file: {path.name}"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _transaction_file_identity(before) != _transaction_file_identity(opened):
            raise TransactionError("evidence_race", f"evidence changed: {path.name}")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise TransactionError("unsafe_evidence", f"opened evidence is unsafe: {path.name}")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _transaction_file_identity(opened) != _transaction_file_identity(after)
        or after.st_nlink != 1
    ):
        raise TransactionError("evidence_race", f"evidence changed: {path.name}")
    if len(data) != opened.st_size or len(data) > maximum:
        raise TransactionError("evidence_race", f"evidence size changed: {path.name}")
    try:
        rebound = os.lstat(path)
    except OSError as error:
        raise TransactionError(
            "evidence_race", f"evidence changed after reading: {path.name}"
        ) from error
    if _transaction_file_identity(opened) != _transaction_file_identity(rebound):
        raise TransactionError(
            "evidence_race", f"evidence changed after reading: {path.name}"
        )
    return bytes(data)


def _decode_json_bytes(data: bytes, path: Path) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (UnicodeError, json.JSONDecodeError, DuplicateKeyError) as error:
        raise TransactionError(
            "invalid_evidence_json", f"evidence is not strict UTF-8 JSON: {path.name}"
        ) from error


def _read_exact_json_document(
    path: Path,
    expected: dict[str, Any],
    *,
    drift_code: str,
    drift_message: str,
) -> tuple[dict[str, Any], str]:
    data = _read_regular_bytes(path)
    expected_data = _canonical_json(expected).encode("utf-8")
    if data != expected_data:
        raise TransactionError(drift_code, drift_message)
    value = _decode_json_bytes(data, path)
    if not isinstance(value, dict) or value != expected:
        raise TransactionError(drift_code, drift_message)
    return value, hashlib.sha256(data).hexdigest()


def _parse_command_json(output: str) -> Any:
    try:
        encoded = output.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise TransactionError("invalid_command_output", "command output is not UTF-8") from error
    if not encoded or len(encoded) > MAX_COMMAND_OUTPUT_BYTES or b"\0" in encoded:
        raise TransactionError("invalid_command_output", "command output is empty or oversized")
    try:
        return json.loads(output, object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, DuplicateKeyError) as error:
        raise TransactionError(
            "invalid_command_output", "command output is not strict JSON"
        ) from error


def _canonical_uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        raise TransactionError("invalid_submission_id", f"{label} is not a UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise TransactionError("invalid_submission_id", f"{label} is not a UUID") from error
    if str(parsed) != value:
        raise TransactionError("invalid_submission_id", f"{label} is not canonical UUID text")
    return value


def _parse_notary_response(
    output: str,
    *,
    allowed_statuses: set[str],
) -> tuple[str, str]:
    value = _parse_command_json(output)
    fields = set(value) if isinstance(value, dict) else set()
    if fields not in ({"id", "status"}, {"id", "message", "status"}):
        raise TransactionError(
            "invalid_notary_response", "notarytool response has an unexpected field set"
        )
    if "message" in value:
        message = value["message"]
        if (
            not isinstance(message, str)
            or not message
            or len(message) > 4096
            or "\0" in message
        ):
            raise TransactionError(
                "invalid_notary_response", "notarytool message is malformed"
            )
    status_value = value["status"]
    if not isinstance(status_value, str) or status_value not in allowed_statuses:
        raise TransactionError("invalid_notary_status", "notarytool status is unsupported")
    return _canonical_uuid(value["id"], "notarytool submission id"), status_value


def _run_bounded_process(
    command: list[str],
    timeout: float,
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
) -> CommandResult:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise TransactionError(
            "command_start_failed",
            "release command could not start",
        ) from error
    if process.stdout is None or process.stderr is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise TransactionError("command_pipe_failed", "release command pipes are absent")
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    selector = selectors.DefaultSelector()
    buffers = {
        stdout_fd: bytearray(),
        stderr_fd: bytearray(),
    }
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransactionError(
                    "command_timeout", "release command exceeded its time limit"
                )
            for key, _events in selector.select(min(remaining, 1.0)):
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.fd].extend(chunk)
                if sum(len(buffer) for buffer in buffers.values()) > MAX_COMMAND_OUTPUT_BYTES:
                    raise TransactionError(
                        "command_output_oversized",
                        "release command output exceeded the safety limit",
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransactionError(
                "command_timeout", "release command exceeded its time limit"
            )
        returncode = process.wait(timeout=remaining)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            os.killpg(process.pid, signal.SIGKILL)
            raise TransactionError(
                "command_descendant_survived",
                "release command left a descendant process running",
            )
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise TransactionError(
            "command_timeout", "release command exceeded its time limit"
        ) from error
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    try:
        stdout = bytes(buffers[stdout_fd]).decode("utf-8", errors="strict")
        stderr = bytes(buffers[stderr_fd]).decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise TransactionError(
            "command_output_invalid_utf8", "release command output is not UTF-8"
        ) from error
    return CommandResult(returncode, stdout, stderr)


def production_command_runner(
    _role: CommandRole,
    command: list[str],
    timeout: float,
) -> CommandResult:
    return _run_bounded_process(command, timeout)


def production_archive_builder(app: Path, archive: Path) -> None:
    if app.parent != archive.parent:
        raise TransactionError(
            "unsafe_archive_path",
            "notarization archive must share the signed app staging directory",
        )
    if os.path.lexists(archive):
        raise TransactionError(
            "archive_exists",
            "notarization archive destination already exists",
        )
    environment = dict(os.environ)
    environment["COPYFILE_DISABLE"] = "1"
    try:
        completed = _run_bounded_process(
            [
                "/usr/bin/ditto",
                "-c",
                "-k",
                "--keepParent",
                "--norsrc",
                "--noextattr",
                "--noqtn",
                "--noacl",
                app.name,
                archive.name,
            ],
            cwd=app.parent,
            timeout=1800,
            environment=environment,
        )
    except TransactionError as error:
        raise TransactionError(
            "archive_creation_failed", "notarization archive creation did not complete"
        ) from error
    if completed.returncode != 0:
        raise TransactionError(
            "archive_creation_failed",
            "notarization archive creation failed",
            exit_code=completed.returncode,
        )
    os.chmod(archive, 0o600, follow_symlinks=False)
    _fsync_directory(archive.parent)


def production_archive_validator(archive: Path, app: Path) -> None:
    try:
        validate_notarization_zip(archive, app)
    except (NotaryArchiveError, OSError) as error:
        raise TransactionError(
            "archive_validation_failed",
            "notarization archive differs from the signed application",
        ) from error


def _read_exact_system_identity_value(
    command: list[str],
    label: str,
) -> str:
    result = _run_bounded_process(command, 30)
    if result.returncode != 0 or result.stderr:
        raise TransactionError(
            "host_system_identity_unavailable",
            f"cannot read the release host {label}",
            exit_code=result.returncode,
        )
    if (
        not result.stdout.endswith("\n")
        or result.stdout.count("\n") != 1
        or len(result.stdout) > 256
        or "\0" in result.stdout
    ):
        raise TransactionError(
            "host_system_identity_invalid",
            f"release host {label} is malformed",
        )
    value = result.stdout[:-1]
    if not value or any(character.isspace() for character in value):
        raise TransactionError(
            "host_system_identity_invalid",
            f"release host {label} is malformed",
        )
    return value


def production_host_system_identity_reader() -> HostSystemIdentity:
    return HostSystemIdentity(
        product_name=_read_exact_system_identity_value(
            ["/usr/bin/sw_vers", "-productName"], "product name"
        ),
        product_version=_read_exact_system_identity_value(
            ["/usr/bin/sw_vers", "-productVersion"], "product version"
        ),
        build_version=_read_exact_system_identity_value(
            ["/usr/bin/sw_vers", "-buildVersion"], "build version"
        ),
        kernel_name=_read_exact_system_identity_value(
            ["/usr/bin/uname", "-s"], "kernel name"
        ),
        kernel_release=_read_exact_system_identity_value(
            ["/usr/bin/uname", "-r"], "kernel release"
        ),
        architecture=_read_exact_system_identity_value(
            ["/usr/bin/uname", "-m"], "architecture"
        ),
    )


def production_gatekeeper_capture(app: Path, tree_sha256: str) -> dict[str, Any]:
    core = capture_gatekeeper(
        app,
        "execute",
        primary_signature_context=False,
    )
    return validate_gatekeeper_evidence(
        {
            **core,
            "target_signed_app_tree_sha256": tree_sha256,
            "captured_at": _utc_now(),
        }
    )


def production_manifest_writer(
    artifact: Path,
    manifest: Path,
    metadata: dict[str, str],
) -> None:
    try:
        document = build_manifest(
            artifact,
            metadata,
            algorithm="sha256-tree-v2",
        )
        write_new_manifest(manifest, json.dumps(document, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError) as error:
        raise TransactionError(
            "manifest_write_failed", f"cannot write artifact manifest: {manifest.name}"
        ) from error


def production_manifest_verifier(
    artifact: Path,
    manifest: Path,
    metadata: dict[str, str],
) -> None:
    try:
        manifest_bytes = _read_regular_bytes(manifest, MAX_MANIFEST_BYTES)
        value = _decode_json_bytes(manifest_bytes, manifest)
        if not isinstance(value, dict) or value.get("algorithm") != "sha256-tree-v2":
            raise TransactionError(
                "manifest_verification_failed",
                f"artifact manifest is not sha256-tree-v2: {manifest.name}",
            )
        actual = build_manifest(
            artifact,
            metadata,
            algorithm="sha256-tree-v2",
        )
    except TransactionError:
        raise
    except (OSError, ValueError) as error:
        raise TransactionError(
            "manifest_verification_failed",
            f"cannot verify artifact manifest: {manifest.name}",
        ) from error
    if value != actual:
        raise TransactionError(
            "manifest_verification_failed",
            f"artifact manifest differs from the exact artifact: {manifest.name}",
        )
    if _read_regular_bytes(manifest, MAX_MANIFEST_BYTES) != manifest_bytes:
        raise TransactionError(
            "manifest_verification_failed",
            f"artifact manifest changed during verification: {manifest.name}",
        )


def _run_manifest_verification_barrier(
    configured_verifier: ManifestVerifier,
    verifications: tuple[tuple[Path, Path, dict[str, str]], ...],
) -> None:
    _run_configured_manifest_verification_hooks(
        configured_verifier,
        verifications,
    )
    _run_production_manifest_verifications(verifications)


def _run_configured_manifest_verification_hooks(
    configured_verifier: ManifestVerifier,
    verifications: tuple[tuple[Path, Path, dict[str, str]], ...],
) -> None:
    if configured_verifier is not production_manifest_verifier:
        for artifact, manifest, metadata in verifications:
            configured_verifier(artifact, manifest, metadata)


def _run_production_manifest_verifications(
    verifications: tuple[tuple[Path, Path, dict[str, str]], ...],
) -> None:
    for artifact, manifest, metadata in verifications:
        production_manifest_verifier(artifact, manifest, metadata)


def _app_tree_sha256(
    app: Path,
    *,
    failure_code: str,
    failure_message: str,
) -> str:
    try:
        value = build_manifest(app, algorithm="sha256-tree-v2")["sha256"]
    except (OSError, ValueError) as error:
        raise TransactionError(failure_code, failure_message) from error
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise TransactionError(failure_code, failure_message)
    return value


def production_source_identity_reader(repository: Path) -> dict[str, str]:
    return current_identity(repository, require_clean=True)


def production_toolchain_metadata_reader(repository: Path) -> dict[str, str]:
    return derive_candidate_toolchain_metadata(repository)


def publish_exclusive(source: Path, destination: Path) -> None:
    if not source.is_absolute() or not destination.is_absolute():
        raise TransactionError("unsafe_publish_path", "publish paths must be absolute")
    _require_real_directory(source, private=True)
    _require_real_directory(destination.parent, trusted=True)
    if os.path.lexists(destination):
        raise TransactionError("publish_destination_exists", "signed output already exists")
    source_parent = source.parent
    if os.lstat(source).st_dev != os.lstat(destination.parent).st_dev:
        raise TransactionError("cross_device_publish", "atomic publication requires one volume")
    if sys.platform != "darwin":
        raise TransactionError("unsupported_publish_platform", "RENAME_EXCL requires macOS")
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(
        os.fsencode(source),
        os.fsencode(destination),
        RENAME_EXCL | RENAME_NOFOLLOW_ANY,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            failure = "publish_destination_exists"
        elif code == errno.EXDEV:
            failure = "cross_device_publish"
        else:
            failure = "atomic_publish_failed"
        raise TransactionError(failure, "exclusive atomic directory publication failed")
    try:
        _fsync_directory(destination.parent)
        if source_parent != destination.parent:
            _fsync_directory(source_parent)
    except OSError as error:
        raise TransactionError(
            "publish_durability_unknown",
            "signed output was atomically published but parent durability is unconfirmed",
            terminal_state="outcome_unknown",
        ) from error


class EventJournal:
    def __init__(self, directory: Path, intent_sha256: str, clock: Clock) -> None:
        self.directory = directory
        self.intent_sha256 = intent_sha256
        self.clock = clock
        self.sequence = 0
        self.previous_event_sha256: str | None = None
        self.documents: list[dict[str, Any]] = []

    def append(
        self,
        state: str,
        *,
        submission_id: str | None = None,
        failure_code: str | None = None,
        exit_code: int | None = None,
        recorded_at: str | None = None,
    ) -> None:
        next_sequence = self.sequence + 1
        document = {
            "schema_version": 1,
            "document": EVENT_DOCUMENT,
            "sequence": next_sequence,
            "previous_event_sha256": self.previous_event_sha256,
            "intent_sha256": self.intent_sha256,
            "state": state,
            "recorded_at": self.clock() if recorded_at is None else recorded_at,
            "submission_id": submission_id,
            "failure_code": failure_code,
            "exit_code": exit_code,
        }
        path = self.directory / f"{next_sequence:08d}.json"
        _write_json_exclusive(path, document)
        event_sha256 = _sha256_file(path)
        self.sequence = next_sequence
        self.previous_event_sha256 = event_sha256
        self.documents.append(document)

    def verify(self) -> str:
        expected_names = {
            f"{sequence:08d}.json"
            for sequence in range(1, len(self.documents) + 1)
        }
        try:
            observed_names = {path.name for path in self.directory.iterdir()}
        except OSError as error:
            raise TransactionError(
                "event_journal_identity_drift",
                "cannot enumerate the notarization event journal",
            ) from error
        if observed_names != expected_names:
            raise TransactionError(
                "event_journal_identity_drift",
                "notarization event journal inventory changed",
            )

        previous_sha256: str | None = None
        for sequence, expected in enumerate(self.documents, start=1):
            if (
                expected["sequence"] != sequence
                or expected["previous_event_sha256"] != previous_sha256
                or expected["intent_sha256"] != self.intent_sha256
            ):
                raise TransactionError(
                    "event_journal_identity_drift",
                    "in-memory notarization event chain is inconsistent",
                )
            _, event_sha256 = _read_exact_json_document(
                self.directory / f"{sequence:08d}.json",
                expected,
                drift_code="event_journal_identity_drift",
                drift_message="notarization event journal changed",
            )
            previous_sha256 = event_sha256
        if previous_sha256 is None or previous_sha256 != self.previous_event_sha256:
            raise TransactionError(
                "event_journal_identity_drift",
                "notarization event journal head changed",
            )
        return previous_sha256


def _validate_context(context: TransactionContext) -> None:
    repository = context.repository
    if not repository.is_absolute() or repository.is_symlink():
        raise TransactionError("unsafe_repository", "repository must be an absolute real path")
    _require_real_directory(repository, trusted=True)
    if context.build_kind not in ("validation", "release"):
        raise TransactionError("invalid_build_kind", "build kind is unsupported")
    canonical_build_version(context.build_number, "build number")
    if not COMMIT_RE.fullmatch(context.repository_commit):
        raise TransactionError("invalid_source_identity", "repository commit is malformed")
    if not SHA256_RE.fullmatch(context.release_source_sha256):
        raise TransactionError("invalid_source_identity", "release source digest is malformed")
    if not DEPLOYMENT_TARGET_RE.fullmatch(context.deployment_target):
        raise TransactionError("invalid_deployment_target", "deployment target is malformed")
    if set(context.toolchain_metadata) != TOOLCHAIN_METADATA_KEYS or any(
        not SHA256_RE.fullmatch(value) for value in context.toolchain_metadata.values()
    ):
        raise TransactionError("invalid_toolchain_identity", "toolchain identity is incomplete")
    if (
        not context.notary_profile
        or len(context.notary_profile) > 256
        or "\0" in context.notary_profile
    ):
        raise TransactionError("invalid_notary_profile", "notary profile name is malformed")
    _require_real_directory(context.repository / "target", trusted=True)
    _require_real_directory(context.repository / "target/candidates", trusted=True)
    _require_real_directory(context.candidate_base, trusted=True)
    _require_real_directory(context.build_root.parent, trusted=True)
    _require_real_directory(context.build_root, trusted=True)
    _require_real_directory(context.native_products, trusted=True)
    if os.path.lexists(context.attempt_root):
        raise TransactionError(
            "attempt_exists",
            "this lane/build already has a notarization attempt and must not be resubmitted",
        )
    expected_native = context.build_root / "native-products"
    if context.native_products != expected_native:
        raise TransactionError("unsafe_native_products", "native products path is not canonical")
    if context.staged_app.name != "Clash for Mac.app":
        raise TransactionError("unsafe_staged_app", "staged app name is not canonical")
    staging = context.staged_app.parent
    if staging.parent != context.candidate_base or not staging.name.startswith(
        ".signed-stage."
    ):
        raise TransactionError("unsafe_staged_app", "staged app parent is not canonical")
    _require_real_directory(staging, trusted=True)
    _require_real_directory(context.staged_app)
    if os.path.lexists(context.final_root):
        raise TransactionError("publish_destination_exists", "signed output already exists")


def _claim_attempt(context: TransactionContext) -> tuple[Path, Path]:
    attempts = context.candidate_base / "notary-attempts"
    lane = attempts / context.build_kind
    _mkdir_private(attempts, exclusive=False)
    _mkdir_private(lane, exclusive=False)
    _mkdir_private(context.attempt_root, exclusive=True)
    events = context.attempt_root / "events"
    work = context.attempt_root / "work"
    _mkdir_private(events, exclusive=True)
    _mkdir_private(work, exclusive=True)
    return events, work


def _require_source_identity(
    context: TransactionContext,
    reader: SourceIdentityReader,
) -> None:
    try:
        observed = reader(context.repository)
    except Exception as error:
        raise TransactionError(
            "source_identity_unavailable", "cannot derive the clean repository identity"
        ) from error
    if observed != context.source_identity:
        raise TransactionError(
            "source_identity_drift", "release source identity changed during notarization"
        )


def _require_toolchain_identity(
    context: TransactionContext,
    reader: ToolchainMetadataReader,
) -> None:
    try:
        observed = reader(context.repository)
    except Exception as error:
        raise TransactionError(
            "toolchain_identity_unavailable",
            "cannot derive the canonical release toolchain identity",
        ) from error
    if observed != context.toolchain_metadata:
        raise TransactionError(
            "toolchain_identity_drift",
            "release toolchain identity changed during notarization",
        )


def _archive_identity(path: Path) -> tuple[str, int]:
    digest, size = _hash_regular_file(path)
    if size <= 0:
        raise TransactionError("empty_archive", "notarization archive is empty")
    return digest, size


def _require_archive_identity(path: Path, digest: str, size: int) -> None:
    observed_digest, observed_size = _archive_identity(path)
    if (observed_digest, observed_size) != (digest, size):
        raise TransactionError(
            "archive_identity_drift", "notarization archive changed during the transaction"
        )


def _app_metadata(context: TransactionContext) -> dict[str, str]:
    return {
        "artifactKind": context.artifact_kind,
        "architecture": "arm64",
        "buildNumber": context.build_number,
        "deploymentTarget": context.deployment_target,
        "releaseSourceSha256": context.release_source_sha256,
        "repositoryCommit": context.repository_commit,
        "teamID": EXPECTED_TEAM_ID,
        "version": VERSION,
        **context.toolchain_metadata,
    }


def _archive_metadata(context: TransactionContext) -> dict[str, str]:
    return {
        "artifactKind": "notarization-submission-v1",
        "architecture": "arm64",
        "buildNumber": context.build_number,
        "releaseSourceSha256": context.release_source_sha256,
        "repositoryCommit": context.repository_commit,
        "teamID": EXPECTED_TEAM_ID,
        "version": VERSION,
        **context.toolchain_metadata,
    }


def _capture_command_result(
    runner: CommandRunner,
    role: CommandRole,
    command: list[str],
    timeout: float,
) -> CommandResult:
    try:
        return runner(role, command, timeout)
    except Exception as error:
        raise TransactionError(
            f"{role.value}_execution_failed",
            f"{role.value} command did not complete",
        ) from error


def _result_or_error(
    runner: CommandRunner,
    role: CommandRole,
    command: list[str],
    timeout: float,
    *,
    uncertain: bool = False,
) -> CommandResult:
    try:
        result = _capture_command_result(runner, role, command, timeout)
    except TransactionError as error:
        if uncertain:
            raise TransactionError(
                error.code,
                str(error),
                terminal_state="outcome_unknown",
            ) from error
        raise
    if result.returncode != 0:
        raise TransactionError(
            f"{role.value}_failed",
            f"{role.value} command failed",
            terminal_state="outcome_unknown" if uncertain else "failed",
            exit_code=result.returncode,
        )
    return result


def _require_syspolicy_success(
    result: CommandResult,
    role: CommandRole,
    app: Path,
) -> None:
    value = _parse_command_json(result.stdout)
    if not isinstance(value, dict) or set(value) != {"output"}:
        raise TransactionError(
            f"{role.value}_invalid_output",
            f"{role.value} returned an unexpected JSON document",
        )
    if value["output"] != []:
        raise TransactionError(
            f"{role.value}_finding",
            f"{role.value} reported a release-blocking finding",
        )
    _require_syspolicy_diagnostic(result, role, app)


def _require_syspolicy_diagnostic(
    result: CommandResult,
    role: CommandRole,
    app: Path,
) -> None:
    expected = (
        f"{_SINGLE_SIGNATURE_DIAGNOSTIC_PREFIX}{app.resolve().as_uri()}"
        f"{_SINGLE_SIGNATURE_DIAGNOSTIC_SUFFIX}"
    )
    if result.stderr not in {"", expected}:
        raise TransactionError(
            f"{role.value}_stderr",
            f"{role.value} emitted unexpected diagnostic output",
        )


def _require_exact_syspolicy_finding(
    result: CommandResult,
    role: CommandRole,
    app: Path,
    expected_finding: dict[str, str],
    *,
    expected_returncode: int,
) -> None:
    if result.returncode != expected_returncode:
        raise TransactionError(
            f"{role.value}_unexpected_status",
            f"{role.value} returned an unsupported status",
            exit_code=result.returncode,
        )
    value = _parse_command_json(result.stdout)
    if (
        not isinstance(value, dict)
        or set(value) != {"output"}
        or not isinstance(value["output"], list)
        or value["output"] != [expected_finding]
    ):
        raise TransactionError(
            f"{role.value}_finding_mismatch",
            f"{role.value} did not return the exact expected finding",
            exit_code=result.returncode,
        )
    _require_syspolicy_diagnostic(result, role, app)


def _require_exact_macos_27_notary_false_positive(
    result: CommandResult,
    app: Path,
    identity: HostSystemIdentity,
) -> None:
    role = CommandRole.NOTARY_READINESS
    if identity != KNOWN_MACOS_27_COMPATIBILITY_IDENTITY:
        raise TransactionError(
            "notary-readiness_compatibility_unsupported_host",
            "notary readiness failed outside the single known host compatibility build",
            exit_code=result.returncode,
        )
    executable = app.resolve() / "Contents/MacOS/clash-for-mac"
    _require_exact_syspolicy_finding(
        result,
        role,
        app,
        {
            "SyspolicyCheckAdditionalInformation": "",
            "SyspolicyCheckAdvice": "",
            "SyspolicyCheckDocumentationLink": (
                "https://developer.apple.com/forums/thread/706442"
            ),
            "SyspolicyCheckErrorFile": str(executable),
            "SyspolicyCheckErrorLevel": "Fatal",
            "SyspolicyCheckLongError": _KNOWN_NOTARY_FALSE_POSITIVE_LONG_ERROR,
            "SyspolicyCheckShortError": "Codesign Error",
        },
        expected_returncode=70,
    )


def _require_exact_pre_notary_missing_ticket(
    result: CommandResult,
    app: Path,
) -> None:
    role = CommandRole.NOTARY_READINESS_CORROBORATION
    _require_exact_syspolicy_finding(
        result,
        role,
        app,
        {
            "SyspolicyCheckAdditionalInformation": "",
            "SyspolicyCheckAdvice": _MISSING_TICKET_ADVICE,
            "SyspolicyCheckDocumentationLink": (
                "https://developer.apple.com/documentation/security/"
                "notarizing_macos_software_before_distribution."
            ),
            "SyspolicyCheckErrorFile": str(app.resolve()),
            "SyspolicyCheckErrorLevel": "Fatal",
            "SyspolicyCheckLongError": _MISSING_TICKET_LONG_ERROR,
            "SyspolicyCheckShortError": "Notary Ticket Missing",
        },
        expected_returncode=70,
    )


def _establish_pre_submission_policy(
    runner: CommandRunner,
    app: Path,
    identity_reader: HostSystemIdentityReader,
) -> PreSubmissionPolicyMode:
    readiness = _capture_command_result(
        runner,
        CommandRole.NOTARY_READINESS,
        [
            "/usr/bin/syspolicy_check",
            "notary-submission",
            str(app),
            "--json",
        ],
        600,
    )
    if readiness.returncode == 0:
        _require_syspolicy_success(
            readiness,
            CommandRole.NOTARY_READINESS,
            app,
        )
        return PreSubmissionPolicyMode.NATIVE
    if readiness.returncode != 70:
        raise TransactionError(
            "notary-readiness_failed",
            "notary-readiness command failed",
            exit_code=readiness.returncode,
        )
    try:
        identity = identity_reader()
    except TransactionError:
        raise
    except Exception as error:
        raise TransactionError(
            "host_system_identity_unavailable",
            "cannot derive the release host identity",
        ) from error
    _require_exact_macos_27_notary_false_positive(readiness, app, identity)
    corroboration = _capture_command_result(
        runner,
        CommandRole.NOTARY_READINESS_CORROBORATION,
        [
            "/usr/bin/syspolicy_check",
            "distribution",
            str(app),
            "--json",
        ],
        600,
    )
    _require_exact_pre_notary_missing_ticket(corroboration, app)
    return PreSubmissionPolicyMode.MACOS_27_26A5388G_COMPATIBILITY


def _require_empty_notary_stderr(
    result: CommandResult,
    role: CommandRole,
) -> None:
    if result.stderr:
        raise TransactionError(
            f"{role.value}_stderr",
            f"{role.value} emitted unexpected diagnostic output",
            terminal_state=(
                "outcome_unknown"
                if role in (CommandRole.SUBMIT, CommandRole.WAIT)
                else "failed"
            ),
        )


def _require_exact_persisted_evidence(
    directory: Path,
    *,
    expected_notarization: dict[str, str],
    expected_log: dict[str, Any],
    expected_gatekeeper: dict[str, Any],
    archive_filename: str,
    archive_sha256: str,
    failure_code: str,
    failure_message: str,
) -> PersistedEvidenceSnapshot:
    persisted_notarization, notarization_sha256 = _read_exact_json_document(
        directory / "notarization.json",
        expected_notarization,
        drift_code="notarization_result_identity_drift",
        drift_message=(
            "persisted notarization result differs from this transaction"
        ),
    )
    persisted_log, notary_log_sha256 = _read_exact_json_document(
        directory / "notarization-log.json",
        expected_log,
        drift_code="accepted_notary_log_identity_drift",
        drift_message=(
            "persisted Accepted notarization log differs from this transaction"
        ),
    )
    persisted_gatekeeper, gatekeeper_sha256 = _read_exact_json_document(
        directory / "gatekeeper.json",
        expected_gatekeeper,
        drift_code="gatekeeper_evidence_identity_drift",
        drift_message=(
            "persisted Gatekeeper evidence differs from this transaction"
        ),
    )
    try:
        validated_log = validate_normalized_documents(
            persisted_notarization,
            persisted_log,
            archive_filename=archive_filename,
            archive_sha256=archive_sha256,
        )
        validated_gatekeeper = validate_gatekeeper_evidence(persisted_gatekeeper)
    except (NotaryLogError, ValueError) as error:
        raise TransactionError(failure_code, failure_message) from error
    if validated_log != expected_log or validated_gatekeeper != expected_gatekeeper:
        raise TransactionError(failure_code, failure_message)
    return PersistedEvidenceSnapshot(
        gatekeeper=validated_gatekeeper,
        notarization_sha256=notarization_sha256,
        notary_log_sha256=notary_log_sha256,
        gatekeeper_sha256=gatekeeper_sha256,
    )


def execute_transaction(
    context: TransactionContext,
    *,
    command_runner: CommandRunner = production_command_runner,
    archive_builder: ArchiveBuilder = production_archive_builder,
    archive_validator: ArchiveValidator = production_archive_validator,
    gatekeeper_capture: GatekeeperCapture = production_gatekeeper_capture,
    manifest_writer: ManifestWriter = production_manifest_writer,
    manifest_verifier: ManifestVerifier = production_manifest_verifier,
    source_identity_reader: SourceIdentityReader = production_source_identity_reader,
    toolchain_metadata_reader: ToolchainMetadataReader = (
        production_toolchain_metadata_reader
    ),
    publisher: Publisher = publish_exclusive,
    clock: Clock = _utc_now,
    attempt_id_factory: AttemptIdFactory = lambda: str(uuid.uuid4()),
    host_system_identity_reader: HostSystemIdentityReader = (
        production_host_system_identity_reader
    ),
) -> Path:
    _validate_context(context)
    _require_source_identity(context, source_identity_reader)
    _require_toolchain_identity(context, toolchain_metadata_reader)
    events, work = _claim_attempt(context)
    journal: EventJournal | None = None
    submission_id: str | None = None
    try:
        work_app = work / "Clash for Mac.app"
        try:
            os.rename(context.staged_app, work_app)
            os.rmdir(context.staged_app.parent)
        except OSError as error:
            raise TransactionError(
                "staged_app_transfer_failed", "cannot transfer the signed app into the attempt"
            ) from error
        _fsync_directory(work)
        pre_staple_app_sha256 = _app_tree_sha256(
            work_app,
            failure_code="app_identity_failed",
            failure_message="pre-staple app digest cannot be derived",
        )

        archive = work / context.archive_name
        archive_builder(work_app, archive)
        _fsync_regular_file(archive)
        archive_sha256, archive_size = _archive_identity(archive)
        try:
            archive_validator(archive, work_app)
        except TransactionError:
            raise
        except Exception as error:
            raise TransactionError(
                "archive_validation_failed",
                "notarization archive validation did not complete",
            ) from error
        _require_archive_identity(archive, archive_sha256, archive_size)
        validated_app_sha256 = _app_tree_sha256(
            work_app,
            failure_code="archive_source_identity_drift",
            failure_message="signed app changed while validating its archive",
        )
        if validated_app_sha256 != pre_staple_app_sha256:
            raise TransactionError(
                "archive_source_identity_drift",
                "signed app changed while validating its archive",
            )
        archive_manifest = work / f"{context.archive_name}.manifest.json"
        archive_metadata = _archive_metadata(context)
        manifest_writer(archive, archive_manifest, archive_metadata)
        _run_manifest_verification_barrier(
            manifest_verifier,
            ((archive, archive_manifest, archive_metadata),),
        )

        attempt_id = _canonical_uuid(attempt_id_factory(), "local attempt id")
        intent = {
            "schema_version": 1,
            "document": ATTEMPT_DOCUMENT,
            "attempt_id": attempt_id,
            "lane": context.build_kind,
            "build_number": context.build_number,
            "version": VERSION,
            "repository_commit": context.repository_commit,
            "release_source_sha256": context.release_source_sha256,
            "team_id": EXPECTED_TEAM_ID,
            "archive_name": context.archive_name,
            "archive_sha256": archive_sha256,
            "archive_size": archive_size,
            "pre_staple_app_tree_sha256": pre_staple_app_sha256,
            "prepared_at": clock(),
        }
        intent_path = context.attempt_root / "intent.json"
        _write_json_exclusive(intent_path, intent)
        intent_sha256 = _sha256_file(intent_path)
        journal = EventJournal(events, intent_sha256, clock)
        journal.append("prepared")
        readiness_mode = _establish_pre_submission_policy(
            command_runner,
            work_app,
            host_system_identity_reader,
        )
        if readiness_mode is PreSubmissionPolicyMode.NATIVE:
            journal.append("notary_ready")
        else:
            journal.append("pre_submission_policy_compatibility_applied")
        _require_source_identity(context, source_identity_reader)
        _require_toolchain_identity(context, toolchain_metadata_reader)
        _require_archive_identity(archive, archive_sha256, archive_size)
        journal.append("submitting")

        submit_command = [
            "/usr/bin/xcrun",
            "notarytool",
            "submit",
            str(archive),
            "--no-wait",
            "--keychain-profile",
            context.notary_profile,
            "--output-format",
            "json",
        ]
        submit = _result_or_error(
            command_runner,
            CommandRole.SUBMIT,
            submit_command,
            1800,
            uncertain=True,
        )
        _require_empty_notary_stderr(submit, CommandRole.SUBMIT)
        try:
            submission_id, submit_status = _parse_notary_response(
                submit.stdout,
                allowed_statuses={"In Progress", "Accepted", "Invalid", "Rejected"},
            )
        except TransactionError as error:
            raise TransactionError(
                error.code,
                str(error),
                terminal_state="outcome_unknown",
            ) from error
        submission_receipt = {
            "schema_version": 1,
            "document": SUBMISSION_DOCUMENT,
            "attempt_id": attempt_id,
            "submission_id": submission_id,
            "status": submit_status,
            "archive_sha256": archive_sha256,
            "observed_at": clock(),
        }
        submission_receipt_path = context.attempt_root / "submission-receipt.json"
        try:
            _write_json_exclusive(submission_receipt_path, submission_receipt)
        except TransactionError as error:
            raise TransactionError(
                "submission_receipt_failed",
                "Apple returned a submission id but its receipt was not persisted",
                terminal_state="outcome_unknown",
            ) from error
        journal.append("submitted", submission_id=submission_id)
        if submit_status in ("Invalid", "Rejected"):
            raise TransactionError(
                "notary_submission_rejected",
                "Apple rejected the notarization submission",
                terminal_state="rejected",
            )

        wait_command = [
            "/usr/bin/xcrun",
            "notarytool",
            "wait",
            submission_id,
            "--keychain-profile",
            context.notary_profile,
            "--output-format",
            "json",
            "--timeout",
            "2h",
        ]
        waited = _result_or_error(
            command_runner,
            CommandRole.WAIT,
            wait_command,
            7500,
            uncertain=True,
        )
        _require_empty_notary_stderr(waited, CommandRole.WAIT)
        try:
            wait_id, wait_status = _parse_notary_response(
                waited.stdout,
                allowed_statuses={"In Progress", "Accepted", "Invalid", "Rejected"},
            )
        except TransactionError as error:
            raise TransactionError(
                error.code,
                str(error),
                terminal_state="outcome_unknown",
            ) from error
        if wait_id != submission_id:
            raise TransactionError(
                "submission_id_mismatch",
                "notarytool wait returned a different submission id",
                terminal_state="outcome_unknown",
            )
        if wait_status in ("Invalid", "Rejected"):
            raise TransactionError(
                "notary_submission_rejected",
                "Apple rejected the notarization submission",
                terminal_state="rejected",
            )
        if wait_status != "Accepted":
            raise TransactionError(
                "notary_wait_incomplete",
                "Apple notarization did not reach a terminal result",
                terminal_state="outcome_unknown",
            )
        notarization = {"id": submission_id, "status": "Accepted"}
        notarization_path = work / "notarization.json"
        _write_json_exclusive(notarization_path, notarization)
        journal.append("accepted", submission_id=submission_id)

        log_command = [
            "/usr/bin/xcrun",
            "notarytool",
            "log",
            submission_id,
            "--keychain-profile",
            context.notary_profile,
        ]
        fetched_log = _result_or_error(
            command_runner,
            CommandRole.FETCH_LOG,
            log_command,
            300,
        )
        _require_empty_notary_stderr(fetched_log, CommandRole.FETCH_LOG)
        raw_log = _parse_command_json(fetched_log.stdout)
        _require_archive_identity(archive, archive_sha256, archive_size)
        try:
            normalized_log = validate_documents(
                notarization,
                raw_log,
                archive_filename=context.archive_name,
                archive_sha256=archive_sha256,
            )
        except NotaryLogError as error:
            raise TransactionError(
                "notary_log_verification_failed",
                "Apple notarization log failed strict binding validation",
            ) from error
        notarization_log_path = work / "notarization-log.json"
        _write_json_exclusive(notarization_log_path, normalized_log)
        journal.append("log_verified", submission_id=submission_id)

        journal.append("stapling", submission_id=submission_id)
        _result_or_error(
            command_runner,
            CommandRole.STAPLE,
            ["/usr/bin/xcrun", "stapler", "staple", str(work_app)],
            600,
        )
        _result_or_error(
            command_runner,
            CommandRole.STAPLE_VALIDATE,
            ["/usr/bin/xcrun", "stapler", "validate", str(work_app)],
            300,
        )
        post_staple_app_sha256 = _app_tree_sha256(
            work_app,
            failure_code="app_identity_failed",
            failure_message="post-staple app digest cannot be derived",
        )
        journal.append("stapled", submission_id=submission_id)

        try:
            gatekeeper = validate_gatekeeper_evidence(
                gatekeeper_capture(work_app, post_staple_app_sha256)
            )
        except Exception as error:
            raise TransactionError(
                "gatekeeper_verification_failed", "Gatekeeper did not accept the stapled app"
            ) from error
        if gatekeeper["target_signed_app_tree_sha256"] != post_staple_app_sha256:
            raise TransactionError(
                "gatekeeper_target_mismatch",
                "Gatekeeper evidence is not bound to the exact stapled app tree",
            )
        gatekeeper_path = work / "gatekeeper.json"
        _write_json_exclusive(gatekeeper_path, gatekeeper)
        journal.append("gatekeeper_verified", submission_id=submission_id)
        _result_or_error(
            command_runner,
            CommandRole.FINAL_VERIFY,
            [
                str(context.repository / "scripts/verify_release_app.sh"),
                str(work_app),
                str(context.native_products),
            ],
            600,
        )
        journal.append("app_verified", submission_id=submission_id)
        _require_source_identity(context, source_identity_reader)

        publish_ready = context.attempt_root / "publish-ready"
        _mkdir_private(publish_ready, exclusive=True)
        for item in (
            work_app,
            archive,
            archive_manifest,
            notarization_path,
            notarization_log_path,
            gatekeeper_path,
        ):
            os.rename(item, publish_ready / item.name)
        os.rmdir(work)
        _fsync_directory(publish_ready)

        final_app = publish_ready / "Clash for Mac.app"
        app_manifest = publish_ready / "Clash for Mac.app.manifest.json"
        app_metadata = _app_metadata(context)
        manifest_writer(final_app, app_manifest, app_metadata)
        _run_manifest_verification_barrier(
            manifest_verifier,
            ((final_app, app_manifest, app_metadata),),
        )
        final_archive = publish_ready / context.archive_name
        final_archive_manifest = publish_ready / f"{context.archive_name}.manifest.json"
        _run_manifest_verification_barrier(
            manifest_verifier,
            ((final_archive, final_archive_manifest, archive_metadata),),
        )
        persisted_evidence = _require_exact_persisted_evidence(
            publish_ready,
            expected_notarization=notarization,
            expected_log=normalized_log,
            expected_gatekeeper=gatekeeper,
            archive_filename=context.archive_name,
            archive_sha256=archive_sha256,
            failure_code="sealed_evidence_verification_failed",
            failure_message=(
                "sealed notarization or Gatekeeper evidence differs from the "
                "validated transaction result"
            ),
        )
        persisted_app_tree_sha256 = _app_tree_sha256(
            final_app,
            failure_code="gatekeeper_target_mismatch",
            failure_message="sealed app identity cannot be derived",
        )
        if (
            persisted_evidence.gatekeeper["target_signed_app_tree_sha256"]
            != persisted_app_tree_sha256
        ):
            raise TransactionError(
                "gatekeeper_target_mismatch",
                "sealed Gatekeeper evidence differs from the final app tree",
            )
        _result_or_error(
            command_runner,
            CommandRole.FINAL_VERIFY,
            [
                str(context.repository / "scripts/verify_release_app.sh"),
                str(final_app),
                str(context.native_products),
            ],
            600,
        )
        distribution = _result_or_error(
            command_runner,
            CommandRole.DISTRIBUTION_CHECK,
            [
                "/usr/bin/syspolicy_check",
                "distribution",
                str(final_app),
                "--json",
            ],
            600,
        )
        _require_syspolicy_success(
            distribution,
            CommandRole.DISTRIBUTION_CHECK,
            final_app,
        )
        journal.append("distribution_verified", submission_id=submission_id)
        expected_inventory = set(FINAL_INVENTORY_TEMPLATE)
        expected_inventory.update({context.archive_name, final_archive_manifest.name})
        if {path.name for path in publish_ready.iterdir()} != expected_inventory:
            raise TransactionError(
                "publish_inventory_mismatch", "publish-ready directory has unexpected entries"
            )
        sealed_at = clock()
        _require_source_identity(context, source_identity_reader)
        _result_or_error(
            command_runner,
            CommandRole.FINAL_VERIFY,
            [
                str(context.repository / "scripts/verify_release_app.sh"),
                str(final_app),
                str(context.native_products),
            ],
            600,
        )
        final_verifications = (
            (final_app, app_manifest, app_metadata),
            (final_archive, final_archive_manifest, archive_metadata),
        )
        _run_configured_manifest_verification_hooks(
            manifest_verifier,
            final_verifications,
        )
        _require_source_identity(context, source_identity_reader)
        _require_toolchain_identity(context, toolchain_metadata_reader)
        _run_production_manifest_verifications(final_verifications)
        _require_archive_identity(final_archive, archive_sha256, archive_size)
        preseal_app_tree_sha256 = _app_tree_sha256(
            final_app,
            failure_code="preseal_app_identity_drift",
            failure_message="publish-ready app identity changed before sealing",
        )
        if (
            preseal_app_tree_sha256 != post_staple_app_sha256
            or gatekeeper["target_signed_app_tree_sha256"]
            != preseal_app_tree_sha256
        ):
            raise TransactionError(
                "preseal_app_identity_drift",
                "publish-ready app differs from the stapled Gatekeeper-assessed app",
            )
        if {path.name for path in publish_ready.iterdir()} != expected_inventory:
            raise TransactionError(
                "preseal_publish_inventory_mismatch",
                "publish-ready inventory changed before sealing",
            )
        sealed_intent, sealed_intent_sha256 = _read_exact_json_document(
            intent_path,
            intent,
            drift_code="notarization_intent_identity_drift",
            drift_message="notarization intent differs from this transaction",
        )
        if sealed_intent != intent or sealed_intent_sha256 != intent_sha256:
            raise TransactionError(
                "notarization_intent_identity_drift",
                "notarization intent differs from this transaction",
            )
        _, sealed_submission_receipt_sha256 = _read_exact_json_document(
            submission_receipt_path,
            submission_receipt,
            drift_code="submission_receipt_identity_drift",
            drift_message="Apple submission receipt differs from this transaction",
        )
        sealed_evidence = _require_exact_persisted_evidence(
            publish_ready,
            expected_notarization=notarization,
            expected_log=normalized_log,
            expected_gatekeeper=gatekeeper,
            archive_filename=context.archive_name,
            archive_sha256=archive_sha256,
            failure_code="sealed_evidence_verification_failed",
            failure_message=(
                "sealed notarization or Gatekeeper evidence differs from the "
                "validated transaction result"
            ),
        )
        preseal_event_sha256 = journal.verify()
        receipt = {
            "schema_version": 1,
            "document": RECEIPT_DOCUMENT,
            "attempt_id": attempt_id,
            "submission_id": submission_id,
            "intent_sha256": intent_sha256,
            "preseal_event_sha256": preseal_event_sha256,
            "submission_receipt_sha256": sealed_submission_receipt_sha256,
            "accepted_notary_log_sha256": sealed_evidence.notary_log_sha256,
            "notarization_result_sha256": sealed_evidence.notarization_sha256,
            "archive_sha256": archive_sha256,
            "pre_staple_app_tree_sha256": pre_staple_app_sha256,
            "post_staple_app_tree_sha256": post_staple_app_sha256,
            "gatekeeper_evidence_sha256": sealed_evidence.gatekeeper_sha256,
            "app_manifest_sha256": _sha256_file(app_manifest),
            "archive_manifest_sha256": _sha256_file(final_archive_manifest),
            "state": "publish-ready",
            "sealed_at": sealed_at,
        }
        receipt_path = context.attempt_root / "receipt.json"
        _write_json_exclusive(receipt_path, receipt)
        journal.append(
            "sealed",
            submission_id=submission_id,
            recorded_at=sealed_at,
        )
        _fsync_tree(publish_ready)
        _run_configured_manifest_verification_hooks(
            manifest_verifier,
            final_verifications,
        )
        _require_source_identity(context, source_identity_reader)
        _require_toolchain_identity(context, toolchain_metadata_reader)
        _run_production_manifest_verifications(final_verifications)
        final_app_tree_sha256 = _app_tree_sha256(
            final_app,
            failure_code="final_app_identity_drift",
            failure_message="publish-ready app identity changed before publication",
        )
        _, final_intent_sha256 = _read_exact_json_document(
            intent_path,
            intent,
            drift_code="notarization_intent_identity_drift",
            drift_message="notarization intent differs from this transaction",
        )
        _, final_submission_receipt_sha256 = _read_exact_json_document(
            submission_receipt_path,
            submission_receipt,
            drift_code="submission_receipt_identity_drift",
            drift_message="Apple submission receipt differs from this transaction",
        )
        final_static_bindings = {
            "submission_receipt_sha256": final_submission_receipt_sha256,
            "app_manifest_sha256": _sha256_file(app_manifest),
            "archive_manifest_sha256": _sha256_file(final_archive_manifest),
        }
        final_receipt, _ = _read_exact_json_document(
            receipt_path,
            receipt,
            drift_code="final_receipt_changed",
            drift_message="notarization receipt changed before publication",
        )
        if final_receipt != receipt or final_intent_sha256 != receipt["intent_sha256"]:
            raise TransactionError(
                "final_receipt_changed", "notarization receipt changed before publication"
            )
        _require_archive_identity(final_archive, archive_sha256, archive_size)
        if {path.name for path in publish_ready.iterdir()} != expected_inventory:
            raise TransactionError(
                "final_publish_inventory_mismatch",
                "publish-ready inventory changed before publication",
            )
        final_evidence = _require_exact_persisted_evidence(
            publish_ready,
            expected_notarization=notarization,
            expected_log=normalized_log,
            expected_gatekeeper=gatekeeper,
            archive_filename=context.archive_name,
            archive_sha256=archive_sha256,
            failure_code="final_evidence_verification_failed",
            failure_message=(
                "final notarization or Gatekeeper evidence changed before publication"
            ),
        )
        if (
            final_evidence.gatekeeper["target_signed_app_tree_sha256"]
            != final_app_tree_sha256
            or final_app_tree_sha256 != post_staple_app_sha256
        ):
            raise TransactionError(
                "final_gatekeeper_target_mismatch",
                "final Gatekeeper evidence is not bound to the publish-ready app",
            )
        final_bindings = {
            **final_static_bindings,
            "accepted_notary_log_sha256": final_evidence.notary_log_sha256,
            "notarization_result_sha256": final_evidence.notarization_sha256,
            "gatekeeper_evidence_sha256": final_evidence.gatekeeper_sha256,
        }
        if any(receipt[key] != value for key, value in final_bindings.items()):
            raise TransactionError(
                "final_receipt_binding_mismatch",
                "publish-ready evidence differs from its sealed receipt",
            )
        journal.verify()
        try:
            publisher(publish_ready, context.final_root)
        except TransactionError:
            raise
        except Exception as error:
            raise TransactionError(
                "atomic_publish_failed", "exclusive atomic publication failed"
            ) from error
        return context.final_root / "Clash for Mac.app"
    except Exception as error:
        if journal is not None:
            if isinstance(error, TransactionError):
                terminal_state = error.terminal_state
                failure_code = error.code
                exit_code = error.exit_code
            else:
                terminal_state = "failed"
                failure_code = "internal_error"
                exit_code = None
            try:
                journal.append(
                    terminal_state,
                    submission_id=submission_id,
                    failure_code=failure_code,
                    exit_code=exit_code,
                )
            except Exception as receipt_error:
                raise TransactionError(
                    "failure_receipt_failed",
                    "transaction failed with "
                    f"{failure_code} and its terminal receipt could not be persisted",
                    terminal_state=terminal_state,
                    exit_code=exit_code,
                ) from receipt_error
        raise


def self_check() -> None:
    if TOOLCHAIN_METADATA_KEYS != set(TOOLCHAIN_METADATA_ORDER):
        raise TransactionError("self_check_failed", "toolchain metadata contract drifted")
    if RENAME_EXCL != 0x00000004:
        raise TransactionError("self_check_failed", "RENAME_EXCL constant drifted")
    if RENAME_NOFOLLOW_ANY != 0x00000010:
        raise TransactionError("self_check_failed", "RENAME_NOFOLLOW_ANY constant drifted")
    print("notarization transaction self-check ok")


def _metadata(arguments: argparse.Namespace) -> dict[str, str]:
    return {
        "goModuleCacheTreeSha256": arguments.go_module_cache_tree_sha256,
        "goToolchainTreeSha256": arguments.go_toolchain_tree_sha256,
        "goToolsTreeSha256": arguments.go_tools_tree_sha256,
        "nodeToolchainTreeSha256": arguments.node_toolchain_tree_sha256,
        "tauriToolchainTreeSha256": arguments.tauri_toolchain_tree_sha256,
        "toolchainSha256": arguments.toolchain_sha256,
        "uiDependenciesTreeSha256": arguments.ui_dependencies_tree_sha256,
        "xcodegenToolchainTreeSha256": arguments.xcodegen_toolchain_tree_sha256,
    }


def main() -> None:
    if sys.argv[1:] == ["--self-check"]:
        self_check()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-kind", choices=("validation", "release"), required=True)
    parser.add_argument("--build-number", required=True)
    parser.add_argument("--staged-app", type=Path, required=True)
    parser.add_argument("--native-products", type=Path, required=True)
    parser.add_argument("--notary-profile", required=True)
    parser.add_argument("--repository-commit", required=True)
    parser.add_argument("--release-source-sha256", required=True)
    parser.add_argument("--deployment-target", required=True)
    parser.add_argument("--go-module-cache-tree-sha256", required=True)
    parser.add_argument("--go-toolchain-tree-sha256", required=True)
    parser.add_argument("--go-tools-tree-sha256", required=True)
    parser.add_argument("--node-toolchain-tree-sha256", required=True)
    parser.add_argument("--tauri-toolchain-tree-sha256", required=True)
    parser.add_argument("--toolchain-sha256", required=True)
    parser.add_argument("--ui-dependencies-tree-sha256", required=True)
    parser.add_argument("--xcodegen-toolchain-tree-sha256", required=True)
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    context = TransactionContext(
        repository=repository,
        build_kind=arguments.build_kind,
        build_number=arguments.build_number,
        staged_app=arguments.staged_app,
        native_products=arguments.native_products,
        notary_profile=arguments.notary_profile,
        repository_commit=arguments.repository_commit,
        release_source_sha256=arguments.release_source_sha256,
        deployment_target=arguments.deployment_target,
        toolchain_metadata=_metadata(arguments),
    )
    try:
        app = execute_transaction(context)
    except (OSError, TransactionError, ValueError) as error:
        code = error.code if isinstance(error, TransactionError) else "unexpected_error"
        raise SystemExit(f"error: notarization transaction [{code}]: {error}") from error
    print(f"notarization transaction published: {app.relative_to(repository)}")


if __name__ == "__main__":
    main()
