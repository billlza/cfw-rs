#!/usr/bin/env python3
"""Atomically export the closed GA install and service journals for acceptance."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Final, Iterator
import uuid

if __package__:
    from . import current_service_transaction as service
    from . import dormant_app_install as install
    from . import ga_acceptance_environment as ga_environment
    from .publication.common import (
        PublicationError,
        canonical_json,
        require_exact_keys,
        require_sha256,
        safe_relative,
        sha256_bytes,
        tree_digest,
    )
    from .publication.durable_file import (
        DurabilityOutcomeUnknown,
        RootedDirectoryChanged,
        exclusive_rooted_directory_lock,
        fsync_directory,
        fsync_locked_directory,
        fsync_private_tree,
        promote_private_pending,
        publish_private_directory_exclusive,
        write_private_pending,
        write_private_pending_locked,
    )
    from .release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
    from .release_regular_file import (
        ReleaseRegularFileError,
        read_bounded_regular_file,
    )
else:
    import current_service_transaction as service
    import dormant_app_install as install
    import ga_acceptance_environment as ga_environment
    from publication.common import (
        PublicationError,
        canonical_json,
        require_exact_keys,
        require_sha256,
        safe_relative,
        sha256_bytes,
        tree_digest,
    )
    from publication.durable_file import (
        DurabilityOutcomeUnknown,
        RootedDirectoryChanged,
        exclusive_rooted_directory_lock,
        fsync_directory,
        fsync_locked_directory,
        fsync_private_tree,
        promote_private_pending,
        publish_private_directory_exclusive,
        write_private_pending,
        write_private_pending_locked,
    )
    from release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
    from release_regular_file import (
        ReleaseRegularFileError,
        read_bounded_regular_file,
    )


PRODUCT_VERSION: Final = ACTIVE_RELEASE_IDENTITY.product_version
GA_BUILD: Final = ACTIVE_RELEASE_IDENTITY.ga_build
PREVIOUS_BUILD: Final = "40019"
GA_ROOT_RELATIVE: Final = ga_root(Path("."))
STAGE_INPUT_ROOT_RELATIVE: Final = GA_ROOT_RELATIVE / "stage-inputs"
ACCEPTANCE_ROOT_RELATIVE: Final = STAGE_INPUT_ROOT_RELATIVE / "ga-acceptance"
MIGRATION_RELATIVE: Final = ACCEPTANCE_ROOT_RELATIVE / "migration-journals"
INSTALL_RELATIVE: Final = MIGRATION_RELATIVE / "dormant-install.json"
SERVICE_RELATIVE: Final = MIGRATION_RELATIVE / "service-transaction"
ENVIRONMENT_RELATIVE: Final = SERVICE_RELATIVE / service.ENVIRONMENT_NAME

EXTERNAL_INTENT_NAME: Final = "ga-acceptance-journal-export-intent.json"
EXTERNAL_PENDING_INTENT_NAME: Final = (
    ".ga-acceptance-journal-export-intent.json.pending"
)
INTERNAL_INTENT_NAME: Final = "export-intent.json"
RECEIPT_NAME: Final = "export-receipt.json"
INSTALL_NAME: Final = "dormant-install.json"
SERVICE_NAME: Final = "service-transaction"
MIGRATION_NAME: Final = "migration-journals"

INTENT_DOCUMENT: Final = "cfm-ga-journal-export-intent-v1"
RECEIPT_DOCUMENT: Final = "cfm-ga-journal-export-receipt-v1"
SCHEMA_VERSION: Final = 1
MAX_DOCUMENT_BYTES: Final = 1024 * 1024
MAX_SERVICE_FILES: Final = 16
PENDING_NAME_PATTERN: Final = re.compile(
    r"^[.]migration-journals-[0-9a-f]{32}[.]pending$"
)
SERVICE_FILE_NAME_PATTERN: Final = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$"
)


class GAAcceptanceJournalExportError(ValueError):
    """The fixed GA journal export is absent, unsafe, mixed, or incomplete."""


class GAAcceptanceJournalExportRecoveryRequired(
    GAAcceptanceJournalExportError
):
    """A durable export intent exists, so only the fixed recovery may continue."""


class GAAcceptanceJournalExportOutcomeUnknown(
    GAAcceptanceJournalExportRecoveryRequired
):
    """A durable namespace mutation may have completed and requires recovery."""


EnvironmentObserver = Callable[[], dict[str, Any]]


@dataclass(frozen=True)
class JournalExportPaths:
    repository: Path
    install_paths: install.InstallPaths
    service_paths: service.ServicePaths

    @classmethod
    def production(cls, repository: Path) -> "JournalExportPaths":
        selected = _canonical_repository(repository)
        install_paths = install.InstallPaths.production()
        if _canonical_repository(install_paths.repository) != selected:
            raise GAAcceptanceJournalExportError(
                "journal export repository differs from the production release tree"
            )
        return cls(
            repository=selected,
            install_paths=install_paths,
            service_paths=service.ServicePaths(
                install_paths=install_paths,
                transaction_parent=install_paths.target_parent,
            ),
        )

    @classmethod
    def verification(cls, repository: Path) -> "JournalExportPaths":
        """Build fixed target paths without consulting live producer evidence."""

        selected = _canonical_repository(repository)
        install_paths = install.InstallPaths.production()
        return cls(
            repository=selected,
            install_paths=install_paths,
            service_paths=service.ServicePaths(
                install_paths=install_paths,
                transaction_parent=install_paths.target_parent,
            ),
        )

    @property
    def stage_input_root(self) -> Path:
        return self.repository.joinpath(*STAGE_INPUT_ROOT_RELATIVE.parts)

    @property
    def acceptance_root(self) -> Path:
        return self.repository.joinpath(*ACCEPTANCE_ROOT_RELATIVE.parts)

    @property
    def migration_root(self) -> Path:
        return self.repository.joinpath(*MIGRATION_RELATIVE.parts)

    @property
    def external_intent(self) -> Path:
        return self.stage_input_root / EXTERNAL_INTENT_NAME

    @property
    def external_pending_intent(self) -> Path:
        return self.stage_input_root / EXTERNAL_PENDING_INTENT_NAME


@dataclass(frozen=True)
class SourceSnapshot:
    environment: dict[str, Any]
    install_document: dict[str, Any]
    service_intent: dict[str, Any]
    service_events: tuple[dict[str, Any], ...]
    payload_files: dict[str, bytes]
    service_tree_sha256: str

    @property
    def environment_sha256(self) -> str:
        return ga_environment.environment_sha256(self.environment)


def _canonical_repository(repository: Path) -> Path:
    path = Path(repository).absolute()
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise GAAcceptanceJournalExportError(
            "journal export repository is unavailable"
        ) from error
    if (
        resolved != path
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise GAAcceptanceJournalExportError(
            "journal export repository is not one canonical owned directory"
        )
    return resolved


def _validated_paths(paths: object) -> JournalExportPaths:
    if not isinstance(paths, JournalExportPaths):
        raise GAAcceptanceJournalExportError("journal export paths are invalid")
    repository = _canonical_repository(paths.repository)
    if (
        repository != paths.repository
        or paths.install_paths.repository != repository
        or paths.install_paths.profile != install.GA_INSTALL_PROFILE
        or paths.service_paths.install_paths != paths.install_paths
        or paths.service_paths.transaction_parent != paths.install_paths.target_parent
        or paths.install_paths.journal_name != install.JOURNAL_NAME
        or paths.service_paths.transaction_directory_name
        != install.GA_INSTALL_PROFILE.service_transaction_directory
    ):
        raise GAAcceptanceJournalExportError(
            "journal export paths differ from the fixed GA producer topology"
        )
    return paths


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


def _private_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GAAcceptanceJournalExportError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise GAAcceptanceJournalExportError(
            f"{label} is not one owned 0700 directory"
        )
    return metadata


def _read_private_file(path: Path, label: str) -> bytes:
    try:
        return read_bounded_regular_file(
            path,
            label=label,
            maximum_bytes=MAX_DOCUMENT_BYTES,
            allowed_owner_uids=frozenset({os.geteuid()}),
            exact_mode=0o600,
        )
    except ReleaseRegularFileError as error:
        raise GAAcceptanceJournalExportError(
            f"{label} is not one stable owned 0600 single-link file"
        ) from error


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_nonfinite_constant(token: str) -> object:
    raise ValueError(f"non-finite JSON constant: {token}")


def _strict_json(data: bytes, label: str) -> dict[str, Any]:
    if not data or len(data) > MAX_DOCUMENT_BYTES:
        raise GAAcceptanceJournalExportError(f"{label} size is invalid")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise GAAcceptanceJournalExportError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise GAAcceptanceJournalExportError(f"{label} is not canonical JSON")
    try:
        encoded = canonical_json(value)
    except (RecursionError, UnicodeError) as error:
        raise GAAcceptanceJournalExportError(
            f"{label} is not canonical JSON"
        ) from error
    if data != encoded:
        raise GAAcceptanceJournalExportError(f"{label} is not canonical JSON")
    return value


def _file_record(path: str, data: bytes) -> dict[str, Any]:
    safe_relative(path, "journal export payload path")
    return {"path": path, "sha256": sha256_bytes(data), "size": len(data)}


def _validated_file_records(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise GAAcceptanceJournalExportError(f"{label} is not a non-empty array")
    records: list[dict[str, Any]] = []
    paths: set[str] = set()
    for index, raw in enumerate(value):
        try:
            record = require_exact_keys(
                raw,
                {"path", "sha256", "size"},
                f"{label}[{index}]",
            )
            path = safe_relative(record["path"], f"{label}[{index}].path").as_posix()
            digest = require_sha256(record["sha256"], f"{label}[{index}].sha256")
        except PublicationError as error:
            raise GAAcceptanceJournalExportError(str(error)) from error
        if type(record["size"]) is not int or not 0 < record["size"] <= MAX_DOCUMENT_BYTES:
            raise GAAcceptanceJournalExportError(f"{label}[{index}].size is invalid")
        if path in paths:
            raise GAAcceptanceJournalExportError(f"{label} repeats a payload path")
        paths.add(path)
        records.append({"path": path, "sha256": digest, "size": record["size"]})
    if records != sorted(records, key=lambda record: record["path"]):
        raise GAAcceptanceJournalExportError(f"{label} is not path-sorted")
    return records


def _tree_entries(files: dict[str, bytes]) -> list[dict[str, object]]:
    directories: set[str] = set()
    for relative in files:
        parsed = safe_relative(relative, "journal export tree path")
        for index in range(1, len(parsed.parts)):
            directories.add(Path(*parsed.parts[:index]).as_posix())
    entries: list[dict[str, object]] = [
        {"path": path, "type": "directory"} for path in directories
    ]
    entries.extend(
        {
            "path": relative,
            "sha256": sha256_bytes(data),
            "size": len(data),
            "type": "file",
        }
        for relative, data in files.items()
    )
    return sorted(entries, key=lambda entry: str(entry["path"]))


def _service_tree_sha256(service_files: dict[str, bytes]) -> str:
    return tree_digest(_tree_entries(service_files))


def _source_snapshot(
    service_snapshot: service.TerminalServiceJournalSnapshot,
    install_snapshot: install.TerminalInstallJournalSnapshot,
    observed_environment: object,
) -> SourceSnapshot:
    service_files = {snapshot.name: snapshot.data for snapshot in service_snapshot.files}
    if len(service_files) > MAX_SERVICE_FILES:
        raise GAAcceptanceJournalExportError("service journal file count is excessive")
    try:
        environment, service_intent, service_events = (
            service.validate_terminal_snapshot_files(service_files)
        )
        install_document = install.validate_journal(install_snapshot.document)
        current_environment = ga_environment.require_same_environment(
            environment,
            observed_environment,
            label="GA journal export environment",
        )
    except (install.InstallError, ga_environment.GAAcceptanceEnvironmentError) as error:
        raise GAAcceptanceJournalExportError(
            "closed producer journals or current GA environment are invalid"
        ) from error
    if (
        install_snapshot.data != canonical_json(install_document)
        or service_intent != service_snapshot.intent
        or service_events != service_snapshot.events
        or service_intent["candidate"] != install_document["candidate"]
        or service_intent["previous"] != install_document["previous"]
        or service_intent["ga_environment_sha256"]
        != install_document["ga_environment_sha256"]
        or ga_environment.environment_sha256(current_environment)
        != install_document["ga_environment_sha256"]
        or install_document["phase"] != "installed"
        or service_events[-1]["phase"] != "recommissioned"
        or install_document["candidate"]["build_number"] != GA_BUILD
        or install_document["previous"]["build_number"] != PREVIOUS_BUILD
    ):
        raise GAAcceptanceJournalExportError(
            "closed install and service journals bind different GA migrations"
        )
    payload_files = {INSTALL_NAME: install_snapshot.data}
    payload_files.update(
        {f"{SERVICE_NAME}/{name}": data for name, data in service_files.items()}
    )
    return SourceSnapshot(
        environment=environment,
        install_document=install_document,
        service_intent=service_intent,
        service_events=service_events,
        payload_files=payload_files,
        service_tree_sha256=_service_tree_sha256(service_files),
    )


@contextmanager
def _locked_source_snapshot(
    paths: JournalExportPaths,
    observer: EnvironmentObserver,
) -> Iterator[SourceSnapshot]:
    try:
        with service.ServiceEventStore(paths.service_paths) as service_store:
            with service_store.locked(require_existing=True):
                service_before = service_store.terminal_snapshot()
                with install.JournalStore(paths.install_paths) as install_store:
                    with install_store.locked(require_existing=True):
                        install_before = install_store.terminal_snapshot()
                        snapshot = _source_snapshot(
                            service_before,
                            install_before,
                            observer(),
                        )
                        yield snapshot
                        service_after = service_store.terminal_snapshot()
                        install_after = install_store.terminal_snapshot()
                        repeated = _source_snapshot(
                            service_after,
                            install_after,
                            observer(),
                        )
                        if repeated != snapshot:
                            raise GAAcceptanceJournalExportOutcomeUnknown(
                                "producer journals changed while the export was published"
                            )
    except GAAcceptanceJournalExportError:
        raise
    except (OSError, install.InstallError, ga_environment.GAAcceptanceEnvironmentError) as error:
        raise GAAcceptanceJournalExportError(
            "producer journal export admission failed closed"
        ) from error


def _intent(snapshot: SourceSnapshot, transaction_id: str) -> dict[str, Any]:
    try:
        canonical_id = str(uuid.UUID(transaction_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise GAAcceptanceJournalExportError(
            "journal export transaction id is invalid"
        ) from error
    if canonical_id != transaction_id:
        raise GAAcceptanceJournalExportError(
            "journal export transaction id is not canonical"
        )
    pending_name = f".migration-journals-{uuid.UUID(transaction_id).hex}.pending"
    payload_records = [
        _file_record(path, data) for path, data in sorted(snapshot.payload_files.items())
    ]
    payload_entries = _tree_entries(snapshot.payload_files)
    return {
        "candidate": snapshot.service_intent["candidate"],
        "document": INTENT_DOCUMENT,
        "ga_environment_sha256": snapshot.environment_sha256,
        "payload": {
            "files": payload_records,
            "tree_sha256": tree_digest(payload_entries),
        },
        "pending_name": pending_name,
        "previous": snapshot.service_intent["previous"],
        "schema_version": SCHEMA_VERSION,
        "service_tree_sha256": snapshot.service_tree_sha256,
        "target": MIGRATION_RELATIVE.as_posix(),
        "transaction_id": transaction_id,
    }


def _validate_intent(value: object) -> dict[str, Any]:
    try:
        intent = require_exact_keys(
            value,
            {
                "candidate",
                "document",
                "ga_environment_sha256",
                "payload",
                "pending_name",
                "previous",
                "schema_version",
                "service_tree_sha256",
                "target",
                "transaction_id",
            },
            "GA journal export intent",
        )
        require_sha256(
            intent["ga_environment_sha256"],
            "GA journal export environment digest",
        )
        require_sha256(
            intent["service_tree_sha256"],
            "GA journal export service tree digest",
        )
        payload = require_exact_keys(
            intent["payload"],
            {"files", "tree_sha256"},
            "GA journal export payload",
        )
        require_sha256(payload["tree_sha256"], "GA journal export payload tree")
    except PublicationError as error:
        raise GAAcceptanceJournalExportError(str(error)) from error
    if (
        intent["document"] != INTENT_DOCUMENT
        or type(intent["schema_version"]) is not int
        or intent["schema_version"] != SCHEMA_VERSION
        or intent["target"] != MIGRATION_RELATIVE.as_posix()
        or not isinstance(intent["pending_name"], str)
        or PENDING_NAME_PATTERN.fullmatch(intent["pending_name"]) is None
    ):
        raise GAAcceptanceJournalExportError("GA journal export intent identity is invalid")
    try:
        transaction_id = str(uuid.UUID(intent["transaction_id"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise GAAcceptanceJournalExportError(
            "GA journal export transaction id is invalid"
        ) from error
    if (
        transaction_id != intent["transaction_id"]
        or f".migration-journals-{uuid.UUID(transaction_id).hex}.pending"
        != intent["pending_name"]
    ):
        raise GAAcceptanceJournalExportError(
            "GA journal export pending path is not transaction-bound"
        )
    payload["files"] = _validated_file_records(
        payload["files"], "GA journal export payload files"
    )
    return intent


def _receipt(intent: dict[str, Any]) -> dict[str, Any]:
    return {
        "document": RECEIPT_DOCUMENT,
        "ga_environment_sha256": intent["ga_environment_sha256"],
        "intent_sha256": sha256_bytes(canonical_json(intent)),
        "payload_tree_sha256": intent["payload"]["tree_sha256"],
        "schema_version": SCHEMA_VERSION,
        "service_tree_sha256": intent["service_tree_sha256"],
    }


def _validate_receipt(
    value: object,
    intent: dict[str, Any],
) -> dict[str, Any]:
    try:
        receipt = require_exact_keys(
            value,
            {
                "document",
                "ga_environment_sha256",
                "intent_sha256",
                "payload_tree_sha256",
                "schema_version",
                "service_tree_sha256",
            },
            "GA journal export receipt",
        )
    except PublicationError as error:
        raise GAAcceptanceJournalExportError(str(error)) from error
    if type(receipt["schema_version"]) is not int or receipt != _receipt(intent):
        raise GAAcceptanceJournalExportError(
            "GA journal export receipt does not bind its exact intent"
        )
    return receipt


def _container_files(
    snapshot: SourceSnapshot,
    intent: dict[str, Any],
) -> dict[str, bytes]:
    files = dict(snapshot.payload_files)
    files[INTERNAL_INTENT_NAME] = canonical_json(intent)
    files[RECEIPT_NAME] = canonical_json(_receipt(intent))
    return files


def _write_pending_tree(
    acceptance_descriptor: int,
    acceptance_root: Path,
    pending_name: str,
    files: dict[str, bytes],
) -> Path:
    pending = acceptance_root / pending_name
    pending_created = False
    try:
        os.mkdir(pending_name, 0o700, dir_fd=acceptance_descriptor)
        pending_created = True
        fsync_locked_directory(acceptance_descriptor, acceptance_root)
    except (OSError, PublicationError) as error:
        if pending_created or os.path.lexists(pending):
            raise GAAcceptanceJournalExportOutcomeUnknown(
                "journal export pending-container creation outcome is unknown; "
                "fixed recovery is required"
            ) from error
        raise GAAcceptanceJournalExportRecoveryRequired(
            "journal export pending container was not created; fixed recovery is required"
        ) from error
    service_root = pending / SERVICE_NAME
    try:
        service_root.mkdir(mode=0o700)
        fsync_directory(pending)
        for relative, data in sorted(files.items()):
            parsed = safe_relative(relative, "journal export pending path")
            if len(parsed.parts) == 1:
                destination = pending / parsed.name
            elif len(parsed.parts) == 2 and parsed.parts[0] == SERVICE_NAME:
                destination = service_root / parsed.parts[1]
            else:
                raise GAAcceptanceJournalExportError(
                    "journal export pending payload path is outside the fixed layout"
                )
            write_private_pending(destination, data)
        fsync_private_tree(pending)
    except (OSError, PublicationError) as error:
        raise GAAcceptanceJournalExportRecoveryRequired(
            "journal export pending container is incomplete; fixed recovery is required "
            "without replacing it"
        ) from error
    return pending


def _read_container_files(root: Path) -> dict[str, bytes]:
    root_before = _private_directory(root, "GA migration journal container")
    try:
        root_names = set(os.listdir(root))
    except OSError as error:
        raise GAAcceptanceJournalExportError(
            "GA migration journal container cannot be enumerated"
        ) from error
    if root_names != {
        INSTALL_NAME,
        SERVICE_NAME,
        INTERNAL_INTENT_NAME,
        RECEIPT_NAME,
    }:
        raise GAAcceptanceJournalExportError(
            "GA migration journal container inventory is invalid"
        )
    service_root = root / SERVICE_NAME
    service_before = _private_directory(
        service_root, "GA exported service transaction"
    )
    try:
        service_names = sorted(os.listdir(service_root))
    except OSError as error:
        raise GAAcceptanceJournalExportError(
            "GA exported service transaction cannot be enumerated"
        ) from error
    if not 1 <= len(service_names) <= MAX_SERVICE_FILES:
        raise GAAcceptanceJournalExportError(
            "GA exported service transaction file count is invalid"
        )
    files = {
        INSTALL_NAME: _read_private_file(root / INSTALL_NAME, "GA install journal"),
        INTERNAL_INTENT_NAME: _read_private_file(
            root / INTERNAL_INTENT_NAME, "GA journal export intent"
        ),
        RECEIPT_NAME: _read_private_file(
            root / RECEIPT_NAME, "GA journal export receipt"
        ),
    }
    for name in service_names:
        if SERVICE_FILE_NAME_PATTERN.fullmatch(name) is None:
            raise GAAcceptanceJournalExportError(
                "GA exported service transaction name is unsafe"
            )
        files[f"{SERVICE_NAME}/{name}"] = _read_private_file(
            service_root / name,
            f"GA exported service journal {name}",
        )
    try:
        root_after = root.lstat()
        service_after = service_root.lstat()
    except OSError as error:
        raise GAAcceptanceJournalExportError(
            "GA migration journal container changed while reopening"
        ) from error
    if (
        _metadata_identity(root_before) != _metadata_identity(root_after)
        or _metadata_identity(service_before) != _metadata_identity(service_after)
    ):
        raise GAAcceptanceJournalExportError(
            "GA migration journal container changed while reopening"
        )
    return files


def _repository_record(repository: Path, path: Path, digest: str) -> dict[str, str]:
    try:
        relative = path.relative_to(repository).as_posix()
    except ValueError as error:
        raise GAAcceptanceJournalExportError(
            "GA journal export record escaped the repository"
        ) from error
    safe_relative(relative, "GA journal export record path")
    return {"path": relative, "sha256": digest}


def _verify_container(
    paths: JournalExportPaths,
    root: Path,
    external_intent_data: bytes,
) -> dict[str, Any]:
    files = _read_container_files(root)
    internal_intent_data = files.pop(INTERNAL_INTENT_NAME)
    receipt_data = files.pop(RECEIPT_NAME)
    if internal_intent_data != external_intent_data:
        raise GAAcceptanceJournalExportError(
            "external and container journal export intents differ"
        )
    intent = _validate_intent(
        _strict_json(internal_intent_data, "GA journal export intent")
    )
    receipt = _validate_receipt(
        _strict_json(receipt_data, "GA journal export receipt"),
        intent,
    )
    payload_records = [
        _file_record(relative, data) for relative, data in sorted(files.items())
    ]
    payload_entries = _tree_entries(files)
    if (
        payload_records != intent["payload"]["files"]
        or tree_digest(payload_entries) != intent["payload"]["tree_sha256"]
    ):
        raise GAAcceptanceJournalExportError(
            "GA journal export payload differs from its durable intent"
        )
    install_data = files[INSTALL_NAME]
    service_files = {
        relative.removeprefix(f"{SERVICE_NAME}/"): data
        for relative, data in files.items()
        if relative.startswith(f"{SERVICE_NAME}/")
    }
    try:
        install_document = install.validate_journal(
            _strict_json(install_data, "GA exported install journal")
        )
        environment, service_intent, service_events = (
            service.validate_terminal_snapshot_files(service_files)
        )
    except install.InstallError as error:
        raise GAAcceptanceJournalExportError(
            "GA exported producer journals are invalid"
        ) from error
    environment_sha256 = ga_environment.environment_sha256(environment)
    service_tree_sha256 = _service_tree_sha256(service_files)
    if (
        install_document["phase"] != "installed"
        or service_events[-1]["phase"] != "recommissioned"
        or service_intent["candidate"] != install_document["candidate"]
        or service_intent["previous"] != install_document["previous"]
        or service_intent["ga_environment_sha256"]
        != install_document["ga_environment_sha256"]
        or environment_sha256 != install_document["ga_environment_sha256"]
        or intent["candidate"] != install_document["candidate"]
        or intent["previous"] != install_document["previous"]
        or intent["ga_environment_sha256"] != environment_sha256
        or intent["service_tree_sha256"] != service_tree_sha256
    ):
        raise GAAcceptanceJournalExportError(
            "GA journal export binds a mixed migration or environment"
        )
    all_files = {
        **files,
        INTERNAL_INTENT_NAME: internal_intent_data,
        RECEIPT_NAME: receipt_data,
    }
    container_tree_sha256 = tree_digest(_tree_entries(all_files))
    return {
        "candidate": service_intent["candidate"],
        "environment": {
            "document": environment,
            "record": _repository_record(
                paths.repository,
                root / SERVICE_NAME / service.ENVIRONMENT_NAME,
                sha256_bytes(service_files[service.ENVIRONMENT_NAME]),
            ),
            "sha256": environment_sha256,
        },
        "export": {
            "intent": intent,
            "receipt": receipt,
            "record": _repository_record(
                paths.repository,
                root,
                container_tree_sha256,
            ),
        },
        "install_journal": {
            "document": install_document,
            "record": _repository_record(
                paths.repository,
                root / INSTALL_NAME,
                sha256_bytes(install_data),
            ),
        },
        "previous": service_intent["previous"],
        "service_journal": {
            "events": list(service_events),
            "intent": service_intent,
            "record": _repository_record(
                paths.repository,
                root / SERVICE_NAME,
                service_tree_sha256,
            ),
        },
    }


def _external_intent_bytes(paths: JournalExportPaths) -> bytes:
    final_exists = os.path.lexists(paths.external_intent)
    pending_exists = os.path.lexists(paths.external_pending_intent)
    if final_exists and pending_exists:
        raise GAAcceptanceJournalExportError(
            "published and pending journal export intents coexist"
        )
    if not final_exists and not pending_exists:
        raise GAAcceptanceJournalExportError("journal export intent is absent")
    return _read_private_file(
        paths.external_intent if final_exists else paths.external_pending_intent,
        "GA journal export intent",
    )


def _publish_external_intent(
    paths: JournalExportPaths,
    data: bytes,
) -> None:
    try:
        with exclusive_rooted_directory_lock(
            paths.repository,
            paths.stage_input_root,
            require_private=True,
        ) as descriptor:
            if os.path.lexists(paths.external_intent) or os.path.lexists(
                paths.external_pending_intent
            ):
                raise GAAcceptanceJournalExportError(
                    "journal export intent already exists; use fixed recovery"
                )
            write_private_pending_locked(
                descriptor,
                paths.stage_input_root,
                EXTERNAL_PENDING_INTENT_NAME,
                data,
            )
            promote_private_pending(
                paths.external_pending_intent,
                paths.external_intent,
            )
    except GAAcceptanceJournalExportError:
        raise
    except (DurabilityOutcomeUnknown, RootedDirectoryChanged) as error:
        raise GAAcceptanceJournalExportOutcomeUnknown(
            "journal export intent publication outcome is unknown; fixed recovery "
            "is required"
        ) from error
    except PublicationError as error:
        if os.path.lexists(paths.external_intent):
            raise GAAcceptanceJournalExportOutcomeUnknown(
                "journal export intent may have been published; fixed recovery is required"
            ) from error
        if os.path.lexists(paths.external_pending_intent):
            raise GAAcceptanceJournalExportRecoveryRequired(
                "journal export pending intent exists; fixed recovery is required"
            ) from error
        raise GAAcceptanceJournalExportError(
            "journal export intent was not published durably"
        ) from error


def _ensure_acceptance_root(paths: JournalExportPaths) -> None:
    root_created = False
    try:
        with exclusive_rooted_directory_lock(
            paths.repository,
            paths.stage_input_root,
            require_private=True,
        ) as descriptor:
            if os.path.lexists(paths.acceptance_root):
                _private_directory(paths.acceptance_root, "GA acceptance input root")
                return
            os.mkdir(
                paths.acceptance_root.name,
                0o700,
                dir_fd=descriptor,
            )
            root_created = True
            fsync_locked_directory(descriptor, paths.stage_input_root)
    except GAAcceptanceJournalExportError:
        raise
    except RootedDirectoryChanged as error:
        if root_created:
            raise GAAcceptanceJournalExportOutcomeUnknown(
                "GA acceptance input root creation outcome is unknown; recover"
            ) from error
        raise GAAcceptanceJournalExportRecoveryRequired(
            "GA acceptance input root changed; fixed recovery is required"
        ) from error
    except (OSError, PublicationError) as error:
        if root_created or os.path.lexists(paths.acceptance_root):
            raise GAAcceptanceJournalExportOutcomeUnknown(
                "GA acceptance input root creation outcome is unknown; fixed recovery "
                "is required"
            ) from error
        raise GAAcceptanceJournalExportRecoveryRequired(
            "GA acceptance input root was not created; fixed recovery is required"
        ) from error


def _complete_export(
    paths: JournalExportPaths,
    snapshot: SourceSnapshot,
    intent: dict[str, Any],
) -> dict[str, Any]:
    _ensure_acceptance_root(paths)
    expected_files = _container_files(snapshot, intent)
    pending = paths.acceptance_root / intent["pending_name"]
    destination = paths.migration_root
    mutation_started = False
    published_this_call = False
    try:
        with exclusive_rooted_directory_lock(
            paths.repository,
            paths.acceptance_root,
            require_private=True,
        ) as descriptor:
            pending_exists = os.path.lexists(pending)
            destination_exists = os.path.lexists(destination)
            if pending_exists and destination_exists:
                raise GAAcceptanceJournalExportError(
                    "pending and published migration journal containers coexist"
                )
            if not destination_exists:
                if pending_exists:
                    observed = _read_container_files(pending)
                    if observed != expected_files:
                        raise GAAcceptanceJournalExportError(
                            "pending migration journal container is partial or drifted"
                        )
                else:
                    mutation_started = True
                    _write_pending_tree(
                        descriptor,
                        paths.acceptance_root,
                        intent["pending_name"],
                        expected_files,
                    )
                mutation_started = True
                publish_private_directory_exclusive(pending, destination)
                published_this_call = True
    except GAAcceptanceJournalExportError:
        raise
    except (DurabilityOutcomeUnknown, RootedDirectoryChanged) as error:
        if mutation_started:
            raise GAAcceptanceJournalExportOutcomeUnknown(
                "migration journal publication outcome is unknown; fixed recovery is "
                "required"
            ) from error
        raise GAAcceptanceJournalExportRecoveryRequired(
            "migration journal container changed; fixed recovery is required"
        ) from error
    except PublicationError as error:
        raise GAAcceptanceJournalExportRecoveryRequired(
            "migration journal container cannot be published; fixed recovery is required"
        ) from error
    try:
        return _verify_published_export(paths)
    except (GAAcceptanceJournalExportError, OSError, PublicationError) as error:
        if published_this_call:
            raise GAAcceptanceJournalExportRecoveryRequired(
                "published migration journal container could not be reopened; fixed "
                "recovery is required"
            ) from error
        raise


def export_ga_acceptance_journals(
    paths: JournalExportPaths,
    *,
    observer: EnvironmentObserver = ga_environment.observe_environment,
    transaction_id: str | None = None,
) -> dict[str, Any]:
    """Create one source-bound intent, then publish one immutable container."""

    paths = _validated_paths(paths)
    selected_id = str(uuid.uuid4()) if transaction_id is None else transaction_id
    intent_is_durable = False
    try:
        with _locked_source_snapshot(paths, observer) as snapshot:
            intent = _validate_intent(_intent(snapshot, selected_id))
            intent_data = canonical_json(intent)
            _publish_external_intent(paths, intent_data)
            intent_is_durable = True
            return _complete_export(paths, snapshot, intent)
    except GAAcceptanceJournalExportRecoveryRequired:
        raise
    except (GAAcceptanceJournalExportError, OSError, PublicationError) as error:
        if intent_is_durable:
            raise GAAcceptanceJournalExportRecoveryRequired(
                "journal export intent is durable but completion failed; fixed "
                "recovery is required"
            ) from error
        raise


def recover_ga_acceptance_journal_export(
    paths: JournalExportPaths,
    *,
    observer: EnvironmentObserver = ga_environment.observe_environment,
) -> dict[str, Any]:
    """Recover only the exact durable intent and its exact source journals."""

    paths = _validated_paths(paths)
    external_data = _external_intent_bytes(paths)
    intent = _validate_intent(_strict_json(external_data, "GA journal export intent"))
    with _locked_source_snapshot(paths, observer) as snapshot:
        expected = _validate_intent(_intent(snapshot, intent["transaction_id"]))
        if canonical_json(expected) != external_data:
            raise GAAcceptanceJournalExportError(
                "producer journals or GA environment drifted after export intent"
            )
        intent_promoted = False
        try:
            with exclusive_rooted_directory_lock(
                paths.repository,
                paths.stage_input_root,
                require_private=True,
            ):
                if os.path.lexists(paths.external_pending_intent):
                    promote_private_pending(
                        paths.external_pending_intent,
                        paths.external_intent,
                    )
                    intent_promoted = True
                    published_external_data = _read_private_file(
                        paths.external_intent,
                        "GA journal export intent",
                    )
                    if published_external_data != canonical_json(expected):
                        raise GAAcceptanceJournalExportError(
                            "recovered journal export intent differs from its source binding"
                        )
        except GAAcceptanceJournalExportRecoveryRequired:
            raise
        except GAAcceptanceJournalExportError as error:
            if intent_promoted:
                raise GAAcceptanceJournalExportRecoveryRequired(
                    "recovered journal export intent could not be reopened; rerun "
                    "fixed recovery"
                ) from error
            raise
        except (DurabilityOutcomeUnknown, RootedDirectoryChanged) as error:
            if intent_promoted or os.path.lexists(paths.external_intent):
                raise GAAcceptanceJournalExportOutcomeUnknown(
                    "journal export intent recovery outcome is unknown; rerun fixed "
                    "recovery"
                ) from error
            raise GAAcceptanceJournalExportRecoveryRequired(
                "journal export intent recovery remains pending"
            ) from error
        except PublicationError as error:
            raise GAAcceptanceJournalExportRecoveryRequired(
                "journal export intent recovery failed before completion"
            ) from error
        return _complete_export(paths, snapshot, expected)


def _verify_published_export(paths: JournalExportPaths) -> dict[str, Any]:
    try:
        with exclusive_rooted_directory_lock(
            paths.repository,
            paths.stage_input_root,
            require_private=True,
        ):
            external_data = _read_private_file(
                paths.external_intent,
                "GA journal export intent",
            )
            if os.path.lexists(paths.external_pending_intent):
                raise GAAcceptanceJournalExportError(
                    "pending journal export intent cannot authorize GA acceptance"
                )
            with exclusive_rooted_directory_lock(
                paths.repository,
                paths.acceptance_root,
                require_private=True,
            ) as acceptance_descriptor:
                acceptance_names = os.listdir(acceptance_descriptor)
                if any(
                    name.startswith(".migration-journals-")
                    and name.endswith(".pending")
                    for name in acceptance_names
                ):
                    raise GAAcceptanceJournalExportError(
                        "pending migration journal container cannot authorize GA acceptance"
                    )
                return _verify_container(
                    paths,
                    paths.migration_root,
                    external_data,
                )
    except GAAcceptanceJournalExportError:
        raise
    except (OSError, PublicationError) as error:
        raise GAAcceptanceJournalExportError(
            "GA journal export fixed paths could not be reopened safely"
        ) from error


def verify_ga_acceptance_journal_export(
    repository: Path,
) -> dict[str, Any]:
    """Reopen the fixed atomic container without consulting live producers."""

    return _verify_published_export(JournalExportPaths.verification(repository))


def self_check() -> None:
    if (
        (PRODUCT_VERSION, PREVIOUS_BUILD, GA_BUILD) != ("0.4.0", "40019", "40039")
        or MIGRATION_RELATIVE
        != Path(
            "target/candidates/0.4.0/ga/40039/stage-inputs/"
            "ga-acceptance/migration-journals"
        )
        or ENVIRONMENT_RELATIVE
        != MIGRATION_RELATIVE / "service-transaction/environment.json"
        or (INTENT_DOCUMENT, RECEIPT_DOCUMENT, SCHEMA_VERSION)
        != (
            "cfm-ga-journal-export-intent-v1",
            "cfm-ga-journal-export-receipt-v1",
            1,
        )
    ):
        raise GAAcceptanceJournalExportError(
            "GA journal export source contract drifted"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--export", action="store_true")
    mode.add_argument("--recover", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--self-check", action="store_true")
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.self_check:
            self_check()
            print("GA journal export source contract passed")
            return
        if arguments.verify:
            result = verify_ga_acceptance_journal_export(repository)
        else:
            paths = JournalExportPaths.production(repository)
            result = (
                export_ga_acceptance_journals(paths)
                if arguments.export
                else recover_ga_acceptance_journal_export(paths)
            )
    except GAAcceptanceJournalExportError as error:
        raise SystemExit(f"error: GA journal export: {error}") from error
    print(
        "GA migration journals verified: "
        f"{result['previous']['build_number']} -> "
        f"{result['candidate']['build_number']}"
    )


if __name__ == "__main__":
    from release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )

    try:
        require_closed_release_runtime()
    except ReleasePythonRuntimeError as error:
        raise SystemExit(f"error: GA journal export runtime admission: {error}") from error
    main()
