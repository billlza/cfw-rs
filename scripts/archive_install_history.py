"""Retain one completed installation before reusing its fixed journal namespace.

This does not stop services, change networking, or remove application bundles.
Both producer journals must be terminal and describe the exact installed app.
The original maintenance/service/install locks cover both atomic renames. A
durable intent permits the same operation to resume after either rename.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
from typing import Callable, NoReturn

from . import current_service_transaction as service
from . import dormant_app_install as install
from .hash_artifact import build_manifest
from .release_executor_source import capture_executor_source, require_executor_unchanged, validate_source_identity

HISTORY_NAME = ".com.bill.clashformac.install-history-v1"
INTENT_NAME = "intent.json"
COMPLETE_NAME = "complete.json"


def _fail(message: str) -> NoReturn:
    raise install.InstallError("install_history_unproven", message)


def _private_directory(path: Path) -> int:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        _fail("installation history directory has unsafe ownership or permissions")
    return descriptor


def _require_directory(descriptor: int, path: Path) -> None:
    held = os.fstat(descriptor)
    visible = path.lstat()
    if not stat.S_ISDIR(visible.st_mode) or (held.st_dev, held.st_ino) != (
        visible.st_dev, visible.st_ino
    ) or visible.st_uid != os.geteuid() or stat.S_IMODE(visible.st_mode) != 0o700:
        _fail("installation history directory identity changed")


def _snapshot_pair(
    paths: install.InstallPaths, service_parent: Path, install_parent: Path
) -> tuple[service.TerminalServiceJournalSnapshot, install.TerminalInstallJournalSnapshot]:
    # The original producer locks remain held even after the immutable files
    # move into history. No independent archive writer is admitted.
    with service.ServiceEventStore(service.ServicePaths(
        install_paths=replace(paths, target_parent=service_parent),
        transaction_parent=service_parent,
    )) as reader:
        service_snapshot = reader.terminal_snapshot()
    with install.JournalStore(replace(paths, target_parent=install_parent)) as reader:
        install_snapshot = reader.terminal_snapshot()
    for key in ("candidate", "previous", "ga_environment_sha256"):
        if service_snapshot.intent[key] != install_snapshot.document[key]:
            _fail("completed service and installation records do not describe the same upgrade")
    return service_snapshot, install_snapshot


def _digests(paths: install.InstallPaths, service_parent: Path, journal: bytes) -> dict[str, str]:
    return {
        "service_tree_sha256": build_manifest(
            service_parent / paths.profile.service_transaction_directory,
            algorithm="sha256-tree-v2",
        )["sha256"],
        "install_journal_sha256": hashlib.sha256(journal).hexdigest(),
    }


def _intent(
    service_snapshot: service.TerminalServiceJournalSnapshot,
    install_snapshot: install.TerminalInstallJournalSnapshot,
    executor_identity: dict[str, str],
    digests: dict[str, str],
) -> dict[str, object]:
    validate_source_identity(executor_identity, "installation history executor")
    return {
        "document": "cfm-install-history-intent-v1",
        "candidate": install_snapshot.document["candidate"],
        "service_transaction_id": service_snapshot.intent["transaction_id"],
        "install_transaction_id": install_snapshot.document["transaction_id"],
        "executor": executor_identity,
        **digests,
    }


def archive_completed_history(
    paths: install.InstallPaths,
    expected: install.AppIdentity,
    executor_identity: dict[str, str],
    observe_installed: Callable[[], install.AppIdentity],
    require_source_unchanged: Callable[[], None],
    *,
    move: Callable[..., None] = os.rename,
) -> Path:
    install.canonical_build_version(expected.build_number, "installation history build")
    validate_source_identity(executor_identity, "installation history executor")
    if paths.profile.build_number != expected.build_number:
        _fail("history profile does not match the expected installed build")
    history = paths.target_parent / HISTORY_NAME
    destination = history / expected.build_number
    service_name = paths.profile.service_transaction_directory
    names = (service_name, paths.journal_name)
    if any(name in {"", ".", ".."} or Path(name).name != name for name in names):
        _fail("producer journal names must be single path components")
    with service.ServiceEventStore(service.ServicePaths(paths, paths.target_parent)) as service_store:
        with service_store.locked(require_existing=True):
            with install.JournalStore(paths) as install_store:
                with install_store.locked(require_existing=True):
                    history_fd = _private_directory(history)
                    try:
                        archive_fd = _private_directory(destination)
                        try:
                            _require_directory(history_fd, history)
                            _require_directory(archive_fd, destination)
                            complete_path = destination / COMPLETE_NAME
                            intent_path = destination / INTENT_NAME
                            if complete_path.exists():
                                if set(os.listdir(archive_fd)) != {INTENT_NAME, COMPLETE_NAME, *names}:
                                    _fail("completed installation history inventory changed")
                                recorded = service._strict_json_bytes(
                                    service.ServiceEventStore._read(archive_fd, COMPLETE_NAME, "history receipt"),
                                    "history receipt",
                                )
                                archived_service, archived = _snapshot_pair(paths, destination, destination)
                                intent_data = service.ServiceEventStore._read(archive_fd, INTENT_NAME, "history intent")
                                prior_intent = service._strict_json_bytes(intent_data, "history intent")
                                digests = _digests(paths, destination, archived.data)
                                if prior_intent != _intent(archived_service, archived, prior_intent.get("executor"), digests):
                                    _fail("completed installation history intent changed")
                                if recorded != {
                                    "document": "cfm-install-history-complete-v1",
                                    "candidate": archived.document["candidate"],
                                    "intent_sha256": hashlib.sha256(intent_data).hexdigest(),
                                    **digests,
                                } or archived.document["candidate"]["tree_sha256"] != expected.tree_sha256:
                                    _fail("completed installation history changed")
                                return destination

                            if set(os.listdir(archive_fd)) - {INTENT_NAME, *names}:
                                _fail("incomplete installation history has unexpected files")
                            for name in (paths.profile.service_pending_directory, paths.journal_pending_name):
                                pending = paths.target_parent / name
                                if pending.exists() or pending.is_symlink():
                                    _fail("pending producer work cannot be archived")
                            locations: list[Path] = []
                            for name in names:
                                original = paths.target_parent / name
                                retained = destination / name
                                present = [p for p in (original, retained) if p.exists() or p.is_symlink()]
                                if len(present) != 1:
                                    _fail("each producer journal must exist at exactly one recorded location")
                                locations.append(present[0].parent)
                            service_snapshot, install_snapshot = _snapshot_pair(paths, *locations)
                            candidate = install_snapshot.document["candidate"]
                            if any(candidate[key] != value for key, value in expected.document().items()):
                                _fail("completed records do not match the expected installed application")
                            if observe_installed() != expected:
                                _fail("the installed application changed before history retention")
                            digests = _digests(paths, locations[0], install_snapshot.data)
                            intent = _intent(service_snapshot, install_snapshot, executor_identity, digests)
                            if intent_path.exists():
                                recorded = service._strict_json_bytes(
                                    service.ServiceEventStore._read(archive_fd, INTENT_NAME, "history intent"),
                                    "history intent",
                                )
                                if recorded != intent:
                                    _fail("incomplete installation history differs from its durable intent")
                            else:
                                if set(os.listdir(archive_fd)) or locations != [paths.target_parent] * 2:
                                    _fail("history has unbound files or moved journals without an intent")
                                require_source_unchanged()
                                service.ServiceEventStore._write_new(archive_fd, INTENT_NAME, intent)
                                install._fsync_directory_fd(history_fd)
                                install._fsync_directory_fd(service_store.parent_fd)

                            for name, parent in zip(names, locations, strict=True):
                                if parent == destination:
                                    continue
                                require_source_unchanged()
                                _require_directory(history_fd, history)
                                _require_directory(archive_fd, destination)
                                if (destination / name).exists() or (destination / name).is_symlink():
                                    _fail("history destination unexpectedly exists")
                                move(name, name, src_dir_fd=service_store.parent_fd, dst_dir_fd=archive_fd)
                                install._fsync_directory_fd(archive_fd)
                                install._fsync_directory_fd(service_store.parent_fd)
                            _, retained = _snapshot_pair(paths, destination, destination)
                            if _digests(paths, destination, retained.data) != digests or observe_installed() != expected:
                                _fail("installation history or installed application changed during retention")
                            require_source_unchanged()
                            _require_directory(history_fd, history)
                            _require_directory(archive_fd, destination)
                            service.ServiceEventStore._write_new(archive_fd, COMPLETE_NAME, {
                                "document": "cfm-install-history-complete-v1",
                                "candidate": candidate,
                                "intent_sha256": hashlib.sha256(install._canonical_json(intent)).hexdigest(),
                                **digests,
                            })
                            return destination
                        finally:
                            os.close(archive_fd)
                    finally:
                        os.close(history_fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-build", required=True)
    arguments = parser.parse_args()
    if os.geteuid() == 0:
        _fail("installation history must be retained by its owning administrator, not sudo")
    predecessor = install.SUPPORTED_PREDECESSORS.get(arguments.previous_build)
    if predecessor is None:
        _fail("installation history build is not an explicitly supported predecessor")
    expected = install.AppIdentity(install.VERSION, predecessor.build_number, predecessor.tree_sha256)
    profile = replace(install.GA_INSTALL_PROFILE, build_number=predecessor.build_number)
    paths = replace(install.InstallPaths.production(), profile=profile)
    repository = Path(__file__).resolve().parent.parent
    executor = capture_executor_source(repository)
    destination = archive_completed_history(
        paths, expected, executor.identity,
        lambda: install.read_app_identity(paths.target_app),
        lambda: require_executor_unchanged(executor),
    )
    print(f"completed installation history retained: {predecessor.build_number} at {destination}")


if __name__ == "__main__":
    from .release_python_runtime import require_closed_release_runtime
    require_closed_release_runtime()
    main()
