"""Atomic publication owner for the three fixed v0.4.0 GA stages."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .common import PublicationError
from .durable_file import (
    DurabilityOutcomeUnknown,
    RootedDirectoryChanged,
    exclusive_rooted_directory_lock,
    publish_private_directory_locked,
    read_private_directory_contents_locked,
)
from . import ga_release_contract as contract


def _publish_stage(
    repository: Path,
    stage: str,
    expected_files: dict[str, bytes],
) -> dict[str, Any]:
    repository = contract._canonical_repository(repository)
    if stage not in contract.STAGES:
        raise PublicationError(f"unknown GA release stage: {stage}")
    output = contract._path(repository, contract.STAGE_OUTPUTS[stage])
    parent = output.parent
    contract._require_real_directory(parent)
    if set(expected_files) != set(contract.STAGE_FILE_NAMES[stage]):
        raise PublicationError(f"{stage} composition has an unexpected file set")
    expected_manifest = contract._manifest_from_files(stage, expected_files, output)
    published_new = False
    try:
        with exclusive_rooted_directory_lock(repository, parent) as descriptor:
            try:
                os.stat(output.name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                for later_stage in contract.STAGES[contract.STAGES.index(stage) + 1 :]:
                    later_output = contract.STAGE_OUTPUTS[later_stage]
                    if later_output.parent != contract.STAGE_OUTPUTS[stage].parent:
                        raise PublicationError(
                            "GA stage outputs do not share one fixed parent"
                        )
                    try:
                        os.stat(
                            later_output.name,
                            dir_fd=descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        continue
                    except OSError as error:
                        raise PublicationError(
                            f"cannot inspect later immutable {later_stage} stage"
                        ) from error
                    raise PublicationError(
                        f"cannot create {stage} after a later GA stage"
                    )
                publish_private_directory_locked(
                    descriptor,
                    parent,
                    output.name,
                    expected_files,
                )
                published_new = True
            except OSError as error:
                raise PublicationError(
                    f"cannot inspect immutable {stage} stage"
                ) from error
            observed = read_private_directory_contents_locked(
                descriptor,
                parent,
                output.name,
                {name: len(data) for name, data in expected_files.items()},
            )
            if observed != expected_files:
                raise PublicationError(f"refusing to replace immutable {stage} stage")
    except RootedDirectoryChanged as error:
        if published_new:
            raise DurabilityOutcomeUnknown(
                f"{stage} stage publication outcome is unknown"
            ) from error
        raise
    try:
        observed = contract._read_stage_files(repository, stage)
    except RootedDirectoryChanged as error:
        if published_new:
            raise DurabilityOutcomeUnknown(
                f"{stage} stage publication outcome is unknown"
            ) from error
        raise
    manifest = contract._manifest_from_files(stage, observed, output)
    if manifest != expected_manifest or observed != expected_files:
        raise PublicationError(f"{stage} stage changed after atomic publication")
    return manifest


def _publish_and_confirm_stage(
    repository: Path,
    stage: str,
    expected_files: dict[str, bytes],
) -> dict[str, Any]:
    _publish_stage(repository, stage, expected_files)
    try:
        return contract.verify_stage(repository, stage)
    except DurabilityOutcomeUnknown:
        raise
    except (OSError, PublicationError, ValueError) as error:
        raise DurabilityOutcomeUnknown(
            f"{stage} seal exists but its post-publication input binding is unknown"
        ) from error


def seal_prepackage(repository: Path) -> dict[str, Any]:
    """Atomically authorize package creation for the exact GA application."""

    expected = contract.build_expected_stage_files(
        repository,
        "prepackage",
        require_live_hosted_ci=True,
    )
    return _publish_and_confirm_stage(repository, "prepackage", expected)


def seal_ga_acceptance(repository: Path) -> dict[str, Any]:
    """Atomically bind exact packages and the completed 40019 -> 40032 run."""

    expected = contract.build_expected_stage_files(repository, "ga-acceptance")
    return _publish_and_confirm_stage(repository, "ga-acceptance", expected)


def seal_publication(repository: Path) -> dict[str, Any]:
    """Atomically authorize upload after every GA-required stage reopens."""

    expected = contract.build_expected_stage_files(
        repository,
        "publication",
        require_live_hosted_ci=True,
    )
    return _publish_and_confirm_stage(repository, "publication", expected)
