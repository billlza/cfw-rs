#!/usr/bin/env python3
"""Strict test-only snapshots for high-cardinality release properties.

The production release builders intentionally reopen source and physical
evidence at every validation boundary.  Property tests exercise hundreds of
pure composition permutations over inputs that do not change on disk, so they
may snapshot those already-validated boundaries for the lifetime of one test
class.  Entry and exit both run the real validators.  Unknown keys are test
fixture defects and raise :class:`AssertionError`; they are never converted to
a production-domain rejection that a fail-closed property could mistake for a
successful assertion.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from contextlib import contextmanager, ExitStack
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, Iterable
from unittest.mock import patch

from scripts.harness.raw_artifacts import canonical_json, RawArtifactError


SourceDeriver = Callable[[Path], dict[str, Any]]
PhysicalLoader = Callable[..., dict[str, Any]]
PatchPoint = tuple[object, str]


def _resolved_directory(value: Path, label: str) -> Path:
    if not isinstance(value, Path):
        raise AssertionError(f"{label} must be a pathlib.Path")
    try:
        resolved = value.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise AssertionError(f"{label} cannot be resolved") from error
    if value.is_symlink() or not resolved.is_dir():
        raise AssertionError(f"{label} must be a real directory")
    return resolved


def _policy_bytes(value: object) -> bytes:
    if not is_dataclass(value) or isinstance(value, type):
        raise AssertionError("physical snapshot trust policy must be a dataclass value")
    policy = asdict(value)
    digest = policy.get("policy_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise AssertionError("physical snapshot trust policy is not content-addressed")
    try:
        policy_type = type(value)
        return canonical_json(
            {
                "type": f"{policy_type.__module__}.{policy_type.__qualname__}",
                "fields": policy,
            }
        )
    except RawArtifactError as error:
        raise AssertionError(
            "physical snapshot trust policy is not canonical JSON"
        ) from error


def _descriptor_bytes(value: object) -> bytes:
    try:
        return canonical_json(value)
    except RawArtifactError as error:
        raise AssertionError("physical snapshot descriptor is not canonical JSON") from error


def _snapshot_bytes(value: object, label: str) -> bytes:
    try:
        return canonical_json(value)
    except RawArtifactError as error:
        raise AssertionError(f"{label} is not canonical JSON") from error


@dataclass(frozen=True)
class PhysicalSnapshotInput:
    """One exact physical-evidence invocation admitted by a property class."""

    descriptor: object
    evidence_root: Path
    trust_policy: object
    fixture: bool = True


@dataclass(frozen=True)
class _PhysicalKey:
    descriptor: bytes
    evidence_root: str
    trust_policy: bytes
    fixture: bool


class _SourceSnapshot:
    def __init__(self, repository: Path, derive: SourceDeriver) -> None:
        self._repository = _resolved_directory(repository, "source snapshot repository")
        self._derive_real = derive
        self._value = copy.deepcopy(self._derive_real(self._repository))
        self._value_bytes = _snapshot_bytes(self._value, "source property snapshot")

    def derive(self, repository: Path) -> dict[str, Any]:
        observed = _resolved_directory(repository, "source snapshot repository")
        if observed != self._repository:
            raise AssertionError(
                "source property requested an unregistered repository snapshot"
            )
        return copy.deepcopy(self._value)

    def revalidate(self) -> None:
        observed = self._derive_real(self._repository)
        if _snapshot_bytes(observed, "source property revalidation") != self._value_bytes:
            raise AssertionError("source property snapshot changed during the test class")


class _PhysicalSnapshot:
    def __init__(
        self,
        loader: PhysicalLoader,
        inputs: Iterable[PhysicalSnapshotInput],
    ) -> None:
        self._loader_real = loader
        self._values: dict[_PhysicalKey, dict[str, Any]] = {}
        self._value_bytes: dict[_PhysicalKey, bytes] = {}
        self._inputs: dict[_PhysicalKey, PhysicalSnapshotInput] = {}
        for item in inputs:
            key = self._key(
                item.descriptor,
                evidence_root=item.evidence_root,
                trust_policy=item.trust_policy,
                fixture=item.fixture,
            )
            if key in self._values:
                raise AssertionError("physical property snapshot input is duplicated")
            value = self._loader_real(
                copy.deepcopy(item.descriptor),
                evidence_root=item.evidence_root,
                trust_policy=item.trust_policy,
                fixture=item.fixture,
            )
            self._inputs[key] = PhysicalSnapshotInput(
                descriptor=copy.deepcopy(item.descriptor),
                evidence_root=item.evidence_root,
                trust_policy=item.trust_policy,
                fixture=item.fixture,
            )
            self._values[key] = copy.deepcopy(value)
            self._value_bytes[key] = _snapshot_bytes(
                value, "physical property snapshot"
            )
        if not self._values:
            raise AssertionError("physical snapshot requires at least one registered input")

    @property
    def real_loader(self) -> PhysicalLoader:
        return self._loader_real

    @staticmethod
    def _key(
        descriptor: object,
        *,
        evidence_root: Path,
        trust_policy: object,
        fixture: bool,
    ) -> _PhysicalKey:
        if type(fixture) is not bool:
            raise AssertionError("physical snapshot fixture marker must be boolean")
        root = _resolved_directory(evidence_root, "physical snapshot evidence root")
        return _PhysicalKey(
            descriptor=_descriptor_bytes(descriptor),
            evidence_root=str(root),
            trust_policy=_policy_bytes(trust_policy),
            fixture=fixture,
        )

    def load(
        self,
        descriptor: object,
        *,
        evidence_root: Path,
        trust_policy: object,
        fixture: bool,
    ) -> dict[str, Any]:
        key = self._key(
            descriptor,
            evidence_root=evidence_root,
            trust_policy=trust_policy,
            fixture=fixture,
        )
        try:
            value = self._values[key]
        except KeyError as error:
            raise AssertionError(
                "physical property requested an unregistered evidence snapshot"
            ) from error
        return copy.deepcopy(value)

    def revalidate(self) -> None:
        for key, item in self._inputs.items():
            observed = self._loader_real(
                copy.deepcopy(item.descriptor),
                evidence_root=item.evidence_root,
                trust_policy=item.trust_policy,
                fixture=item.fixture,
            )
            if (
                _snapshot_bytes(observed, "physical property revalidation")
                != self._value_bytes[key]
            ):
                raise AssertionError(
                    "physical property snapshot changed during the test class"
                )


def _require_patch_points(
    points: Iterable[PatchPoint],
    expected: object,
    label: str,
) -> tuple[PatchPoint, ...]:
    result = tuple(points)
    if not result:
        raise AssertionError(f"{label} snapshot has no consumers")
    identities: set[tuple[int, str]] = set()
    for owner, attribute in result:
        identity = (id(owner), attribute)
        if identity in identities:
            raise AssertionError(f"{label} snapshot consumer is duplicated")
        identities.add(identity)
        if getattr(owner, attribute, None) is not expected:
            raise AssertionError(f"{label} snapshot consumer differs from the real dependency")
    return result


class StrictReleasePropertySnapshots:
    """Scope strict source/physical snapshots to one property test class."""

    def __init__(
        self,
        *,
        repository: Path,
        source_deriver: SourceDeriver,
        source_consumers: Iterable[PatchPoint],
        physical_loader: PhysicalLoader | None = None,
        physical_consumers: Iterable[PatchPoint] = (),
        physical_inputs: Iterable[PhysicalSnapshotInput] = (),
    ) -> None:
        self._source_dependency = source_deriver
        self._source_consumers = _require_patch_points(
            source_consumers, source_deriver, "source"
        )
        self._source = _SourceSnapshot(repository, source_deriver)

        physical_points = tuple(physical_consumers)
        physical_values = tuple(physical_inputs)
        if physical_loader is None:
            if physical_points or physical_values:
                raise AssertionError(
                    "physical snapshot consumers/inputs require the real loader"
                )
            self._physical_consumers: tuple[PatchPoint, ...] = ()
            self._physical: _PhysicalSnapshot | None = None
            self._physical_dependency: PhysicalLoader | None = None
        else:
            self._physical_dependency = physical_loader
            self._physical_consumers = _require_patch_points(
                physical_points, physical_loader, "physical"
            )
            self._physical = _PhysicalSnapshot(physical_loader, physical_values)

        self._patches: ExitStack | None = None

    def __enter__(self) -> StrictReleasePropertySnapshots:
        if self._patches is not None:
            raise AssertionError("release property snapshots cannot be entered twice")
        _require_patch_points(
            self._source_consumers, self._source_dependency, "source"
        )
        if self._physical_dependency is not None:
            _require_patch_points(
                self._physical_consumers,
                self._physical_dependency,
                "physical",
            )
        patches = ExitStack()
        try:
            for owner, attribute in self._source_consumers:
                patches.enter_context(patch.object(owner, attribute, self._source.derive))
            if self._physical is not None:
                for owner, attribute in self._physical_consumers:
                    patches.enter_context(
                        patch.object(owner, attribute, self._physical.load)
                    )
        except BaseException:
            patches.close()
            raise
        self._patches = patches
        return self

    @contextmanager
    def uncached_physical_validation(self) -> Iterator[None]:
        """Run one intentional physical-defect case through the real loader.

        This is an explicit scope for property mutators whose defect is the
        physical descriptor itself.  It is not a fallback: callers must opt in,
        and every unregistered key outside this scope remains an AssertionError.
        """

        if self._patches is None or self._physical is None:
            raise AssertionError(
                "uncached physical validation requires active physical snapshots"
            )
        with ExitStack() as patches:
            for owner, attribute in self._physical_consumers:
                patches.enter_context(
                    patch.object(owner, attribute, self._physical.real_loader)
                )
            yield

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if self._patches is None:
            raise AssertionError("release property snapshots were not entered")
        self._patches.close()
        self._patches = None

        revalidation_errors: list[BaseException] = []
        if self._physical is not None:
            try:
                self._physical.revalidate()
            except BaseException as error:
                revalidation_errors.append(error)
        try:
            self._source.revalidate()
        except BaseException as error:
            revalidation_errors.append(error)

        if revalidation_errors:
            revalidation_error: BaseException
            if len(revalidation_errors) == 1:
                revalidation_error = revalidation_errors[0]
            else:
                revalidation_error = BaseExceptionGroup(
                    "release property snapshot exit revalidation failures",
                    revalidation_errors,
                )
            if exception is None:
                raise revalidation_error
            exception.add_note(
                "release property snapshot exit revalidation also failed: "
                f"{revalidation_error}"
            )
        return False


__all__ = [
    "PhysicalSnapshotInput",
    "StrictReleasePropertySnapshots",
]
