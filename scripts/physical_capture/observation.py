"""Immutable pre-nonce observation manifests and producer boundary.

Physical behavior is executed only while a capture session is collecting.  Each
producer publishes its proof-free bytes below one fixed observation namespace.
The manifest then binds the exact subject, artifact kind, path, size, and digest
of every observation.  It contains no nonce or proof material; post-nonce code
may only reopen these bytes through the manifest.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Final, Protocol

from scripts.harness.raw_artifacts import (
    ARTIFACT_KINDS,
    ArtifactDescriptor,
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
    parse_descriptor,
)

from .archive import (
    ArchivedFile,
    PhysicalCaptureArchiveError,
    SecureArchive,
)
from .execution import (
    CommandResult,
    CommandSpec,
    ReadinessSpec,
    StartedCommand,
    run_fixed_command,
    start_fixed_command,
)


OBSERVATION_MANIFEST_RELATIVE: Final = "raw/observation-manifest.json"
OBSERVATION_MANIFEST_DOCUMENT: Final = "cfw-physical-observation-manifest-v1"
OBSERVATION_MANIFEST_SCHEMA_VERSION: Final = 1
MAX_OBSERVATIONS: Final = 512
MAX_MANIFEST_BYTES: Final = 1024 * 1024

OBSERVATION_HARNESSES: Final = (
    "adversarial",
    "lifecycle",
    "packet",
    "performance",
)
OBSERVATION_DIRECTORIES: Final = tuple(
    f"raw/{harness}/observations" for harness in OBSERVATION_HARNESSES
)

_MANIFEST_FIELDS: Final = {
    "schema_version",
    "document",
    "observation_count",
    "observations",
}
_ENTRY_FIELDS: Final = {"subject", "descriptor"}
_SUBJECT_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


class PhysicalObservationError(RuntimeError):
    """Observation bytes or their immutable manifest are invalid or drifted."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ObservationArtifact:
    subject: str
    descriptor: ArtifactDescriptor

    def as_entry(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "descriptor": self.descriptor.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class ObservationManifest:
    record: ArchivedFile
    observations: tuple[ObservationArtifact, ...]

    @property
    def root_sha256(self) -> str:
        return self.record.sha256

    def descriptor_mapping(self) -> dict[str, dict[str, object]]:
        return {
            observation.subject: observation.descriptor.as_dict()
            for observation in self.observations
        }


class _CollectionPhase(Protocol):
    archive: SecureArchive

    def require_collection_open(self) -> None: ...


class ObservationCommand:
    """A fixed command whose lifecycle remains bound to collection phase."""

    def __init__(self, phase: _CollectionPhase, command: StartedCommand) -> None:
        self._phase = phase
        self._command = command

    def __enter__(self) -> ObservationCommand:
        self._require_collection_open()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.cancel()

    def _require_collection_open(self) -> None:
        try:
            self._phase.require_collection_open()
        except BaseException:
            self._command.cancel()
            raise

    def wait_for_readiness(self, readiness: ReadinessSpec) -> None:
        """Wait for one exact line only while pre-nonce collection is open."""

        self._require_collection_open()
        self._command.wait_for_readiness(readiness)
        self._require_collection_open()

    def finish(self) -> CommandResult:
        """Finish the fixed command and revalidate collection before return."""

        self._require_collection_open()
        result = self._command.finish()
        self._require_collection_open()
        return result

    def cancel(self) -> None:
        self._command.cancel()


class ObservationCapture:
    """The only session-aware boundary for executing and archiving probes."""

    def __init__(self, phase: _CollectionPhase) -> None:
        if not isinstance(phase.archive, SecureArchive):
            raise PhysicalObservationError(
                "invalid_capture_phase",
                "observation capture requires a secure session archive",
            )
        self._phase = phase

    def run_command(self, spec: CommandSpec) -> CommandResult:
        """Run one source-fixed command only in the pre-nonce collection phase."""

        self._phase.require_collection_open()
        result = run_fixed_command(spec)
        self._phase.require_collection_open()
        return result

    def start_command(self, spec: CommandSpec) -> ObservationCommand:
        """Start one source-fixed command for bounded readiness coordination."""

        self._phase.require_collection_open()
        command = start_fixed_command(spec)
        try:
            self._phase.require_collection_open()
        except BaseException:
            command.cancel()
            raise
        return ObservationCommand(self._phase, command)

    def write_bytes(
        self,
        *,
        subject: str,
        kind: str,
        relative: str,
        data: bytes,
        maximum: int | None = None,
    ) -> ObservationArtifact:
        """Exclusively archive one proof-free observation while collecting."""

        _validate_declared_artifact(subject, kind, relative)
        bound = _maximum_for_kind(kind, maximum)
        self._phase.require_collection_open()
        try:
            archived = self._phase.archive.write_bytes(
                relative,
                data,
                maximum=bound,
            )
        except PhysicalCaptureArchiveError as error:
            raise PhysicalObservationError(
                "observation_archive_failed",
                "proof-free observation bytes could not be exclusively archived",
            ) from error
        self._phase.require_collection_open()
        return _parse_artifact(
            subject,
            archived.descriptor(kind),
            "captured observation",
        )

    def copy_file(
        self,
        *,
        subject: str,
        kind: str,
        source: Path,
        relative: str,
        maximum: int | None = None,
    ) -> ObservationArtifact:
        """Race-safely copy one existing probe output while collection is open."""

        _validate_declared_artifact(subject, kind, relative)
        bound = _maximum_for_kind(kind, maximum)
        self._phase.require_collection_open()
        try:
            archived = self._phase.archive.copy_file(
                source,
                relative,
                maximum=bound,
            )
        except PhysicalCaptureArchiveError as error:
            raise PhysicalObservationError(
                "observation_archive_failed",
                "proof-free observation file could not be exclusively archived",
            ) from error
        self._phase.require_collection_open()
        return _parse_artifact(
            subject,
            archived.descriptor(kind),
            "captured observation",
        )


def _maximum_for_kind(kind: str, maximum: int | None) -> int:
    spec = ARTIFACT_KINDS.get(kind) if isinstance(kind, str) else None
    if spec is None:
        raise PhysicalObservationError(
            "invalid_observation_kind",
            "observation kind is not part of the source-pinned artifact contract",
        )
    selected = spec.maximum_bytes if maximum is None else maximum
    if (
        type(selected) is not int
        or selected < 1
        or selected > spec.maximum_bytes
    ):
        raise PhysicalObservationError(
            "invalid_observation_bound",
            "observation byte bound exceeds its source-pinned artifact kind",
        )
    return selected


def _subject(value: object, label: str) -> str:
    if not isinstance(value, str) or _SUBJECT_RE.fullmatch(value) is None:
        raise PhysicalObservationError(
            "invalid_observation_subject",
            f"{label} is not a bounded canonical subject",
        )
    return value


def _validate_observation_path(path: str, label: str) -> None:
    parts = PurePosixPath(path).parts
    if (
        len(parts) != 4
        or parts[0] != "raw"
        or parts[1] not in OBSERVATION_HARNESSES
        or parts[2] != "observations"
    ):
        raise PhysicalObservationError(
            "invalid_observation_path",
            f"{label} is outside the fixed observation namespaces",
        )


def _parse_artifact(
    subject: object,
    descriptor: object,
    label: str,
) -> ObservationArtifact:
    normalized_subject = _subject(subject, f"{label}.subject")
    try:
        parsed = parse_descriptor(
            descriptor,
            expected_kinds=ARTIFACT_KINDS,
            label=f"{label}.descriptor",
        )
    except RawArtifactError as error:
        raise PhysicalObservationError(
            "invalid_observation_descriptor",
            f"{label} has an invalid typed artifact descriptor",
        ) from error
    _validate_observation_path(parsed.path, f"{label}.descriptor.path")
    return ObservationArtifact(normalized_subject, parsed)


def _validate_declared_artifact(subject: str, kind: str, relative: str) -> None:
    _parse_artifact(
        subject,
        {
            "kind": kind,
            "path": relative,
            "size": 1,
            "sha256": "0" * 64,
        },
        "declared observation",
    )


def _require_unique_sorted(
    observations: tuple[ObservationArtifact, ...],
) -> tuple[ObservationArtifact, ...]:
    if not 1 <= len(observations) <= MAX_OBSERVATIONS:
        raise PhysicalObservationError(
            "invalid_observation_count",
            f"observation manifest must contain 1..{MAX_OBSERVATIONS} entries",
        )
    expected = tuple(
        sorted(
            observations,
            key=lambda observation: (
                observation.subject,
                observation.descriptor.path,
            ),
        )
    )
    if observations != expected:
        raise PhysicalObservationError(
            "noncanonical_observation_order",
            "observation manifest entries are not in canonical subject/path order",
        )
    subjects = [observation.subject for observation in observations]
    paths = [observation.descriptor.path for observation in observations]
    digests = [observation.descriptor.sha256 for observation in observations]
    if (
        len(set(subjects)) != len(subjects)
        or len(set(paths)) != len(paths)
        or len(set(digests)) != len(digests)
    ):
        raise PhysicalObservationError(
            "duplicate_observation_binding",
            "observation subjects, paths, and digests must each be unique",
        )
    return observations


def _mapping_observations(
    value: dict[str, object],
) -> tuple[ObservationArtifact, ...]:
    if not isinstance(value, dict):
        raise PhysicalObservationError(
            "invalid_observation_mapping",
            "observation descriptors must be a subject-to-descriptor mapping",
        )
    if not 1 <= len(value) <= MAX_OBSERVATIONS:
        raise PhysicalObservationError(
            "invalid_observation_count",
            f"observation manifest must contain 1..{MAX_OBSERVATIONS} entries",
        )
    parsed = tuple(
        sorted(
            (
                _parse_artifact(subject, descriptor, f"observations[{index}]")
                for index, (subject, descriptor) in enumerate(value.items())
            ),
            key=lambda observation: (
                observation.subject,
                observation.descriptor.path,
            ),
        )
    )
    return _require_unique_sorted(parsed)


def _manifest_document(
    observations: tuple[ObservationArtifact, ...],
) -> dict[str, object]:
    return {
        "schema_version": OBSERVATION_MANIFEST_SCHEMA_VERSION,
        "document": OBSERVATION_MANIFEST_DOCUMENT,
        "observation_count": len(observations),
        "observations": [observation.as_entry() for observation in observations],
    }


def _parse_manifest(value: object) -> tuple[ObservationArtifact, ...]:
    try:
        raw = exact_object(value, _MANIFEST_FIELDS, "observation manifest")
    except RawArtifactError as error:
        raise PhysicalObservationError(
            "invalid_observation_manifest",
            "observation manifest has an unexpected field set",
        ) from error
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != OBSERVATION_MANIFEST_SCHEMA_VERSION
        or raw["document"] != OBSERVATION_MANIFEST_DOCUMENT
    ):
        raise PhysicalObservationError(
            "invalid_observation_manifest",
            "observation manifest schema or document identifier is unsupported",
        )
    values = raw["observations"]
    if not isinstance(values, list):
        raise PhysicalObservationError(
            "invalid_observation_manifest",
            "observation manifest observations must be an array",
        )
    if not 1 <= len(values) <= MAX_OBSERVATIONS:
        raise PhysicalObservationError(
            "invalid_observation_count",
            f"observation manifest must contain 1..{MAX_OBSERVATIONS} entries",
        )
    parsed: list[ObservationArtifact] = []
    for index, value_entry in enumerate(values):
        try:
            entry = exact_object(
                value_entry,
                _ENTRY_FIELDS,
                f"observation manifest.observations[{index}]",
            )
        except RawArtifactError as error:
            raise PhysicalObservationError(
                "invalid_observation_manifest",
                "observation manifest entry has an unexpected field set",
            ) from error
        parsed.append(
            _parse_artifact(
                entry["subject"],
                entry["descriptor"],
                f"observation manifest.observations[{index}]",
            )
        )
    observations = _require_unique_sorted(tuple(parsed))
    if type(raw["observation_count"]) is not int or raw[
        "observation_count"
    ] != len(observations):
        raise PhysicalObservationError(
            "invalid_observation_count",
            "observation manifest count differs from its exact entry set",
        )
    return observations


def _verify_observation_files(
    archive: SecureArchive,
    observations: tuple[ObservationArtifact, ...],
) -> None:
    expected_names = {harness: set() for harness in OBSERVATION_HARNESSES}
    try:
        for observation in observations:
            descriptor = observation.descriptor
            observed = archive.describe_file(
                descriptor.path,
                maximum=descriptor.size,
            )
            if observed != ArchivedFile(
                descriptor.path,
                descriptor.size,
                descriptor.sha256,
            ):
                raise PhysicalObservationError(
                    "observation_bytes_drifted",
                    f"observation bytes drifted for subject {observation.subject!r}",
                )
            parts = PurePosixPath(descriptor.path).parts
            expected_names[parts[1]].add(parts[3])

        for harness in OBSERVATION_HARNESSES:
            directory = f"raw/{harness}/observations"
            expected = tuple(sorted(expected_names[harness]))
            observed_names = archive.list_names(directory)
            if observed_names != expected:
                raise PhysicalObservationError(
                    "observation_namespace_drifted",
                    f"{harness} observation namespace differs from the manifest",
                )
    except PhysicalObservationError:
        raise
    except PhysicalCaptureArchiveError as error:
        raise PhysicalObservationError(
            "observation_archive_unreadable",
            "manifest-bound observation bytes cannot be securely reopened",
        ) from error


def _canonical_manifest_bytes(
    observations: tuple[ObservationArtifact, ...],
) -> bytes:
    try:
        data = canonical_json(_manifest_document(observations)) + b"\n"
    except RawArtifactError as error:
        raise PhysicalObservationError(
            "observation_manifest_encoding_failed",
            "observation manifest cannot be canonically encoded",
        ) from error
    if len(data) > MAX_MANIFEST_BYTES:
        raise PhysicalObservationError(
            "observation_manifest_too_large",
            "observation manifest exceeds its fixed byte bound",
        )
    return data


def load_observation_manifest(
    archive: SecureArchive,
    *,
    expected_root_sha256: str | None = None,
) -> ObservationManifest:
    """Reopen the canonical manifest and every exact observation it binds."""

    if not isinstance(archive, SecureArchive):
        raise PhysicalObservationError(
            "invalid_archive",
            "observation manifest requires a secure archive",
        )
    try:
        data = archive.read_bytes(
            OBSERVATION_MANIFEST_RELATIVE,
            maximum=MAX_MANIFEST_BYTES,
        )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalObservationError(
            "observation_manifest_unreadable",
            "observation manifest cannot be securely reopened",
        ) from error
    root = hashlib.sha256(data).hexdigest()
    if expected_root_sha256 is not None and root != expected_root_sha256:
        raise PhysicalObservationError(
            "observation_manifest_root_mismatch",
            "observation manifest digest differs from the RAW_COMPLETED binding",
        )
    try:
        value = load_json_bytes(data, "observation manifest")
    except RawArtifactError as error:
        raise PhysicalObservationError(
            "invalid_observation_manifest",
            "observation manifest is not strict JSON",
        ) from error
    observations = _parse_manifest(value)
    if _canonical_manifest_bytes(observations) != data:
        raise PhysicalObservationError(
            "noncanonical_observation_manifest",
            "observation manifest bytes are not canonical",
        )
    _verify_observation_files(archive, observations)
    return ObservationManifest(
        record=ArchivedFile(
            OBSERVATION_MANIFEST_RELATIVE,
            len(data),
            root,
        ),
        observations=observations,
    )


def publish_observation_manifest(
    archive: SecureArchive,
    observations: dict[str, object],
) -> ObservationManifest:
    """Publish once, then reopen the exact pre-nonce observation root."""

    if not isinstance(archive, SecureArchive):
        raise PhysicalObservationError(
            "invalid_archive",
            "observation manifest requires a secure archive",
        )
    normalized = _mapping_observations(observations)
    try:
        for directory in OBSERVATION_DIRECTORIES:
            archive.ensure_directory(directory)
    except PhysicalCaptureArchiveError as error:
        raise PhysicalObservationError(
            "observation_namespace_unavailable",
            "fixed observation namespaces cannot be securely initialized",
        ) from error
    _verify_observation_files(archive, normalized)
    data = _canonical_manifest_bytes(normalized)
    try:
        archived = archive.write_or_reopen_exact(
            OBSERVATION_MANIFEST_RELATIVE,
            data,
            maximum=MAX_MANIFEST_BYTES,
        )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalObservationError(
            "observation_manifest_archive_failed",
            "observation manifest could not be durably published or reopened",
        ) from error
    try:
        if archive.pending_files("raw"):
            raise PhysicalObservationError(
                "observation_manifest_pending",
                "observation manifest publication left pending raw bytes",
            )
    except PhysicalCaptureArchiveError as error:
        raise PhysicalObservationError(
            "observation_manifest_unreadable",
            "observation manifest namespace cannot be inspected",
        ) from error
    reopened = load_observation_manifest(
        archive,
        expected_root_sha256=archived.sha256,
    )
    if reopened.record != archived or reopened.observations != normalized:
        raise PhysicalObservationError(
            "observation_manifest_drifted",
            "reopened observation manifest differs from its published bytes",
        )
    return reopened


__all__ = [
    "MAX_MANIFEST_BYTES",
    "OBSERVATION_DIRECTORIES",
    "OBSERVATION_MANIFEST_RELATIVE",
    "ObservationArtifact",
    "ObservationCapture",
    "ObservationCommand",
    "ObservationManifest",
    "PhysicalObservationError",
    "load_observation_manifest",
    "publish_observation_manifest",
]
