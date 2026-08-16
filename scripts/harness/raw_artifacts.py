#!/usr/bin/env python3
"""Shared proof-to-byte primitives for physical release evidence.

This module is deliberately the only place that resolves evidence paths, opens
raw artifacts, enforces byte/count limits, parses collector trust policy, and
verifies collector receipts. Harness-specific modules consume already opened
bytes and add only their domain checks.

The filesystem checks reduce accidental drift and local path races. They do not
make an operator-controlled machine trustworthy. A physical release grant also
requires a receipt signed by the source-pinned external collector key.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Iterable

if __package__:
    from ..release_build_identity import BuildIdentityError, canonical_build_version
else:  # pragma: no cover - direct-script import path
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from release_build_identity import BuildIdentityError, canonical_build_version


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
GCP_KMS_KEY_VERSION_RE = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/"
    r"locations/[a-z0-9-]{1,63}/"
    r"keyRings/[A-Za-z0-9_-]{1,63}/"
    r"cryptoKeys/[A-Za-z0-9_-]{1,63}/"
    r"cryptoKeyVersions/[1-9][0-9]*$"
)

COLLECTOR_SIGNATURE_ALGORITHM = "PS256"
KMS_SIGNATURE_ALGORITHM = "RSA_SIGN_PSS_3072_SHA256"
KMS_PROTECTION_LEVEL = "HSM"
KMS_ATTESTATION_FORMATS = frozenset(
    {"CAVIUM_V1_COMPRESSED", "CAVIUM_V2_COMPRESSED"}
)
RSA_MODULUS_BITS = 3072
RSA_PUBLIC_EXPONENT = 65537
PS256_SIGNATURE_BYTES = 384
PS256_HASH_BYTES = 32
PS256_SALT_BYTES = 32
PS256_EM_BITS = 3071

# One receipt contains 4 reports plus 265 required raw subjects; the two
# optional Packet restore observations raise the only valid maximum to 271.
# One production aggregate reader holds two maximal runs plus the aggregate
# root descriptor itself: 1 + (2 * 271) = 543.  Keep the receipt and reader
# domains distinct so neither a 272nd receipt descriptor nor a valid two-run
# archive is accidentally admitted/rejected by the other's bound.
REQUIRED_RECEIPT_ARTIFACT_COUNT = 269
MAX_RECEIPT_ARTIFACT_COUNT = 271
MAX_ARTIFACT_COUNT = 543
MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_RELATIVE_PATH_BYTES = 512
MAX_JSON_DEPTH = 32
MAX_JSON_INTEGER_DIGITS = 19
MAX_JSON_FLOAT_CHARS = 128
MAX_TRUST_POLICY_BYTES = 64 * 1024

REPORT_MAX_BYTES = 1 * 1024 * 1024

EVIDENCE_PROFILE = {
    "aggregate_schema_version": 5,
    "aggregator_version": "physical-evidence-aggregator-v5-single-machine",
    "boot_environment_scheme": "cfw-boot-environment-v1",
    "machine_identity_scheme": "cfw-physical-machine-identity-v1",
    "machine_topology": "one-machine-two-clean-os-v1",
    "required_runs": [
        {
            "macos_build": "25G72",
            "macos_version": "26.6",
            "os": "current-macos",
        },
        {
            "macos_build": "24G824",
            "macos_version": "15.7.8",
            "os": "macos15",
        },
    ],
    "schema_version": 1,
    "soak_hours_per_run": 3,
}
EVIDENCE_PROFILE_FIELDS = {
    "schema_version",
    "aggregate_schema_version",
    "aggregator_version",
    "boot_environment_scheme",
    "machine_identity_scheme",
    "machine_topology",
    "required_runs",
    "soak_hours_per_run",
}


@dataclass(frozen=True)
class ArtifactKindSpec:
    """The one accepted extension and byte bound for an artifact kind."""

    suffix: str
    maximum_bytes: int


ARTIFACT_KINDS: dict[str, ArtifactKindSpec] = {
    "physical-aggregate": ArtifactKindSpec(".json", 8 * 1024 * 1024),
    "packet-report": ArtifactKindSpec(".json", REPORT_MAX_BYTES),
    "lifecycle-report": ArtifactKindSpec(".json", REPORT_MAX_BYTES),
    "performance-report": ArtifactKindSpec(".json", REPORT_MAX_BYTES),
    "adversarial-report": ArtifactKindSpec(".json", REPORT_MAX_BYTES),
    "packet-pcap": ArtifactKindSpec(".pcap", 32 * 1024 * 1024),
    "packet-pcapng": ArtifactKindSpec(".pcapng", 32 * 1024 * 1024),
    "packet-product-state-observation": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "packet-capture-provenance": ArtifactKindSpec(".json", 256 * 1024),
    "packet-send-attempt": ArtifactKindSpec(".json", 256 * 1024),
    "lifecycle-observation": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "lifecycle-event": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "renderer-ready-trace": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "network-extension-trace": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "sleep-wake-trace": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "wkwebview-metadata": ArtifactKindSpec(".json", 256 * 1024),
    "wkwebview-rgba": ArtifactKindSpec(".rgba", 16 * 1024 * 1024),
    "performance-sample-ledger": ArtifactKindSpec(".json", 64 * 1024 * 1024),
    "performance-shaping-transaction": ArtifactKindSpec(".json", 16 * 1024 * 1024),
    "adversarial-case-observation": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "adversarial-secret-coverage": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "adversarial-signature-observation": ArtifactKindSpec(".json", 256 * 1024),
    "adversarial-transcript": ArtifactKindSpec(".json", 1 * 1024 * 1024),
}

DESCRIPTOR_FIELDS = {"kind", "path", "size", "sha256"}
PROOF_SCHEMA_VERSION = 3
PROOF_FIELDS = {"schema_version", "run_id", "run_nonce", "candidate", "collector"}
CANDIDATE_FIELDS = {
    "version",
    "build_number",
    "app_manifest_sha256",
    "signed_app_tree_sha256",
    "artifact_hash_manifest_sha256",
}
COLLECTOR_BINDING_FIELDS = {
    "version",
    "source_sha256",
    "executable_sha256",
    "algorithm",
    "key_version",
}

RELEASE_TRUST_POLICY_PATH = Path(__file__).with_name(
    "physical_collector_trust_policy.json"
)
# Updated only together with the canonical policy file after the external HSM
# attestation, collector source closure, and immutable image digest are reviewed.
RELEASE_TRUST_POLICY_SHA256 = "907e7f11c9510eb541537a077290c43cf2121b5047d777339a4c1f3debf9bec3"


class RawArtifactError(ValueError):
    """A raw artifact, proof binding, or collector receipt is invalid."""


class CollectorTrustNotConfiguredError(RawArtifactError):
    """The source-pinned production policy intentionally has no trust key yet."""


@dataclass(frozen=True)
class ArtifactDescriptor:
    """A strictly parsed relative artifact descriptor."""

    kind: str
    path: str
    size: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ArtifactSnapshot:
    """The accepted descriptor and inode metadata retained for a final rescan."""

    descriptor: ArtifactDescriptor
    identity: tuple[int, ...]


@dataclass(frozen=True)
class CollectorTrustPolicy:
    """One externally provisioned and source-pinned collector trust root."""

    policy_sha256: str
    key_version: str
    algorithm: str
    kms_algorithm: str
    protection_level: str
    attestation_format: str
    public_key_sha256: str
    attestation_sha256: str
    modulus: int
    exponent: int
    collector_version: str
    collector_source_sha256: str
    collector_executable_sha256: str
    evidence_profile_sha256: str
    aggregate_schema_version: int
    aggregator_version: str
    boot_environment_scheme: str
    machine_identity_scheme: str
    machine_topology: str
    release_source_pinned: bool


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    """Require an object with exactly ``fields`` and no silent narrowing."""

    if not isinstance(value, dict):
        raise RawArtifactError(f"{label} must be a JSON object")
    actual = set(value)
    missing = fields - actual
    unknown = actual - fields
    if missing:
        raise RawArtifactError(f"{label} is missing required fields: {sorted(missing)}")
    if unknown:
        raise RawArtifactError(f"{label} has unknown fields: {sorted(unknown)}")
    return value


def _require_exact_json_value(value: Any, expected: Any, label: str) -> None:
    """Require the exact JSON shape, scalar type, and value of a pinned contract."""

    if type(value) is not type(expected):
        raise RawArtifactError(f"{label} has a non-canonical JSON type")
    if isinstance(expected, dict):
        raw = exact_object(value, set(expected), label)
        for key in sorted(expected):
            _require_exact_json_value(raw[key], expected[key], f"{label}.{key}")
        return
    if isinstance(expected, list):
        if len(value) != len(expected):
            raise RawArtifactError(f"{label} has a non-canonical JSON array length")
        for index, (item, expected_item) in enumerate(zip(value, expected)):
            _require_exact_json_value(item, expected_item, f"{label}[{index}]")
        return
    if value != expected:
        raise RawArtifactError(f"{label} differs from the source-pinned value")


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise RawArtifactError(f"{label} is not a lowercase SHA-256")
    return value


def require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise RawArtifactError(f"{label} is not a canonical identifier")
    return value


def require_kms_key_version(value: Any, label: str) -> str:
    if not isinstance(value, str) or not GCP_KMS_KEY_VERSION_RE.fullmatch(value):
        raise RawArtifactError(f"{label} is not a complete GCP KMS key-version resource")
    return value


def utf8_size(value: str, label: str) -> int:
    """Return the UTF-8 byte length or reject an unencodable Unicode scalar."""

    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise RawArtifactError(f"{label} is not valid Unicode text") from error


def canonical_json(value: Any) -> bytes:
    """Encode the exact canonical JSON bytes used by collector signatures."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise RawArtifactError("value cannot be encoded as canonical JSON") from error


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RawArtifactError(f"JSON object has a duplicate field: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise RawArtifactError(f"JSON contains a non-finite number: {value}")


def _parse_json_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise RawArtifactError(
            f"JSON integer exceeds {MAX_JSON_INTEGER_DIGITS} decimal digits"
        )
    return int(value)


def _parse_json_float(value: str) -> float:
    if len(value) > MAX_JSON_FLOAT_CHARS:
        raise RawArtifactError(
            f"JSON floating-point token exceeds {MAX_JSON_FLOAT_CHARS} characters"
        )
    parsed = float(value)
    if not math.isfinite(parsed):
        raise RawArtifactError("JSON floating-point value is not finite")
    return parsed


def _json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise RawArtifactError(f"JSON nesting exceeds {MAX_JSON_DEPTH}")
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise RawArtifactError("JSON object key is not a string")
            utf8_size(key, "JSON object key")
            _json_depth(nested, depth + 1)
    elif isinstance(value, list):
        for nested in value:
            _json_depth(nested, depth + 1)
    elif isinstance(value, str):
        utf8_size(value, "JSON string")
    return depth


def load_json_bytes(data: bytes, label: str) -> Any:
    """Parse strict UTF-8 JSON, rejecting duplicates and non-finite numbers."""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RawArtifactError(f"{label} is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_parse_json_float,
            parse_int=_parse_json_integer,
            parse_constant=_reject_constant,
        )
    except RawArtifactError:
        raise
    except json.JSONDecodeError as error:
        raise RawArtifactError(f"{label} is not valid JSON") from error
    except RecursionError as error:
        raise RawArtifactError(f"{label} JSON nesting is excessive") from error
    _json_depth(value)
    return value


def parse_proof_binding(value: Any, label: str = "proof") -> dict[str, Any]:
    """Parse the common candidate/run/collector binding carried by every report."""

    proof = exact_object(value, PROOF_FIELDS, label)
    if type(proof["schema_version"]) is not int or (
        proof["schema_version"] != PROOF_SCHEMA_VERSION
    ):
        raise RawArtifactError(
            f"{label}.schema_version must be {PROOF_SCHEMA_VERSION}"
        )
    run_id = require_identifier(proof["run_id"], f"{label}.run_id")
    run_nonce = require_sha256(proof["run_nonce"], f"{label}.run_nonce")
    candidate = exact_object(proof["candidate"], CANDIDATE_FIELDS, f"{label}.candidate")
    version = candidate["version"]
    build_number = candidate["build_number"]
    if (
        not isinstance(version, str)
        or not version
        or utf8_size(version, f"{label}.candidate.version") > 32
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in version)
    ):
        raise RawArtifactError(f"{label}.candidate.version must be bounded printable text")
    try:
        canonical_build_version(build_number, f"{label}.candidate.build_number")
    except BuildIdentityError as error:
        raise RawArtifactError(str(error)) from error
    parsed_candidate = {
        "version": version,
        "build_number": build_number,
        "app_manifest_sha256": require_sha256(
            candidate["app_manifest_sha256"], f"{label}.candidate.app_manifest_sha256"
        ),
        "signed_app_tree_sha256": require_sha256(
            candidate["signed_app_tree_sha256"],
            f"{label}.candidate.signed_app_tree_sha256",
        ),
        "artifact_hash_manifest_sha256": require_sha256(
            candidate["artifact_hash_manifest_sha256"],
            f"{label}.candidate.artifact_hash_manifest_sha256",
        ),
    }
    collector = exact_object(
        proof["collector"], COLLECTOR_BINDING_FIELDS, f"{label}.collector"
    )
    parsed_collector = {
        "version": require_identifier(collector["version"], f"{label}.collector.version"),
        "source_sha256": require_sha256(
            collector["source_sha256"], f"{label}.collector.source_sha256"
        ),
        "executable_sha256": require_sha256(
            collector["executable_sha256"], f"{label}.collector.executable_sha256"
        ),
        "algorithm": collector["algorithm"],
        "key_version": require_kms_key_version(
            collector["key_version"], f"{label}.collector.key_version"
        ),
    }
    if parsed_collector["algorithm"] != COLLECTOR_SIGNATURE_ALGORITHM:
        raise RawArtifactError(
            f"{label}.collector.algorithm must be {COLLECTOR_SIGNATURE_ALGORITHM}"
        )
    return {
        "schema_version": PROOF_SCHEMA_VERSION,
        "run_id": run_id,
        "run_nonce": run_nonce,
        "candidate": parsed_candidate,
        "collector": parsed_collector,
    }


def parse_descriptor(
    value: Any,
    *,
    expected_kinds: Iterable[str],
    label: str,
) -> ArtifactDescriptor:
    raw = exact_object(value, DESCRIPTOR_FIELDS, label)
    expected = frozenset(expected_kinds)
    kind = raw["kind"]
    if not isinstance(kind, str) or kind not in expected or kind not in ARTIFACT_KINDS:
        raise RawArtifactError(f"{label}.kind is not an allowed artifact kind")
    path = raw["path"]
    if not isinstance(path, str) or not path:
        raise RawArtifactError(f"{label}.path must be a non-empty relative path")
    if "\\" in path or utf8_size(path, f"{label}.path") > MAX_RELATIVE_PATH_BYTES:
        raise RawArtifactError(f"{label}.path is not a bounded POSIX relative path")
    relative = PurePosixPath(path)
    if relative.is_absolute() or str(relative) != path:
        raise RawArtifactError(f"{label}.path must be canonical and relative")
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise RawArtifactError(f"{label}.path contains traversal or an empty component")
    if any(not PATH_COMPONENT_RE.fullmatch(part) for part in parts):
        raise RawArtifactError(f"{label}.path contains a non-canonical component")
    spec = ARTIFACT_KINDS[kind]
    if not path.endswith(spec.suffix):
        raise RawArtifactError(
            f"{label}.path extension does not match artifact kind {kind!r}"
        )
    size = raw["size"]
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise RawArtifactError(f"{label}.size must be a positive integer")
    if size > spec.maximum_bytes:
        raise RawArtifactError(f"{label}.size exceeds the {kind!r} byte bound")
    digest = require_sha256(raw["sha256"], f"{label}.sha256")
    return ArtifactDescriptor(kind=kind, path=path, size=size, sha256=digest)


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class ArtifactReader:
    """Open and hash descriptors beneath one fixed evidence-root directory fd."""

    def __init__(self, evidence_root: Path) -> None:
        root = evidence_root.absolute()
        if not root.is_absolute():
            raise RawArtifactError("evidence root must be absolute")
        self.root = root
        self._root_fd: int | None = None
        self._root_identity: tuple[int, int] | None = None
        self._seen_paths: set[str] = set()
        self._seen_digests: set[str] = set()
        self._artifact_count = 0
        self._total_bytes = 0
        self._snapshots: list[ArtifactSnapshot] = []

    def __enter__(self) -> ArtifactReader:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.root, flags)
        except OSError as error:
            raise RawArtifactError(
                "evidence root is not an openable non-symlink directory"
            ) from error
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(fd)
            raise RawArtifactError("evidence root is not a directory")
        self._root_fd = fd
        self._root_identity = (metadata.st_dev, metadata.st_ino)
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    @property
    def artifact_count(self) -> int:
        return self._artifact_count

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    def _require_open(self) -> int:
        if self._root_fd is None:
            raise RawArtifactError("artifact reader is not open")
        return self._root_fd

    def _check_root_path(self) -> None:
        root_fd = self._require_open()
        try:
            metadata = os.stat(self.root, follow_symlinks=False)
        except OSError as error:
            raise RawArtifactError("evidence root path drifted during verification") from error
        if not stat.S_ISDIR(metadata.st_mode) or (
            metadata.st_dev,
            metadata.st_ino,
        ) != self._root_identity:
            raise RawArtifactError("evidence root path drifted during verification")
        if (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino) != self._root_identity:
            raise RawArtifactError("evidence root descriptor drifted during verification")

    def _open_relative(self, relative_path: str) -> int:
        root_fd = self._require_open()
        parts = PurePosixPath(relative_path).parts
        current_fd = os.dup(root_fd)
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        file_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            for component in parts[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            return os.open(parts[-1], file_flags, dir_fd=current_fd)
        except OSError as error:
            raise RawArtifactError(
                f"artifact path cannot be opened without following links: {relative_path!r}"
            ) from error
        finally:
            os.close(current_fd)

    @staticmethod
    def _read_fd(fd: int, maximum: int) -> bytes:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            try:
                chunk = os.read(fd, min(1024 * 1024, remaining))
            except BlockingIOError as error:
                raise RawArtifactError("artifact read would block") from error
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _revalidate_snapshot(self, snapshot: ArtifactSnapshot, label: str) -> None:
        """Reopen, reread, and rehash one previously accepted path."""

        descriptor = snapshot.descriptor
        self._check_root_path()
        fd = self._open_relative(descriptor.path)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise RawArtifactError(f"{label} is no longer a regular single-link file")
            if _stat_identity(before) != snapshot.identity:
                raise RawArtifactError(f"{label} identity drifted after its initial verification")
            data = self._read_fd(fd, descriptor.size)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        if _stat_identity(before) != _stat_identity(after):
            raise RawArtifactError(f"{label} changed during its final verification")
        if len(data) != descriptor.size:
            raise RawArtifactError(f"{label} byte count drifted after its initial verification")
        digest = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(digest, descriptor.sha256):
            raise RawArtifactError(f"{label} bytes drifted after its initial verification")
        check_fd = self._open_relative(descriptor.path)
        try:
            reopened = os.fstat(check_fd)
        finally:
            os.close(check_fd)
        if _stat_identity(reopened) != snapshot.identity:
            raise RawArtifactError(f"{label} path drifted during its final verification")
        self._check_root_path()

    def verify_all_unchanged(self, *, final_path: str | None = None) -> None:
        """Final-rescan every accepted object, with the aggregate checked last."""

        if not self._snapshots:
            raise RawArtifactError("artifact reader has no accepted objects to revalidate")
        final: ArtifactSnapshot | None = None
        ordered: list[ArtifactSnapshot] = []
        for snapshot in self._snapshots:
            if final_path is not None and snapshot.descriptor.path == final_path:
                if final is not None:
                    raise RawArtifactError("final artifact path was accepted more than once")
                final = snapshot
            else:
                ordered.append(snapshot)
        if final_path is not None and final is None:
            raise RawArtifactError("final artifact path was not accepted by this reader")
        if final is not None:
            ordered.append(final)
        for index, snapshot in enumerate(ordered):
            self._revalidate_snapshot(
                snapshot,
                f"final artifact rescan[{index}] {snapshot.descriptor.path!r}",
            )

    def read(
        self,
        value: Any,
        *,
        expected_kinds: Iterable[str],
        label: str,
    ) -> tuple[ArtifactDescriptor, bytes]:
        descriptor = parse_descriptor(value, expected_kinds=expected_kinds, label=label)
        if descriptor.path in self._seen_paths:
            raise RawArtifactError(f"{label} reuses artifact path {descriptor.path!r}")
        if descriptor.sha256 in self._seen_digests:
            raise RawArtifactError(f"{label} reuses artifact bytes already bound")
        if self._artifact_count + 1 > MAX_ARTIFACT_COUNT:
            raise RawArtifactError("artifact count exceeds the global bound")
        if self._total_bytes + descriptor.size > MAX_TOTAL_ARTIFACT_BYTES:
            raise RawArtifactError("artifact bytes exceed the global bound")

        self._check_root_path()
        fd = self._open_relative(descriptor.path)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise RawArtifactError(f"{label} is not a regular file")
            if before.st_nlink != 1:
                raise RawArtifactError(f"{label} is a hard-linked file")
            if before.st_size != descriptor.size:
                raise RawArtifactError(f"{label}.size does not match the reopened artifact")
            data = self._read_fd(fd, descriptor.size)
            after = os.fstat(fd)
        finally:
            os.close(fd)

        if _stat_identity(before) != _stat_identity(after):
            raise RawArtifactError(f"{label} changed while it was being read")
        if len(data) != descriptor.size:
            raise RawArtifactError(f"{label} byte count drifted while it was being read")
        computed = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(computed, descriptor.sha256):
            raise RawArtifactError(f"{label}.sha256 does not match the reopened artifact")

        # Reopen the declared path and compare inode/metadata after hashing. The
        # bytes came from the held fd; this second lookup additionally rejects a
        # path swap that happened during the read.
        check_fd = self._open_relative(descriptor.path)
        try:
            reopened = os.fstat(check_fd)
        finally:
            os.close(check_fd)
        if _stat_identity(before) != _stat_identity(reopened):
            raise RawArtifactError(f"{label} path drifted while it was being verified")
        self._check_root_path()

        self._seen_paths.add(descriptor.path)
        self._seen_digests.add(descriptor.sha256)
        self._artifact_count += 1
        self._total_bytes += descriptor.size
        self._snapshots.append(
            ArtifactSnapshot(descriptor=descriptor, identity=_stat_identity(before))
        )
        return descriptor, data

    def read_json(
        self,
        value: Any,
        *,
        expected_kind: str,
        label: str,
    ) -> tuple[ArtifactDescriptor, Any]:
        descriptor, data = self.read(
            value, expected_kinds={expected_kind}, label=label
        )
        return descriptor, load_json_bytes(data, label)


def _base64url_decode(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value or not BASE64URL_RE.fullmatch(value):
        raise RawArtifactError(f"{label} is not unpadded base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, base64.binascii.Error) as error:
        raise RawArtifactError(f"{label} is not valid base64url") from error
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(canonical, value):
        raise RawArtifactError(f"{label} is not canonical unpadded base64url")
    return decoded


def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    """Return MGF1(SHA-256) bytes for the fixed PS256 verification contract."""

    if not isinstance(seed, bytes) or not isinstance(length, int) or length < 0:
        raise RawArtifactError("PS256 MGF1 input is invalid")
    if length > (2**32) * PS256_HASH_BYTES:
        raise RawArtifactError("PS256 MGF1 output length is excessive")
    blocks = (
        hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        for counter in range((length + PS256_HASH_BYTES - 1) // PS256_HASH_BYTES)
    )
    return b"".join(blocks)[:length]


def verify_ps256(
    message: bytes,
    signature_base64url: Any,
    *,
    modulus: int,
    exponent: int,
) -> None:
    """Verify the sole production signature: PS256 with an RSA-3072 key."""

    if not isinstance(message, bytes):
        raise RawArtifactError("collector receipt message must be bytes")
    if (
        not isinstance(modulus, int)
        or isinstance(modulus, bool)
        or modulus <= 0
        or modulus % 2 == 0
        or modulus.bit_length() != RSA_MODULUS_BITS
    ):
        raise RawArtifactError("collector RSA modulus must be exactly 3072 bits")
    if (
        not isinstance(exponent, int)
        or isinstance(exponent, bool)
        or exponent != RSA_PUBLIC_EXPONENT
    ):
        raise RawArtifactError("collector RSA public exponent must be 65537")
    signature = _base64url_decode(signature_base64url, "collector signature")
    if len(signature) != PS256_SIGNATURE_BYTES:
        raise RawArtifactError("collector PS256 signature must be exactly 384 bytes")
    encoded_integer = int.from_bytes(signature, "big")
    if encoded_integer >= modulus:
        raise RawArtifactError("collector signature representative is outside the RSA modulus")
    encoded = pow(encoded_integer, exponent, modulus).to_bytes(
        PS256_SIGNATURE_BYTES, "big"
    )
    if encoded[-1] != 0xBC:
        raise RawArtifactError("collector PS256 trailer field is invalid")

    masked_db = encoded[: -(PS256_HASH_BYTES + 1)]
    encoded_hash = encoded[-(PS256_HASH_BYTES + 1) : -1]
    if len(masked_db) != 351:
        raise RawArtifactError("collector PS256 encoded DB length is invalid")
    unused_bits = 8 * PS256_SIGNATURE_BYTES - PS256_EM_BITS
    if unused_bits != 1 or masked_db[0] & 0x80:
        raise RawArtifactError("collector PS256 unused high bit is nonzero")

    mask = _mgf1_sha256(encoded_hash, len(masked_db))
    decoded_db = bytearray(left ^ right for left, right in zip(masked_db, mask, strict=True))
    decoded_db[0] &= 0x7F
    padding_length = len(decoded_db) - PS256_SALT_BYTES - 1
    if padding_length != 318:
        raise RawArtifactError("collector PS256 salt contract is inconsistent")
    if not hmac.compare_digest(bytes(decoded_db[:padding_length]), b"\x00" * padding_length):
        raise RawArtifactError("collector PS256 DB padding is invalid")
    if decoded_db[padding_length] != 0x01:
        raise RawArtifactError("collector PS256 DB delimiter is invalid")
    salt = bytes(decoded_db[-PS256_SALT_BYTES:])
    expected_hash = hashlib.sha256(
        b"\x00" * 8 + hashlib.sha256(message).digest() + salt
    ).digest()
    if not hmac.compare_digest(encoded_hash, expected_hash):
        raise RawArtifactError("collector PS256 receipt signature is invalid")


def _der_length(length: int) -> bytes:
    if length < 0:
        raise RawArtifactError("DER length is negative")
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _der_length(len(value)) + value


def _der_integer(value: int) -> bytes:
    if value <= 0:
        raise RawArtifactError("RSA public integer must be positive")
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _der_tlv(0x02, encoded)


def rsa_spki_sha256(modulus: int, exponent: int) -> str:
    """Hash the canonical DER SubjectPublicKeyInfo for the RSA public key."""

    rsa_public_key = _der_tlv(0x30, _der_integer(modulus) + _der_integer(exponent))
    rsa_encryption_algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    subject_public_key = _der_tlv(0x03, b"\x00" + rsa_public_key)
    return hashlib.sha256(
        _der_tlv(0x30, rsa_encryption_algorithm + subject_public_key)
    ).hexdigest()


def parse_trust_policy_bytes(
    data: bytes,
    *,
    expected_sha256: str,
    release_source_pinned: bool = False,
) -> CollectorTrustPolicy:
    """Parse a canonical trust policy whose exact bytes are already source-pinned."""

    require_sha256(expected_sha256, "expected trust policy SHA-256")
    if not data or len(data) > MAX_TRUST_POLICY_BYTES:
        raise RawArtifactError("collector trust policy size is outside the accepted range")
    actual_digest = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_sha256):
        raise RawArtifactError("collector trust policy bytes do not match the source-pinned digest")
    value = load_json_bytes(data, "collector trust policy")
    if not isinstance(value, dict):
        raise RawArtifactError("collector trust policy must be a JSON object")
    canonical = canonical_json(value) + b"\n"
    if data != canonical:
        raise RawArtifactError("collector trust policy bytes are not canonical JSON plus newline")
    state = value.get("state")
    if state == "not-configured":
        exact_object(
            value,
            {"schema_version", "state", "reason"},
            "collector trust policy",
        )
        reason = value["reason"]
        if (
            type(value["schema_version"]) is not int
            # This is the historical deployment sentinel recognized by the
            # immutable collector image. Configured policies use schema v3;
            # changing this sentinel requires a new image and source digest.
            or value["schema_version"] != 2
            or not isinstance(reason, str)
            or not reason
            or utf8_size(reason, "collector trust policy.reason") > 512
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in reason)
        ):
            raise RawArtifactError("collector trust policy not-configured record is malformed")
        raise CollectorTrustNotConfiguredError(
            "production collector trust policy is not configured"
        )
    policy = exact_object(
        value,
        {
            "schema_version",
            "state",
            "key_version",
            "kty",
            "alg",
            "kms_algorithm",
            "protection_level",
            "attestation_format",
            "public_key_sha256",
            "attestation_sha256",
            "n",
            "e",
            "collector_version",
            "collector_source_sha256",
            "collector_executable_sha256",
            "evidence_profile",
        },
        "collector trust policy",
    )
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != 3
        or policy["state"] != "configured"
    ):
        raise RawArtifactError("collector trust policy state/schema is unsupported")
    evidence_profile = exact_object(
        policy["evidence_profile"],
        EVIDENCE_PROFILE_FIELDS,
        "collector trust policy.evidence_profile",
    )
    _require_exact_json_value(
        evidence_profile,
        EVIDENCE_PROFILE,
        "collector trust policy.evidence_profile",
    )
    evidence_profile_sha256 = hashlib.sha256(
        canonical_json(evidence_profile)
    ).hexdigest()
    if policy["kty"] != "RSA" or policy["alg"] != COLLECTOR_SIGNATURE_ALGORITHM:
        raise RawArtifactError(
            f"collector trust policy must use RSA/{COLLECTOR_SIGNATURE_ALGORITHM}"
        )
    if policy["kms_algorithm"] != KMS_SIGNATURE_ALGORITHM:
        raise RawArtifactError(
            f"collector trust policy kms_algorithm must be {KMS_SIGNATURE_ALGORITHM}"
        )
    if policy["protection_level"] != KMS_PROTECTION_LEVEL:
        raise RawArtifactError(
            f"collector trust policy protection_level must be {KMS_PROTECTION_LEVEL}"
        )
    if policy["attestation_format"] not in KMS_ATTESTATION_FORMATS:
        raise RawArtifactError(
            "collector trust policy attestation_format is not an allowed "
            "Cloud HSM attestation format"
        )
    key_version = require_kms_key_version(
        policy["key_version"], "collector trust policy.key_version"
    )
    modulus_bytes = _base64url_decode(policy["n"], "collector trust policy.n")
    exponent_bytes = _base64url_decode(policy["e"], "collector trust policy.e")
    if len(modulus_bytes) != PS256_SIGNATURE_BYTES or modulus_bytes[0] < 0x80:
        raise RawArtifactError(
            "collector trust policy RSA modulus must be canonical 3072-bit bytes"
        )
    if exponent_bytes != RSA_PUBLIC_EXPONENT.to_bytes(3, "big"):
        raise RawArtifactError(
            "collector trust policy RSA exponent must be canonical 65537 bytes"
        )
    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    if modulus % 2 == 0 or modulus.bit_length() != RSA_MODULUS_BITS:
        raise RawArtifactError(
            f"collector trust policy RSA modulus must be exactly {RSA_MODULUS_BITS} bits"
        )
    if exponent != RSA_PUBLIC_EXPONENT:
        raise RawArtifactError(
            f"collector trust policy RSA exponent must be {RSA_PUBLIC_EXPONENT}"
        )
    public_key_sha256 = require_sha256(
        policy["public_key_sha256"], "collector trust policy.public_key_sha256"
    )
    computed_public_key_sha256 = rsa_spki_sha256(modulus, exponent)
    if not hmac.compare_digest(public_key_sha256, computed_public_key_sha256):
        raise RawArtifactError(
            "collector trust policy public-key digest does not match n/e"
        )
    attestation_sha256 = require_sha256(
        policy["attestation_sha256"], "collector trust policy.attestation_sha256"
    )
    if hmac.compare_digest(attestation_sha256, "0" * 64) or hmac.compare_digest(
        attestation_sha256, public_key_sha256
    ):
        raise RawArtifactError(
            "collector trust policy attestation digest is not independently provisioned"
        )
    return CollectorTrustPolicy(
        policy_sha256=actual_digest,
        key_version=key_version,
        algorithm=COLLECTOR_SIGNATURE_ALGORITHM,
        kms_algorithm=KMS_SIGNATURE_ALGORITHM,
        protection_level=KMS_PROTECTION_LEVEL,
        attestation_format=policy["attestation_format"],
        public_key_sha256=public_key_sha256,
        attestation_sha256=attestation_sha256,
        modulus=modulus,
        exponent=exponent,
        collector_version=require_identifier(
            policy["collector_version"], "collector trust policy.collector_version"
        ),
        collector_source_sha256=require_sha256(
            policy["collector_source_sha256"],
            "collector trust policy.collector_source_sha256",
        ),
        collector_executable_sha256=require_sha256(
            policy["collector_executable_sha256"],
            "collector trust policy.collector_executable_sha256",
        ),
        evidence_profile_sha256=evidence_profile_sha256,
        aggregate_schema_version=evidence_profile["aggregate_schema_version"],
        aggregator_version=evidence_profile["aggregator_version"],
        boot_environment_scheme=evidence_profile["boot_environment_scheme"],
        machine_identity_scheme=evidence_profile["machine_identity_scheme"],
        machine_topology=evidence_profile["machine_topology"],
        release_source_pinned=release_source_pinned,
    )


def _read_regular_absolute(path: Path, maximum: int) -> bytes:
    absolute = path.absolute()
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(absolute, flags)
    except OSError as error:
        raise RawArtifactError("input is not an openable non-symlink file") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RawArtifactError("input must be a regular, single-link file")
        if before.st_size < 1 or before.st_size > maximum:
            raise RawArtifactError("input size is outside the accepted range")
        data = ArtifactReader._read_fd(fd, maximum)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if _stat_identity(before) != _stat_identity(after) or len(data) != before.st_size:
        raise RawArtifactError("input changed while it was being read")
    try:
        check_fd = os.open(absolute, flags)
    except OSError as error:
        raise RawArtifactError("regular input path drifted while it was being read") from error
    try:
        reopened = os.fstat(check_fd)
    finally:
        os.close(check_fd)
    if _stat_identity(before) != _stat_identity(reopened):
        raise RawArtifactError("regular input path drifted while it was being read")
    return data


def load_json_file(path: Path, *, maximum: int, label: str) -> Any:
    """Securely reopen one absolute JSON file for a standalone harness check."""

    return load_json_bytes(_read_regular_absolute(path, maximum), label)


def read_regular_file_bytes(path: Path, *, maximum: int) -> bytes:
    """Securely reopen one bounded standalone file and return its exact bytes."""

    return _read_regular_absolute(path, maximum)


def load_release_trust_policy() -> CollectorTrustPolicy:
    """Load the only trust policy accepted by the production release boundary."""

    data = _read_regular_absolute(RELEASE_TRUST_POLICY_PATH, MAX_TRUST_POLICY_BYTES)
    return parse_trust_policy_bytes(
        data,
        expected_sha256=RELEASE_TRUST_POLICY_SHA256,
        release_source_pinned=True,
    )


def read_release_trust_policy_bytes() -> bytes:
    """Securely reopen the source-pinned policy bytes for static pin checks."""

    return _read_regular_absolute(RELEASE_TRUST_POLICY_PATH, MAX_TRUST_POLICY_BYTES)
