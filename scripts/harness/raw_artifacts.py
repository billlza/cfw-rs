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

MAX_ARTIFACT_COUNT = 512
MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_RELATIVE_PATH_BYTES = 512
MAX_JSON_DEPTH = 32
MAX_TRUST_POLICY_BYTES = 64 * 1024

REPORT_MAX_BYTES = 1 * 1024 * 1024


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
    "packet-capture-provenance": ArtifactKindSpec(".json", 256 * 1024),
    "packet-send-attempt": ArtifactKindSpec(".json", 256 * 1024),
    "lifecycle-event": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "performance-samples": ArtifactKindSpec(".json", 16 * 1024 * 1024),
    "adversarial-transcript": ArtifactKindSpec(".json", 1 * 1024 * 1024),
    "client-signature-evidence": ArtifactKindSpec(".json", 256 * 1024),
}

DESCRIPTOR_FIELDS = {"kind", "path", "size", "sha256"}
PROOF_FIELDS = {"run_id", "run_nonce", "candidate", "collector"}
CANDIDATE_FIELDS = {
    "version",
    "build_number",
    "app_manifest_sha256",
    "signed_app_tree_sha256",
}
COLLECTOR_BINDING_FIELDS = {
    "version",
    "source_sha256",
    "executable_sha256",
}

RELEASE_TRUST_POLICY_PATH = Path(__file__).with_name(
    "physical_collector_trust_policy.json"
)
# Updated only together with the canonical policy file. The checked-in policy
# intentionally has state=not-configured until release engineering provisions
# and reviews a production collector key.
RELEASE_TRUST_POLICY_SHA256 = "52d4e515567ee32b333dc3f23043382c7444157c8daafb40cda4968059393319"

_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


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
    key_id: str
    modulus: int
    exponent: int
    collector_version: str
    collector_source_sha256: str
    collector_executable_sha256: str
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


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise RawArtifactError(f"{label} is not a lowercase SHA-256")
    return value


def require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise RawArtifactError(f"{label} is not a canonical identifier")
    return value


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
    except (TypeError, ValueError) as error:
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


def _json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise RawArtifactError(f"JSON nesting exceeds {MAX_JSON_DEPTH}")
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise RawArtifactError("JSON object key is not a string")
            _json_depth(nested, depth + 1)
    elif isinstance(value, list):
        for nested in value:
            _json_depth(nested, depth + 1)
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
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as error:
        raise RawArtifactError(f"{label} is not valid JSON") from error
    except RecursionError as error:
        raise RawArtifactError(f"{label} JSON nesting is excessive") from error
    _json_depth(value)
    return value


def parse_proof_binding(value: Any, label: str = "proof") -> dict[str, Any]:
    """Parse the common candidate/run/collector binding carried by every report."""

    proof = exact_object(value, PROOF_FIELDS, label)
    run_id = require_identifier(proof["run_id"], f"{label}.run_id")
    run_nonce = require_sha256(proof["run_nonce"], f"{label}.run_nonce")
    candidate = exact_object(proof["candidate"], CANDIDATE_FIELDS, f"{label}.candidate")
    version = candidate["version"]
    build_number = candidate["build_number"]
    if (
        not isinstance(version, str)
        or not version
        or len(version.encode("utf-8")) > 32
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
    }
    return {
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
    if "\\" in path or len(path.encode("utf-8")) > MAX_RELATIVE_PATH_BYTES:
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


def verify_rs256(
    message: bytes,
    signature_base64url: Any,
    *,
    modulus: int,
    exponent: int,
) -> None:
    """Verify RSASSA-PKCS1-v1_5 SHA-256 using only Python's standard library."""

    if (
        modulus <= 0
        or modulus % 2 == 0
        or modulus.bit_length() < 2048
        or modulus.bit_length() > 4096
    ):
        raise RawArtifactError("collector RSA modulus must be between 2048 and 4096 bits")
    if exponent < 65537 or exponent > 0xFFFFFFFF or exponent % 2 == 0:
        raise RawArtifactError("collector RSA public exponent is outside the accepted range")
    signature = _base64url_decode(signature_base64url, "collector signature")
    width = (modulus.bit_length() + 7) // 8
    if len(signature) != width:
        raise RawArtifactError("collector signature length does not match its RSA key")
    encoded_integer = int.from_bytes(signature, "big")
    if encoded_integer >= modulus:
        raise RawArtifactError("collector signature representative is outside the RSA modulus")
    encoded = pow(encoded_integer, exponent, modulus).to_bytes(width, "big")
    digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding_length = width - len(digest_info) - 3
    if padding_length < 8:
        raise RawArtifactError("collector RSA modulus is too short for RS256")
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    if not hmac.compare_digest(encoded, expected):
        raise RawArtifactError("collector receipt signature is invalid")


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
            value["schema_version"] != 1
            or not isinstance(reason, str)
            or not reason
            or len(reason.encode("utf-8")) > 512
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
            "key_id",
            "kty",
            "alg",
            "n",
            "e",
            "collector_version",
            "collector_source_sha256",
            "collector_executable_sha256",
        },
        "collector trust policy",
    )
    if policy["schema_version"] != 1 or policy["state"] != "configured":
        raise RawArtifactError("collector trust policy state/schema is unsupported")
    if policy["kty"] != "RSA" or policy["alg"] != "RS256":
        raise RawArtifactError("collector trust policy must use RSA/RS256")
    modulus_bytes = _base64url_decode(policy["n"], "collector trust policy.n")
    exponent_bytes = _base64url_decode(policy["e"], "collector trust policy.e")
    if len(modulus_bytes) < 256 or len(modulus_bytes) > 512 or modulus_bytes[0] == 0:
        raise RawArtifactError("collector trust policy RSA modulus encoding is non-canonical")
    if not exponent_bytes or len(exponent_bytes) > 4 or exponent_bytes[0] == 0:
        raise RawArtifactError("collector trust policy RSA exponent encoding is non-canonical")
    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    if modulus % 2 == 0 or modulus.bit_length() < 2048 or modulus.bit_length() > 4096:
        raise RawArtifactError("collector trust policy RSA modulus is outside 2048..4096 bits")
    if exponent < 65537 or exponent > 0xFFFFFFFF or exponent % 2 == 0:
        raise RawArtifactError("collector trust policy RSA exponent is outside the accepted range")
    return CollectorTrustPolicy(
        policy_sha256=actual_digest,
        key_id=require_identifier(policy["key_id"], "collector trust policy.key_id"),
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
