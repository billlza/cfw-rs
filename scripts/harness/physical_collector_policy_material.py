#!/usr/bin/env python3
"""Build canonical configured collector-policy bytes from reviewed offline material.

This tool performs no Google Cloud request and writes no file.  It accepts one
strict CryptoKeyVersion metadata projection, the exact DER SubjectPublicKeyInfo,
and either the REST ``attestation.content`` bytes or the same raw compressed
bytes in a separate file.  The resulting policy is printed to stdout only.

This is a material normalizer, not an attestation-chain verifier.  The Google
and HSM-manufacturer certificate chains and the decompressed Cavium attributes
must be independently reviewed before these inputs are supplied.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
from pathlib import Path
import sys
from typing import Any, Sequence
import zlib

if __package__:
    from .raw_artifacts import (
        COLLECTOR_SIGNATURE_ALGORITHM,
        EVIDENCE_PROFILE,
        KMS_ATTESTATION_FORMATS,
        KMS_PROTECTION_LEVEL,
        KMS_SIGNATURE_ALGORITHM,
        RSA_MODULUS_BITS,
        RSA_PUBLIC_EXPONENT,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        parse_trust_policy_bytes,
        read_regular_file_bytes,
        require_identifier,
        require_kms_key_version,
        require_sha256,
        rsa_spki_sha256,
    )
else:  # Direct-script import path.
    from raw_artifacts import (
        COLLECTOR_SIGNATURE_ALGORITHM,
        EVIDENCE_PROFILE,
        KMS_ATTESTATION_FORMATS,
        KMS_PROTECTION_LEVEL,
        KMS_SIGNATURE_ALGORITHM,
        RSA_MODULUS_BITS,
        RSA_PUBLIC_EXPONENT,
        RawArtifactError,
        canonical_json,
        exact_object,
        load_json_bytes,
        parse_trust_policy_bytes,
        read_regular_file_bytes,
        require_identifier,
        require_kms_key_version,
        require_sha256,
        rsa_spki_sha256,
    )


MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_PUBLIC_KEY_DER_BYTES = 64 * 1024
MAX_COMPRESSED_ATTESTATION_BYTES = 8 * 1024 * 1024
MAX_DECOMPRESSED_ATTESTATION_BYTES = 16 * 1024 * 1024

METADATA_FIELDS = {"name", "state", "algorithm", "protectionLevel", "attestation"}
ATTESTATION_REQUIRED_FIELDS = {"format"}
ATTESTATION_OPTIONAL_FIELDS = {"content"}
RSA_ENCRYPTION_ALGORITHM_IDENTIFIER = bytes.fromhex(
    "300d06092a864886f70d0101010500"
)


class PolicyMaterialError(ValueError):
    """Offline key, attestation, or collector material is invalid."""


class _DerReader:
    """Minimal strict DER reader for the one accepted RSA SPKI shape."""

    def __init__(self, data: bytes, label: str) -> None:
        self._data = data
        self._label = label
        self._offset = 0

    @property
    def at_end(self) -> bool:
        return self._offset == len(self._data)

    def _take(self, length: int) -> bytes:
        end = self._offset + length
        if length < 0 or end > len(self._data):
            raise PolicyMaterialError(f"{self._label} DER value is truncated")
        value = self._data[self._offset : end]
        self._offset = end
        return value

    def _length(self) -> int:
        initial = self._take(1)[0]
        if initial < 0x80:
            return initial
        width = initial & 0x7F
        if width == 0:
            raise PolicyMaterialError(f"{self._label} uses indefinite-length DER")
        if width > 4:
            raise PolicyMaterialError(f"{self._label} DER length is excessive")
        encoded = self._take(width)
        if encoded[0] == 0:
            raise PolicyMaterialError(f"{self._label} DER length is not minimal")
        length = int.from_bytes(encoded, "big")
        if length < 0x80:
            raise PolicyMaterialError(f"{self._label} DER length is not minimal")
        return length

    def value(self, tag: int, description: str) -> bytes:
        observed = self._take(1)[0]
        if observed != tag:
            raise PolicyMaterialError(
                f"{self._label} {description} has DER tag 0x{observed:02x}, "
                f"expected 0x{tag:02x}"
            )
        return self._take(self._length())

    def require_end(self) -> None:
        if not self.at_end:
            raise PolicyMaterialError(f"{self._label} has trailing DER bytes")


def _der_positive_integer(data: bytes, label: str) -> bytes:
    reader = _DerReader(data, label)
    encoded = reader.value(0x02, "integer")
    reader.require_end()
    if not encoded:
        raise PolicyMaterialError(f"{label} is an empty DER integer")
    if encoded[0] & 0x80:
        raise PolicyMaterialError(f"{label} is a negative DER integer")
    if len(encoded) > 1 and encoded[0] == 0:
        if not encoded[1] & 0x80:
            raise PolicyMaterialError(f"{label} DER integer has redundant padding")
        encoded = encoded[1:]
    if not encoded or not any(encoded):
        raise PolicyMaterialError(f"{label} must be positive")
    return encoded


def _parse_rsa_spki(data: bytes) -> tuple[bytes, bytes, int, int]:
    outer = _DerReader(data, "public key")
    spki = outer.value(0x30, "SubjectPublicKeyInfo")
    outer.require_end()

    spki_reader = _DerReader(spki, "public key SubjectPublicKeyInfo")
    algorithm = spki_reader.value(0x30, "algorithm identifier")
    if b"\x30" + _encode_der_length(len(algorithm)) + algorithm != (
        RSA_ENCRYPTION_ALGORITHM_IDENTIFIER
    ):
        raise PolicyMaterialError(
            "public key algorithm identifier is not canonical rsaEncryption with NULL"
        )
    bit_string = spki_reader.value(0x03, "subjectPublicKey")
    spki_reader.require_end()
    if not bit_string or bit_string[0] != 0:
        raise PolicyMaterialError("public key BIT STRING has nonzero unused bits")

    wrapped_key = _DerReader(bit_string[1:], "public key RSAPublicKey wrapper")
    rsa_sequence = wrapped_key.value(0x30, "RSAPublicKey")
    wrapped_key.require_end()
    rsa_reader = _DerReader(rsa_sequence, "public key RSAPublicKey")

    modulus_tlv = _read_complete_tlv(rsa_reader, 0x02, "modulus")
    exponent_tlv = _read_complete_tlv(rsa_reader, 0x02, "exponent")
    rsa_reader.require_end()
    modulus_bytes = _der_positive_integer(modulus_tlv, "public key modulus")
    exponent_bytes = _der_positive_integer(exponent_tlv, "public key exponent")
    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")
    if (
        len(modulus_bytes) != RSA_MODULUS_BITS // 8
        or modulus.bit_length() != RSA_MODULUS_BITS
        or modulus % 2 == 0
    ):
        raise PolicyMaterialError(
            f"public key RSA modulus must be an odd, canonical {RSA_MODULUS_BITS}-bit integer"
        )
    if exponent != RSA_PUBLIC_EXPONENT or exponent_bytes != b"\x01\x00\x01":
        raise PolicyMaterialError(
            f"public key RSA exponent must be canonical {RSA_PUBLIC_EXPONENT}"
        )
    return modulus_bytes, exponent_bytes, modulus, exponent


def _encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _read_complete_tlv(reader: _DerReader, tag: int, description: str) -> bytes:
    value = reader.value(tag, description)
    return bytes((tag,)) + _encode_der_length(len(value)) + value


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_rest_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise PolicyMaterialError("metadata attestation.content must be non-empty base64")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise PolicyMaterialError(
            "metadata attestation.content must be ASCII base64"
        ) from error
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise PolicyMaterialError(
            "metadata attestation.content is not valid base64"
        ) from error
    if base64.b64encode(decoded) != encoded:
        raise PolicyMaterialError(
            "metadata attestation.content is not canonical padded base64"
        )
    if not decoded or len(decoded) > MAX_COMPRESSED_ATTESTATION_BYTES:
        raise PolicyMaterialError("decoded attestation size is outside the accepted range")
    return decoded


def _validate_gzip_attestation(data: bytes) -> None:
    if len(data) < 18 or not data.startswith(b"\x1f\x8b\x08"):
        raise PolicyMaterialError("attestation content is not a gzip-compressed stream")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        expanded = decoder.decompress(data, MAX_DECOMPRESSED_ATTESTATION_BYTES + 1)
        if decoder.unconsumed_tail or len(expanded) > MAX_DECOMPRESSED_ATTESTATION_BYTES:
            raise PolicyMaterialError("decompressed attestation exceeds the accepted bound")
        expanded += decoder.flush(
            MAX_DECOMPRESSED_ATTESTATION_BYTES + 1 - len(expanded)
        )
    except zlib.error as error:
        raise PolicyMaterialError("attestation gzip stream is invalid") from error
    if len(expanded) > MAX_DECOMPRESSED_ATTESTATION_BYTES:
        raise PolicyMaterialError("decompressed attestation exceeds the accepted bound")
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise PolicyMaterialError(
            "attestation gzip stream is truncated, concatenated, or has trailing bytes"
        )
    if not expanded:
        raise PolicyMaterialError("attestation gzip stream expands to empty content")


def _non_placeholder_sha256(value: Any, label: str) -> str:
    digest = require_sha256(value, label)
    if hmac.compare_digest(digest, "0" * 64):
        raise PolicyMaterialError(f"{label} cannot be the all-zero placeholder")
    return digest


def _load_metadata(path: Path) -> dict[str, Any]:
    value = load_json_bytes(
        read_regular_file_bytes(path, maximum=MAX_METADATA_BYTES),
        "Cloud KMS key-version metadata",
    )
    return exact_object(value, METADATA_FIELDS, "Cloud KMS key-version metadata")


def _attestation_bytes(
    attestation: dict[str, Any], compressed_path: Path | None
) -> bytes:
    actual = set(attestation)
    allowed = ATTESTATION_REQUIRED_FIELDS | ATTESTATION_OPTIONAL_FIELDS
    missing = ATTESTATION_REQUIRED_FIELDS - actual
    unknown = actual - allowed
    if missing:
        raise PolicyMaterialError(
            f"Cloud KMS attestation is missing required fields: {sorted(missing)}"
        )
    if unknown:
        raise PolicyMaterialError(
            f"Cloud KMS attestation has unknown fields: {sorted(unknown)}"
        )

    metadata_bytes = (
        _decode_rest_bytes(attestation["content"])
        if "content" in attestation
        else None
    )
    file_bytes = (
        read_regular_file_bytes(
            compressed_path, maximum=MAX_COMPRESSED_ATTESTATION_BYTES
        )
        if compressed_path is not None
        else None
    )
    if metadata_bytes is None and file_bytes is None:
        raise PolicyMaterialError(
            "attestation content is absent; provide REST content or --attestation-compressed"
        )
    if metadata_bytes is not None and file_bytes is not None and not hmac.compare_digest(
        metadata_bytes, file_bytes
    ):
        raise PolicyMaterialError(
            "REST attestation content differs from the raw compressed attestation file"
        )
    selected = metadata_bytes if metadata_bytes is not None else file_bytes
    if selected is None:
        raise AssertionError("attestation material resolution is inconsistent")
    _validate_gzip_attestation(selected)
    return selected


def build_configured_policy(
    *,
    metadata_path: Path,
    public_key_der_path: Path,
    expected_key_version: str,
    collector_version: str,
    collector_source_sha256: str,
    collector_executable_sha256: str,
    attestation_compressed_path: Path | None = None,
) -> bytes:
    """Return canonical configured policy bytes after validating all material."""

    try:
        expected_name = require_kms_key_version(
            expected_key_version, "expected Cloud KMS key version"
        )
        version = require_identifier(collector_version, "collector version")
        source_digest = _non_placeholder_sha256(
            collector_source_sha256, "collector source SHA-256"
        )
        executable_digest = _non_placeholder_sha256(
            collector_executable_sha256, "collector executable SHA-256"
        )
        metadata = _load_metadata(metadata_path)
        observed_name = require_kms_key_version(
            metadata["name"], "metadata Cloud KMS key version"
        )
        if observed_name != expected_name:
            raise PolicyMaterialError(
                "metadata key-version name differs from --expected-key-version"
            )
        if metadata["state"] != "ENABLED":
            raise PolicyMaterialError("Cloud KMS key version state must be ENABLED")
        if metadata["algorithm"] != KMS_SIGNATURE_ALGORITHM:
            raise PolicyMaterialError(
                f"Cloud KMS key version algorithm must be {KMS_SIGNATURE_ALGORITHM}"
            )
        if metadata["protectionLevel"] != KMS_PROTECTION_LEVEL:
            raise PolicyMaterialError(
                f"Cloud KMS key version protectionLevel must be {KMS_PROTECTION_LEVEL}"
            )
        if not isinstance(metadata["attestation"], dict):
            raise PolicyMaterialError("Cloud KMS attestation must be a JSON object")
        attestation = metadata["attestation"]
        attestation_format = attestation.get("format")
        if attestation_format not in KMS_ATTESTATION_FORMATS:
            raise PolicyMaterialError(
                "Cloud KMS attestation format is not an allowed compressed Cavium format"
            )
        compressed_attestation = _attestation_bytes(
            attestation, attestation_compressed_path
        )

        public_der = read_regular_file_bytes(
            public_key_der_path, maximum=MAX_PUBLIC_KEY_DER_BYTES
        )
        modulus_bytes, exponent_bytes, modulus, exponent = _parse_rsa_spki(public_der)
        public_key_sha256 = hashlib.sha256(public_der).hexdigest()
        if not hmac.compare_digest(
            public_key_sha256, rsa_spki_sha256(modulus, exponent)
        ):
            raise PolicyMaterialError(
                "public key DER differs from the canonical RSA SubjectPublicKeyInfo"
            )

        policy = {
            "alg": COLLECTOR_SIGNATURE_ALGORITHM,
            "attestation_format": attestation_format,
            "attestation_sha256": hashlib.sha256(compressed_attestation).hexdigest(),
            "collector_executable_sha256": executable_digest,
            "collector_source_sha256": source_digest,
            "collector_version": version,
            "e": _base64url(exponent_bytes),
            "evidence_profile": EVIDENCE_PROFILE,
            "key_version": observed_name,
            "kms_algorithm": KMS_SIGNATURE_ALGORITHM,
            "kty": "RSA",
            "n": _base64url(modulus_bytes),
            "protection_level": KMS_PROTECTION_LEVEL,
            "public_key_sha256": public_key_sha256,
            "schema_version": 3,
            "state": "configured",
        }
        encoded = canonical_json(policy) + b"\n"
        parse_trust_policy_bytes(
            encoded, expected_sha256=hashlib.sha256(encoded).hexdigest()
        )
        return encoded
    except RawArtifactError as error:
        raise PolicyMaterialError(str(error)) from error


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "The metadata projection must contain exactly name, state, algorithm, "
            "protectionLevel, and attestation; attestation contains format and "
            "optional REST content."
        ),
    )
    parser.add_argument("--key-version-metadata", required=True, type=Path)
    parser.add_argument("--public-key-der", required=True, type=Path)
    parser.add_argument("--attestation-compressed", type=Path)
    parser.add_argument("--expected-key-version", required=True)
    parser.add_argument("--collector-version", required=True)
    parser.add_argument("--collector-source-sha256", required=True)
    parser.add_argument("--collector-executable-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        encoded = build_configured_policy(
            metadata_path=arguments.key_version_metadata,
            public_key_der_path=arguments.public_key_der,
            attestation_compressed_path=arguments.attestation_compressed,
            expected_key_version=arguments.expected_key_version,
            collector_version=arguments.collector_version,
            collector_source_sha256=arguments.collector_source_sha256,
            collector_executable_sha256=arguments.collector_executable_sha256,
        )
    except (OSError, PolicyMaterialError) as error:
        print(f"error: physical collector policy material: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(encoded.decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
