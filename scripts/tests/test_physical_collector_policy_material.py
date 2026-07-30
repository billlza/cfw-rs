from __future__ import annotations

import base64
from contextlib import redirect_stderr, redirect_stdout
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.harness.physical_collector_policy_material import (
    MAX_PUBLIC_KEY_DER_BYTES,
    PolicyMaterialError,
    build_configured_policy,
    main,
)
from scripts.harness.raw_artifacts import (
    KMS_SIGNATURE_ALGORITHM,
    canonical_json,
    parse_trust_policy_bytes,
)
from scripts.tests.physical_evidence_fixture import TEST_RSA_N


KEY_VERSION = (
    "projects/cfw-release-evidence-20260730/locations/asia-east1/"
    "keyRings/physical-evidence/cryptoKeys/collector-receipts/cryptoKeyVersions/1"
)
COLLECTOR_VERSION = "physical-collector-v1"
SOURCE_SHA256 = "c" * 64
EXECUTABLE_SHA256 = "d" * 64


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _der_length(len(value)) + value


def _integer(value: bytes) -> bytes:
    if value[0] & 0x80:
        value = b"\x00" + value
    return _tlv(0x02, value)


def _spki(
    modulus: bytes,
    *,
    exponent: bytes = b"\x01\x00\x01",
    algorithm: bytes = bytes.fromhex("300d06092a864886f70d0101010500"),
) -> bytes:
    rsa = _tlv(0x30, _integer(modulus) + _integer(exponent))
    return _tlv(0x30, algorithm + _tlv(0x03, b"\x00" + rsa))


class PhysicalCollectorPolicyMaterialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.modulus = base64.urlsafe_b64decode(TEST_RSA_N)
        self.public_der = _spki(self.modulus)
        self.attestation = gzip.compress(
            b"reviewed Cloud HSM attestation fixture", mtime=0
        )
        self.metadata = {
            "algorithm": KMS_SIGNATURE_ALGORITHM,
            "attestation": {
                "content": base64.b64encode(self.attestation).decode("ascii"),
                "format": "CAVIUM_V2_COMPRESSED",
            },
            "name": KEY_VERSION,
            "protectionLevel": "HSM",
            "state": "ENABLED",
        }
        self.metadata_path = self.write_json("metadata.json", self.metadata)
        self.public_key_path = self.write("public-key.der", self.public_der)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def write_json(self, name: str, value: object) -> Path:
        return self.write(name, canonical_json(value) + b"\n")

    def build(
        self,
        *,
        metadata_path: Path | None = None,
        public_key_der_path: Path | None = None,
        expected_key_version: str = KEY_VERSION,
        collector_version: str = COLLECTOR_VERSION,
        collector_source_sha256: str = SOURCE_SHA256,
        collector_executable_sha256: str = EXECUTABLE_SHA256,
        attestation_compressed_path: Path | None = None,
    ) -> bytes:
        return build_configured_policy(
            metadata_path=self.metadata_path if metadata_path is None else metadata_path,
            public_key_der_path=(
                self.public_key_path
                if public_key_der_path is None
                else public_key_der_path
            ),
            expected_key_version=expected_key_version,
            collector_version=collector_version,
            collector_source_sha256=collector_source_sha256,
            collector_executable_sha256=collector_executable_sha256,
            attestation_compressed_path=attestation_compressed_path,
        )

    def test_rest_attestation_content_builds_exact_configured_policy(self) -> None:
        encoded = self.build()
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(encoded, canonical_json(json.loads(encoded)) + b"\n")
        value = json.loads(encoded)
        self.assertEqual(
            set(value),
            {
                "alg",
                "attestation_format",
                "attestation_sha256",
                "collector_executable_sha256",
                "collector_source_sha256",
                "collector_version",
                "e",
                "key_version",
                "kms_algorithm",
                "kty",
                "n",
                "protection_level",
                "public_key_sha256",
                "schema_version",
                "state",
            },
        )
        self.assertEqual(value["state"], "configured")
        self.assertEqual(value["schema_version"], 2)
        self.assertEqual(value["key_version"], KEY_VERSION)
        self.assertEqual(value["n"], TEST_RSA_N)
        self.assertEqual(value["e"], "AQAB")
        self.assertEqual(
            value["public_key_sha256"], hashlib.sha256(self.public_der).hexdigest()
        )
        self.assertEqual(
            value["attestation_sha256"],
            hashlib.sha256(self.attestation).hexdigest(),
        )
        parsed = parse_trust_policy_bytes(
            encoded, expected_sha256=hashlib.sha256(encoded).hexdigest()
        )
        self.assertEqual(parsed.key_version, KEY_VERSION)

    def test_raw_compressed_attestation_is_accepted_without_rest_content(self) -> None:
        metadata = copy.deepcopy(self.metadata)
        del metadata["attestation"]["content"]
        metadata_path = self.write_json("metadata-without-content.json", metadata)
        attestation_path = self.write("attestation.compressed", self.attestation)
        encoded = self.build(
            metadata_path=metadata_path,
            attestation_compressed_path=attestation_path,
        )
        self.assertEqual(
            json.loads(encoded)["attestation_sha256"],
            hashlib.sha256(self.attestation).hexdigest(),
        )

    def test_both_supported_cavium_attestation_formats_are_accepted(self) -> None:
        for attestation_format in (
            "CAVIUM_V1_COMPRESSED",
            "CAVIUM_V2_COMPRESSED",
        ):
            metadata = copy.deepcopy(self.metadata)
            metadata["attestation"]["format"] = attestation_format
            path = self.write_json(f"{attestation_format}.json", metadata)
            with self.subTest(attestation_format=attestation_format):
                encoded = self.build(metadata_path=path)
                self.assertEqual(
                    json.loads(encoded)["attestation_format"], attestation_format
                )

    def test_matching_rest_and_file_attestation_are_cross_checked(self) -> None:
        attestation_path = self.write("matching-attestation.gz", self.attestation)
        self.build(attestation_compressed_path=attestation_path)
        mismatched = self.write(
            "mismatched-attestation.gz", gzip.compress(b"different", mtime=0)
        )
        with self.assertRaisesRegex(PolicyMaterialError, "differs"):
            self.build(attestation_compressed_path=mismatched)

    def test_metadata_schema_rejects_unknown_missing_and_duplicate_fields(self) -> None:
        unknown = {**self.metadata, "primary": True}
        missing = dict(self.metadata)
        del missing["state"]
        for label, value, message in (
            ("unknown", unknown, "unknown fields"),
            ("missing", missing, "missing required fields"),
        ):
            path = self.write_json(f"{label}.json", value)
            with self.subTest(label=label), self.assertRaisesRegex(
                PolicyMaterialError, message
            ):
                self.build(metadata_path=path)
        duplicate = self.write(
            "duplicate.json",
            canonical_json(self.metadata)[:-1] + b',"state":"ENABLED"}\n',
        )
        with self.assertRaisesRegex(PolicyMaterialError, "duplicate field"):
            self.build(metadata_path=duplicate)

    def test_attestation_schema_rejects_unknown_field(self) -> None:
        metadata = copy.deepcopy(self.metadata)
        metadata["attestation"]["certChains"] = {}
        path = self.write_json("attestation-unknown.json", metadata)
        with self.assertRaisesRegex(PolicyMaterialError, "attestation has unknown fields"):
            self.build(metadata_path=path)

    def test_key_version_name_must_be_complete_and_match_expected(self) -> None:
        with self.assertRaisesRegex(PolicyMaterialError, "differs"):
            self.build(
                expected_key_version=KEY_VERSION.replace(
                    "cryptoKeyVersions/1", "cryptoKeyVersions/2"
                )
            )
        metadata = copy.deepcopy(self.metadata)
        metadata["name"] = "collector-receipts"
        path = self.write_json("short-key-name.json", metadata)
        with self.assertRaisesRegex(PolicyMaterialError, "complete GCP KMS"):
            self.build(metadata_path=path)

    def test_metadata_requires_enabled_pss3072_hsm_and_allowed_format(self) -> None:
        variants = (
            ("state", "DISABLED", "state must be ENABLED"),
            ("algorithm", "RSA_SIGN_PKCS1_3072_SHA256", "algorithm must be"),
            ("protectionLevel", "SOFTWARE", "protectionLevel must be HSM"),
        )
        for field, value, message in variants:
            metadata = copy.deepcopy(self.metadata)
            metadata[field] = value
            path = self.write_json(f"wrong-{field}.json", metadata)
            with self.subTest(field=field), self.assertRaisesRegex(
                PolicyMaterialError, message
            ):
                self.build(metadata_path=path)
        metadata = copy.deepcopy(self.metadata)
        metadata["attestation"]["format"] = "ATTESTATION_FORMAT_UNSPECIFIED"
        path = self.write_json("wrong-format.json", metadata)
        with self.assertRaisesRegex(PolicyMaterialError, "allowed compressed Cavium"):
            self.build(metadata_path=path)

    def test_rest_attestation_base64_must_be_canonical_and_gzip_valid(self) -> None:
        for label, content, message in (
            ("invalid-base64", "%%%", "not valid base64"),
            (
                "unpadded-base64",
                base64.b64encode(self.attestation).decode("ascii").rstrip("="),
                "not valid base64|not canonical padded base64",
            ),
            (
                "not-gzip",
                base64.b64encode(b"not gzip").decode("ascii"),
                "not a gzip-compressed stream",
            ),
        ):
            metadata = copy.deepcopy(self.metadata)
            metadata["attestation"]["content"] = content
            path = self.write_json(f"{label}.json", metadata)
            with self.subTest(label=label), self.assertRaisesRegex(
                PolicyMaterialError, message
            ):
                self.build(metadata_path=path)

    def test_gzip_trailing_bytes_are_rejected(self) -> None:
        metadata = copy.deepcopy(self.metadata)
        metadata["attestation"]["content"] = base64.b64encode(
            self.attestation + b"trailing"
        ).decode("ascii")
        path = self.write_json("trailing-gzip.json", metadata)
        with self.assertRaisesRegex(PolicyMaterialError, "trailing bytes"):
            self.build(metadata_path=path)

    def test_der_requires_canonical_rsa3072_and_exponent_65537(self) -> None:
        variants = (
            (
                "wrong-algorithm",
                _spki(
                    self.modulus,
                    algorithm=bytes.fromhex("300d06092a864886f70d0101010501"),
                ),
                "algorithm identifier",
            ),
            ("wrong-size", _spki(b"\x80" + b"\x01" * 254 + b"\x03"), "3072-bit"),
            ("wrong-exponent", _spki(self.modulus, exponent=b"\x03"), "exponent"),
            ("trailing", self.public_der + b"\x00", "trailing DER bytes"),
        )
        for label, data, message in variants:
            path = self.write(f"{label}.der", data)
            with self.subTest(label=label), self.assertRaisesRegex(
                PolicyMaterialError, message
            ):
                self.build(public_key_der_path=path)

    def test_inputs_reject_symlinks_hardlinks_and_oversized_files(self) -> None:
        metadata_link = self.root / "metadata-link.json"
        os.symlink(self.metadata_path, metadata_link)
        with self.assertRaisesRegex(PolicyMaterialError, "non-symlink"):
            self.build(metadata_path=metadata_link)

        public_hardlink = self.root / "public-hardlink.der"
        os.link(self.public_key_path, public_hardlink)
        with self.assertRaisesRegex(PolicyMaterialError, "single-link"):
            self.build(public_key_der_path=public_hardlink)
        public_hardlink.unlink()

        oversized = self.write(
            "oversized.der", b"x" * (MAX_PUBLIC_KEY_DER_BYTES + 1)
        )
        with self.assertRaisesRegex(PolicyMaterialError, "size"):
            self.build(public_key_der_path=oversized)

    def test_placeholder_and_malformed_collector_identity_are_rejected(self) -> None:
        with self.assertRaisesRegex(PolicyMaterialError, "all-zero placeholder"):
            self.build(collector_source_sha256="0" * 64)
        with self.assertRaisesRegex(PolicyMaterialError, "canonical identifier"):
            self.build(collector_version="physical collector v1")

    def test_cli_prints_only_policy_and_returns_nonzero_on_invalid_material(self) -> None:
        arguments = [
            "--key-version-metadata",
            str(self.metadata_path),
            "--public-key-der",
            str(self.public_key_path),
            "--expected-key-version",
            KEY_VERSION,
            "--collector-version",
            COLLECTOR_VERSION,
            "--collector-source-sha256",
            SOURCE_SHA256,
            "--collector-executable-sha256",
            EXECUTABLE_SHA256,
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(arguments)
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.getvalue().encode("utf-8"), self.build())

        invalid_metadata = copy.deepcopy(self.metadata)
        invalid_metadata["state"] = "DISABLED"
        invalid_path = self.write_json("disabled.json", invalid_metadata)
        invalid_arguments = list(arguments)
        invalid_arguments[1] = str(invalid_path)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(invalid_arguments)
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("state must be ENABLED", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
