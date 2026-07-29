from __future__ import annotations

import base64
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.harness.raw_artifacts import (
    COLLECTOR_SIGNATURE_ALGORITHM,
    KMS_ATTESTATION_FORMATS,
    KMS_PROTECTION_LEVEL,
    KMS_SIGNATURE_ALGORITHM,
    MAX_ARTIFACT_COUNT,
    ArtifactReader,
    RawArtifactError,
    canonical_json,
    load_json_bytes,
    load_release_trust_policy,
    parse_descriptor,
    parse_trust_policy_bytes,
    rsa_spki_sha256,
    verify_ps256,
)
from scripts.tests.physical_evidence_fixture import (
    DEFAULT_PSS_SALT,
    TEST_ATTESTATION_FORMAT,
    TEST_ATTESTATION_SHA256,
    TEST_EXPONENT,
    TEST_KEY_VERSION,
    TEST_MODULUS,
    TEST_PRIVATE_EXPONENT,
    TEST_PUBLIC_KEY_SHA256,
    TEST_RSA_E,
    TEST_RSA_N,
    ps256_sign,
    pss_encoded_message,
    sign_encoded_message,
)

PS256_MESSAGE = b"cfw physical collector receipt fixture v3"
PS256_SIGNATURE = (
    "vkwsUw1iNgAay8zR1pI6dUYhOsrBm_fr9WJTC6gQ2f7HXxW82PPggQd-ogVWY35WccbYSE6d"
    "fz0iiQni23rE0uF1vh_GbPuAlHbh0rZj2lRhNXGWuTpkCTt6tJm9IWsPvS4yE6yd9HqIR0ai"
    "6GtHJqBlXAWkrtdJCW9kr5y9FDNbrwCrWKrn9kHUeiOEhwZ1yAeG-pgT9PVeYps1p9iG2f_o"
    "FqvDy3kVOQUEipvNwDNMe9Nke2_ntnrAFx7EiroEe518EzAtr-0QJ2yr2OvazkYM1MgzQMEb"
    "v_gCAXe9U-kwBAdZ6csTJwMiYyReLPyaA0R-WUYyDJ2gcFjDgnxouVFHz_wDOfivXP-Iu2n7"
    "zLnkFuA5aQBNvwiBd92RYVeAul0j-MqWF3YYXRtMioljNOkPknX3WEg6R656yJqaGbAOSWcs"
    "HTSQbuSGQCMD2qOsbb0Yxeke9KUuM-Sm8WP9YYtvgwK7584_2jzlTeDBKv9n-FPZSkV3sh10"
    "g1pwY_hK"
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _descriptor(path: str, data: bytes, kind: str = "lifecycle-event") -> dict:
    return {
        "kind": kind,
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class Ps256VerifierTests(unittest.TestCase):
    def verify(self, signature: str = PS256_SIGNATURE, message: bytes = PS256_MESSAGE) -> None:
        verify_ps256(
            message,
            signature,
            modulus=TEST_MODULUS,
            exponent=TEST_EXPONENT,
        )

    def test_static_independent_ps256_vector(self) -> None:
        self.assertEqual(ps256_sign(PS256_MESSAGE), PS256_SIGNATURE)
        self.verify()

    def test_rs256_signature_is_rejected_by_ps256_verifier(self) -> None:
        digest_info = (
            bytes.fromhex("3031300d060960864801650304020105000420")
            + hashlib.sha256(PS256_MESSAGE).digest()
        )
        encoded = (
            b"\x00\x01"
            + b"\xff" * (384 - len(digest_info) - 3)
            + b"\x00"
            + digest_info
        )
        signature = pow(
            int.from_bytes(encoded, "big"), TEST_PRIVATE_EXPONENT, TEST_MODULUS
        ).to_bytes(384, "big")
        with self.assertRaises(RawArtifactError):
            self.verify(_b64url(signature))

    def test_message_mutation_fails(self) -> None:
        with self.assertRaisesRegex(RawArtifactError, "signature is invalid"):
            self.verify(message=PS256_MESSAGE + b"x")

    def test_signature_mutation_fails(self) -> None:
        signature = bytearray(base64.urlsafe_b64decode(PS256_SIGNATURE))
        signature[-1] ^= 1
        with self.assertRaises(RawArtifactError):
            self.verify(_b64url(signature))

    def test_padded_and_non_base64url_signatures_fail(self) -> None:
        for signature in (PS256_SIGNATURE + "=", PS256_SIGNATURE[:-1] + "+"):
            with self.subTest(signature=signature[-2:]), self.assertRaisesRegex(
                RawArtifactError, "unpadded base64url"
            ):
                self.verify(signature)

    def test_signature_length_is_exactly_384_bytes(self) -> None:
        signature = base64.urlsafe_b64decode(PS256_SIGNATURE)
        for mutated in (signature[:-1], signature + b"\x00"):
            with self.subTest(length=len(mutated)), self.assertRaisesRegex(
                RawArtifactError, "exactly 384 bytes"
            ):
                self.verify(_b64url(mutated))

    def test_signature_representative_must_be_below_modulus(self) -> None:
        with self.assertRaisesRegex(RawArtifactError, "outside the RSA modulus"):
            self.verify(_b64url(TEST_MODULUS.to_bytes(384, "big")))

    def test_even_modulus_is_rejected(self) -> None:
        with self.assertRaisesRegex(RawArtifactError, "modulus"):
            verify_ps256(
                PS256_MESSAGE,
                PS256_SIGNATURE,
                modulus=TEST_MODULUS - 1,
                exponent=TEST_EXPONENT,
            )

    def test_only_3072_bit_modulus_is_accepted(self) -> None:
        for bits in (2048, 3071, 3073, 4096):
            modulus = (1 << (bits - 1)) | 1
            with self.subTest(bits=bits), self.assertRaisesRegex(
                RawArtifactError, "exactly 3072 bits"
            ):
                verify_ps256(
                    PS256_MESSAGE,
                    PS256_SIGNATURE,
                    modulus=modulus,
                    exponent=TEST_EXPONENT,
                )

    def test_public_exponent_is_exactly_65537(self) -> None:
        for exponent in (3, 65539):
            with self.subTest(exponent=exponent), self.assertRaisesRegex(
                RawArtifactError, "must be 65537"
            ):
                verify_ps256(
                    PS256_MESSAGE,
                    PS256_SIGNATURE,
                    modulus=TEST_MODULUS,
                    exponent=exponent,
                )

    def test_wrong_trailer_is_rejected(self) -> None:
        signature = sign_encoded_message(
            pss_encoded_message(PS256_MESSAGE, trailer=0xBD)
        )
        with self.assertRaisesRegex(RawArtifactError, "trailer"):
            self.verify(signature)

    def test_unused_high_bit_is_rejected(self) -> None:
        signature = sign_encoded_message(
            pss_encoded_message(PS256_MESSAGE, force_unused_high_bit=True)
        )
        with self.assertRaisesRegex(RawArtifactError, "unused high bit"):
            self.verify(signature)

    def test_mgf1_must_use_sha256(self) -> None:
        signature = sign_encoded_message(
            pss_encoded_message(PS256_MESSAGE, mgf_hash_name="sha1")
        )
        with self.assertRaises(RawArtifactError):
            self.verify(signature)

    def test_message_hash_must_use_sha256(self) -> None:
        signature = sign_encoded_message(
            pss_encoded_message(PS256_MESSAGE, message_hash_name="sha384")
        )
        with self.assertRaises(RawArtifactError):
            self.verify(signature)

    def test_salt_length_is_exactly_32_bytes(self) -> None:
        for length in (0, 31, 33, 350):
            signature = sign_encoded_message(
                pss_encoded_message(PS256_MESSAGE, salt=b"s" * length)
            )
            with self.subTest(length=length), self.assertRaises(RawArtifactError):
                self.verify(signature)

    def test_db_padding_and_delimiter_are_exact(self) -> None:
        variants = (
            pss_encoded_message(PS256_MESSAGE, padding_byte=1),
            pss_encoded_message(PS256_MESSAGE, delimiter=2),
        )
        for encoded in variants:
            with self.subTest(encoded=hashlib.sha256(encoded).hexdigest()), self.assertRaises(
                RawArtifactError
            ):
                self.verify(sign_encoded_message(encoded))


class TrustPolicyTests(unittest.TestCase):
    def configured_value(self) -> dict:
        return {
            "alg": COLLECTOR_SIGNATURE_ALGORITHM,
            "attestation_format": TEST_ATTESTATION_FORMAT,
            "attestation_sha256": TEST_ATTESTATION_SHA256,
            "collector_executable_sha256": "d" * 64,
            "collector_source_sha256": "c" * 64,
            "collector_version": "collector-v1",
            "e": TEST_RSA_E,
            "key_version": TEST_KEY_VERSION,
            "kms_algorithm": KMS_SIGNATURE_ALGORITHM,
            "kty": "RSA",
            "n": TEST_RSA_N,
            "protection_level": KMS_PROTECTION_LEVEL,
            "public_key_sha256": TEST_PUBLIC_KEY_SHA256,
            "schema_version": 2,
            "state": "configured",
        }

    def configured_policy(self, value: dict | None = None) -> tuple[bytes, str]:
        value = self.configured_value() if value is None else value
        data = canonical_json(value) + b"\n"
        return data, hashlib.sha256(data).hexdigest()

    def parse(self, value: dict) -> object:
        data, digest = self.configured_policy(value)
        return parse_trust_policy_bytes(data, expected_sha256=digest)

    def test_configured_ps256_hsm_policy_is_accepted(self) -> None:
        policy = self.parse(self.configured_value())
        self.assertEqual(policy.algorithm, COLLECTOR_SIGNATURE_ALGORITHM)
        self.assertEqual(policy.kms_algorithm, KMS_SIGNATURE_ALGORITHM)
        self.assertEqual(policy.protection_level, KMS_PROTECTION_LEVEL)
        self.assertIn(policy.attestation_format, KMS_ATTESTATION_FORMATS)
        self.assertEqual(policy.key_version, TEST_KEY_VERSION)
        self.assertEqual(policy.public_key_sha256, rsa_spki_sha256(TEST_MODULUS, 65537))

    def test_policy_bytes_must_match_source_pin(self) -> None:
        data, _digest = self.configured_policy()
        with self.assertRaisesRegex(RawArtifactError, "source-pinned digest"):
            parse_trust_policy_bytes(data, expected_sha256="0" * 64)

    def test_policy_bytes_must_be_canonical(self) -> None:
        data, digest = self.configured_policy()
        pretty = data.replace(b",", b", ")
        with self.assertRaisesRegex(RawArtifactError, "canonical JSON"):
            parse_trust_policy_bytes(pretty, expected_sha256=hashlib.sha256(pretty).hexdigest())
        self.assertNotEqual(hashlib.sha256(pretty).hexdigest(), digest)

    def test_even_policy_modulus_is_rejected(self) -> None:
        data, _digest = self.configured_policy()
        value = load_json_bytes(data, "fixture")
        modulus = bytearray(base64.urlsafe_b64decode(value["n"]))
        modulus[-1] &= 0xFE
        value["n"] = base64.urlsafe_b64encode(modulus).rstrip(b"=").decode()
        mutated = canonical_json(value) + b"\n"
        with self.assertRaisesRegex(RawArtifactError, "modulus"):
            parse_trust_policy_bytes(
                mutated, expected_sha256=hashlib.sha256(mutated).hexdigest()
            )

    def test_rs256_and_ps384_downgrades_are_rejected(self) -> None:
        for algorithm in ("RS256", "PS384"):
            value = self.configured_value()
            value["alg"] = algorithm
            with self.subTest(algorithm=algorithm), self.assertRaisesRegex(
                RawArtifactError, "RSA/PS256"
            ):
                self.parse(value)

    def test_policy_v1_is_rejected_without_compatibility(self) -> None:
        value = self.configured_value()
        value["schema_version"] = 1
        with self.assertRaisesRegex(RawArtifactError, "state/schema"):
            self.parse(value)

    def test_policy_schema_rejects_float_and_bool(self) -> None:
        for schema_version in (2.0, True):
            value = self.configured_value()
            value["schema_version"] = schema_version
            with self.subTest(schema_version=schema_version), self.assertRaisesRegex(
                RawArtifactError, "state/schema"
            ):
                self.parse(value)

    def test_key_version_must_be_complete_and_versioned(self) -> None:
        for key_version in (
            "collector-key",
            "projects/cfw-fixture/locations/global/keyRings/r/cryptoKeys/k",
            "projects/cfw-fixture/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/0",
        ):
            value = self.configured_value()
            value["key_version"] = key_version
            with self.subTest(key_version=key_version), self.assertRaisesRegex(
                RawArtifactError, "complete GCP KMS"
            ):
                self.parse(value)

    def test_kms_algorithm_is_exact(self) -> None:
        value = self.configured_value()
        value["kms_algorithm"] = "RSA_SIGN_PSS_4096_SHA256"
        with self.assertRaisesRegex(RawArtifactError, "kms_algorithm"):
            self.parse(value)

    def test_only_hsm_protection_is_accepted(self) -> None:
        for protection in ("SOFTWARE", "EXTERNAL", "EXTERNAL_VPC"):
            value = self.configured_value()
            value["protection_level"] = protection
            with self.subTest(protection=protection), self.assertRaisesRegex(
                RawArtifactError, "protection_level"
            ):
                self.parse(value)

    def test_attestation_format_is_explicitly_allowlisted(self) -> None:
        for attestation_format in ("ATTESTATION_FORMAT_UNSPECIFIED", "", "TPM2"):
            value = self.configured_value()
            value["attestation_format"] = attestation_format
            with self.subTest(attestation_format=attestation_format), self.assertRaisesRegex(
                RawArtifactError, "attestation_format"
            ):
                self.parse(value)

    def test_both_documented_cloud_hsm_attestation_formats_are_accepted(self) -> None:
        for attestation_format in sorted(KMS_ATTESTATION_FORMATS):
            value = self.configured_value()
            value["attestation_format"] = attestation_format
            with self.subTest(attestation_format=attestation_format):
                self.parse(value)

    def test_public_key_digest_must_match_der_spki(self) -> None:
        value = self.configured_value()
        value["public_key_sha256"] = "1" * 64
        with self.assertRaisesRegex(RawArtifactError, "does not match n/e"):
            self.parse(value)

    def test_attestation_digest_must_be_independently_provisioned(self) -> None:
        for digest in ("0" * 64, TEST_PUBLIC_KEY_SHA256):
            value = self.configured_value()
            value["attestation_sha256"] = digest
            with self.subTest(digest=digest), self.assertRaisesRegex(
                RawArtifactError, "independently provisioned"
            ):
                self.parse(value)

    def test_modulus_encoding_and_size_are_exact(self) -> None:
        for bits in (2048, 3071, 3073, 4096):
            value = self.configured_value()
            modulus = ((1 << (bits - 1)) | 1).to_bytes((bits + 7) // 8, "big")
            value["n"] = _b64url(modulus)
            with self.subTest(bits=bits), self.assertRaisesRegex(
                RawArtifactError, "3072-bit|exactly 3072"
            ):
                self.parse(value)

    def test_exponent_must_be_canonical_65537(self) -> None:
        for exponent in (3, 65539):
            value = self.configured_value()
            value["e"] = _b64url(exponent.to_bytes((exponent.bit_length() + 7) // 8, "big"))
            with self.subTest(exponent=exponent), self.assertRaisesRegex(
                RawArtifactError, "canonical 65537"
            ):
                self.parse(value)

    def test_unknown_policy_field_is_rejected(self) -> None:
        value = self.configured_value()
        value["fallback_alg"] = "RS256"
        with self.assertRaisesRegex(RawArtifactError, "unknown fields"):
            self.parse(value)

    def test_checked_in_production_policy_is_explicitly_unconfigured(self) -> None:
        with self.assertRaisesRegex(RawArtifactError, "not configured"):
            load_release_trust_policy()

    def test_not_configured_policy_requires_exact_schema_v2_integer(self) -> None:
        for schema_version in (1, 2.0, True):
            value = {
                "reason": "fixture trust is absent",
                "schema_version": schema_version,
                "state": "not-configured",
            }
            data = canonical_json(value) + b"\n"
            with self.subTest(schema_version=schema_version), self.assertRaisesRegex(
                RawArtifactError, "malformed"
            ):
                parse_trust_policy_bytes(
                    data, expected_sha256=hashlib.sha256(data).hexdigest()
                )


class ArtifactReaderSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, data: bytes) -> dict:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return _descriptor(relative, data)

    def test_path_traversal_absolute_and_unknown_fields_rejected(self) -> None:
        for path in ("../escape.json", "/absolute.json", "a/./b.json"):
            with self.subTest(path=path), self.assertRaises(RawArtifactError):
                parse_descriptor(
                    _descriptor(path, b"x"),
                    expected_kinds={"lifecycle-event"},
                    label="artifact",
                )
        value = _descriptor("a.json", b"x")
        value["extra"] = True
        with self.assertRaisesRegex(RawArtifactError, "unknown fields"):
            parse_descriptor(value, expected_kinds={"lifecycle-event"}, label="artifact")

    def test_symlink_file_and_symlink_directory_rejected(self) -> None:
        real = self.root / "real.json"
        real.write_bytes(b"x")
        os.symlink(real, self.root / "link.json")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "nested.json").write_bytes(b"x")
        os.symlink(outside, self.root / "linked-dir")
        descriptors = (
            _descriptor("link.json", b"x"),
            _descriptor("linked-dir/nested.json", b"x"),
        )
        for value in descriptors:
            with self.subTest(path=value["path"]), self.assertRaises(RawArtifactError):
                with ArtifactReader(self.root) as reader:
                    reader.read(value, expected_kinds={"lifecycle-event"}, label="artifact")

    def test_hardlink_rejected(self) -> None:
        original = self.root / "original.json"
        original.write_bytes(b"hardlink")
        os.link(original, self.root / "alias.json")
        with ArtifactReader(self.root) as reader, self.assertRaisesRegex(
            RawArtifactError, "hard-linked"
        ):
            reader.read(
                _descriptor("alias.json", b"hardlink"),
                expected_kinds={"lifecycle-event"},
                label="artifact",
            )

    def test_path_swap_during_read_is_detected(self) -> None:
        value = self.write("race.json", b"stable-bytes")
        path = self.root / "race.json"
        original_read = ArtifactReader._read_fd

        def swapping_read(fd: int, maximum: int) -> bytes:
            data = original_read(fd, maximum)
            path.rename(self.root / "old.json")
            path.write_bytes(data)
            return data

        with mock.patch.object(ArtifactReader, "_read_fd", side_effect=swapping_read):
            with ArtifactReader(self.root) as reader, self.assertRaisesRegex(
                RawArtifactError, "changed while|path drifted"
            ):
                reader.read(
                    value,
                    expected_kinds={"lifecycle-event"},
                    label="artifact",
                )

    def test_duplicate_bytes_under_another_path_are_rejected(self) -> None:
        first = self.write("first.json", b"same")
        second = self.write("second.json", b"same")
        with ArtifactReader(self.root) as reader:
            reader.read(first, expected_kinds={"lifecycle-event"}, label="first")
            with self.assertRaisesRegex(RawArtifactError, "reuses artifact bytes"):
                reader.read(second, expected_kinds={"lifecycle-event"}, label="second")

    def test_final_rescan_detects_append_after_initial_read(self) -> None:
        value = self.write("append-race.json", b"initial-bytes")
        path = self.root / value["path"]
        with ArtifactReader(self.root) as reader:
            reader.read(value, expected_kinds={"lifecycle-event"}, label="append race")
            with path.open("ab") as stream:
                stream.write(b"-appended")
            with self.assertRaisesRegex(RawArtifactError, "identity drifted"):
                reader.verify_all_unchanged()

    def test_final_rescan_detects_path_replacement_after_initial_read(self) -> None:
        value = self.write("replacement-race.json", b"initial-bytes")
        path = self.root / value["path"]
        with ArtifactReader(self.root) as reader:
            reader.read(value, expected_kinds={"lifecycle-event"}, label="replacement race")
            path.rename(self.root / "original.json")
            path.write_bytes(b"initial-bytes")
            with self.assertRaisesRegex(RawArtifactError, "identity drifted"):
                reader.verify_all_unchanged()

    def test_final_rescan_detects_same_bytes_restored_in_place(self) -> None:
        value = self.write("restore-race.json", b"initial-bytes")
        path = self.root / value["path"]
        with ArtifactReader(self.root) as reader:
            reader.read(value, expected_kinds={"lifecycle-event"}, label="restore race")
            path.write_bytes(b"mutated-value")
            path.write_bytes(b"initial-bytes")
            with self.assertRaisesRegex(RawArtifactError, "identity drifted"):
                reader.verify_all_unchanged()

    def test_final_path_is_revalidated_last(self) -> None:
        aggregate_path = self.root / "aggregate.json"
        aggregate_path.write_bytes(b"aggregate")
        aggregate = _descriptor("aggregate.json", b"aggregate", kind="physical-aggregate")
        child = self.write("child.json", b"child")
        with ArtifactReader(self.root) as reader:
            reader.read(
                aggregate,
                expected_kinds={"physical-aggregate"},
                label="aggregate",
            )
            reader.read(child, expected_kinds={"lifecycle-event"}, label="child")
            order: list[str] = []
            original = reader._revalidate_snapshot

            def record(snapshot, label):
                order.append(snapshot.descriptor.path)
                original(snapshot, label)

            with mock.patch.object(reader, "_revalidate_snapshot", side_effect=record):
                reader.verify_all_unchanged(final_path="aggregate.json")
            self.assertEqual(order, ["child.json", "aggregate.json"])

    def test_oversize_descriptor_rejected_before_open(self) -> None:
        value = {
            "kind": "lifecycle-event",
            "path": "large.json",
            "size": 1_048_577,
            "sha256": "a" * 64,
        }
        with self.assertRaisesRegex(RawArtifactError, "byte bound"):
            parse_descriptor(value, expected_kinds={"lifecycle-event"}, label="artifact")

    def test_global_artifact_count_bound(self) -> None:
        with ArtifactReader(self.root) as reader:
            for index in range(MAX_ARTIFACT_COUNT + 1):
                data = f"artifact-{index}".encode()
                value = self.write(f"many/{index}.json", data)
                if index == MAX_ARTIFACT_COUNT:
                    with self.assertRaisesRegex(RawArtifactError, "count exceeds"):
                        reader.read(
                            value,
                            expected_kinds={"lifecycle-event"},
                            label=f"artifact[{index}]",
                        )
                else:
                    reader.read(
                        value,
                        expected_kinds={"lifecycle-event"},
                        label=f"artifact[{index}]",
                    )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(RawArtifactError, "duplicate field"):
            load_json_bytes(b'{"a":1,"a":2}', "duplicate")


if __name__ == "__main__":
    unittest.main()
