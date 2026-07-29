from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.harness.raw_artifacts import (
    MAX_ARTIFACT_COUNT,
    ArtifactReader,
    RawArtifactError,
    canonical_json,
    load_json_bytes,
    load_release_trust_policy,
    parse_descriptor,
    parse_trust_policy_bytes,
    verify_rs256,
)
from scripts.tests.physical_evidence_fixture import (
    RFC7515_E,
    RFC7515_N,
    RFC_EXPONENT,
    RFC_MODULUS,
)


RFC7515_SIGNING_INPUT = (
    b"eyJhbGciOiJSUzI1NiJ9."
    b"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    b"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
)
RFC7515_SIGNATURE = (
    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
    "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
    "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
    "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
    "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
    "p0igcN_IoypGlUPQGe77Rw"
)


def _descriptor(path: str, data: bytes, kind: str = "lifecycle-event") -> dict:
    return {
        "kind": kind,
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class Rs256VerifierTests(unittest.TestCase):
    def test_rfc7515_appendix_a2_public_vector(self) -> None:
        verify_rs256(
            RFC7515_SIGNING_INPUT,
            RFC7515_SIGNATURE,
            modulus=RFC_MODULUS,
            exponent=RFC_EXPONENT,
        )

    def test_rfc_vector_message_mutation_fails(self) -> None:
        with self.assertRaisesRegex(RawArtifactError, "signature is invalid"):
            verify_rs256(
                RFC7515_SIGNING_INPUT + b"x",
                RFC7515_SIGNATURE,
                modulus=RFC_MODULUS,
                exponent=RFC_EXPONENT,
            )

    def test_rfc_vector_signature_mutation_fails(self) -> None:
        mutated = "A" + RFC7515_SIGNATURE[1:]
        with self.assertRaisesRegex(RawArtifactError, "signature is invalid"):
            verify_rs256(
                RFC7515_SIGNING_INPUT,
                mutated,
                modulus=RFC_MODULUS,
                exponent=RFC_EXPONENT,
            )

    def test_noncanonical_base64url_pad_bits_fail(self) -> None:
        self.assertTrue(RFC7515_SIGNATURE.endswith("w"))
        with self.assertRaisesRegex(RawArtifactError, "canonical unpadded"):
            verify_rs256(
                RFC7515_SIGNING_INPUT,
                RFC7515_SIGNATURE[:-1] + "x",
                modulus=RFC_MODULUS,
                exponent=RFC_EXPONENT,
            )

    def test_even_modulus_is_rejected(self) -> None:
        with self.assertRaisesRegex(RawArtifactError, "modulus"):
            verify_rs256(
                RFC7515_SIGNING_INPUT,
                RFC7515_SIGNATURE,
                modulus=RFC_MODULUS - 1,
                exponent=RFC_EXPONENT,
            )


class TrustPolicyTests(unittest.TestCase):
    def configured_policy(self) -> tuple[bytes, str]:
        value = {
            "alg": "RS256",
            "collector_executable_sha256": "d" * 64,
            "collector_source_sha256": "c" * 64,
            "collector_version": "collector-v1",
            "e": RFC7515_E,
            "key_id": "fixture-key",
            "kty": "RSA",
            "n": RFC7515_N,
            "schema_version": 1,
            "state": "configured",
        }
        data = canonical_json(value) + b"\n"
        return data, hashlib.sha256(data).hexdigest()

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
        modulus = bytearray(base64.urlsafe_b64decode(value["n"] + "=="))
        modulus[-1] &= 0xFE
        value["n"] = base64.urlsafe_b64encode(modulus).rstrip(b"=").decode()
        mutated = canonical_json(value) + b"\n"
        with self.assertRaisesRegex(RawArtifactError, "modulus"):
            parse_trust_policy_bytes(
                mutated, expected_sha256=hashlib.sha256(mutated).hexdigest()
            )

    def test_checked_in_production_policy_is_explicitly_unconfigured(self) -> None:
        with self.assertRaisesRegex(RawArtifactError, "not configured"):
            load_release_trust_policy()


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
