from __future__ import annotations

import copy
import struct
import tempfile
import unittest
from pathlib import Path

from scripts.harness.packet_capture import PacketCaptureError, parse_packet_records
from scripts.harness.packet_evidence import (
    REQUIRED_CASES,
    PacketEvidenceError,
    validate_packet_evidence,
)
from scripts.harness.raw_artifacts import ArtifactReader, canonical_json
from scripts.tests.physical_evidence_fixture import (
    PhysicalEvidenceFixture,
    pcap_bytes,
)


def _block(block_type: int, body: bytes) -> bytes:
    if len(body) % 4:
        body += b"\x00" * (4 - len(body) % 4)
    length = len(body) + 12
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def pcapng_bytes(start: bytes, token: bytes, end: bytes, *, token_in_option: bool = False) -> bytes:
    section = _block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    interface = _block(1, struct.pack("<HHI", 1, 0, 65535))
    epoch_us = 1_784_678_400 * 1_000_000

    def packet(timestamp: int, payload: bytes, option: bytes = b"") -> bytes:
        frame = b"\x00" * 14 + payload
        padded = frame + b"\x00" * ((4 - len(frame) % 4) % 4)
        options = b""
        if option:
            options = struct.pack("<HH", 2988, len(option)) + option
            options += b"\x00" * ((4 - len(option) % 4) % 4)
            options += b"\x00\x00\x00\x00"
        body = struct.pack(
            "<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(frame), len(frame)
        )
        return _block(6, body + padded + options)

    middle_option = token if token_in_option else b""
    middle_payload = b"not-the-target" if token_in_option else token
    return (
        section
        + interface
        + packet(epoch_us, start)
        + packet(epoch_us + 1_000_000, middle_payload, middle_option)
        + packet(epoch_us + 5_000_000, end)
    )


class PacketEvidenceHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)
        self.document = self.fixture.report_documents[0]["packet"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self, document: dict | None = None) -> dict:
        with ArtifactReader(self.root) as artifacts:
            return validate_packet_evidence(
                self.document if document is None else document, artifacts
            )

    def test_complete_capture_set_reopens_and_passes(self) -> None:
        result = self.validate()
        self.assertEqual(len(result["artifacts"]), len(REQUIRED_CASES))

    def test_presence_declaration_with_token_absent_fails(self) -> None:
        self.document["cases"][0]["token"] = "different-unique-target-token"
        with self.assertRaisesRegex(PacketEvidenceError, "unique token is absent"):
            self.validate()

    def test_absence_declaration_with_token_present_fails(self) -> None:
        case = next(item for item in self.document["cases"] if item["id"] == "stop-cleanup")
        capture = pcap_bytes(
            start_marker=case["window_start_token"].encode(),
            token=case["token"].encode(),
            end_marker=case["window_end_token"].encode(),
            include_token=True,
        )
        self.fixture.rewrite(case["artifact"], capture)
        with self.assertRaisesRegex(PacketEvidenceError, "forbidden unique token is present"):
            self.validate()

    def test_malformed_pcap_fails_closed(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["artifact"]["path"]
        self.fixture.rewrite(case["artifact"], path.read_bytes()[:-1])
        with self.assertRaisesRegex(PacketEvidenceError, "truncated"):
            self.validate()

    def test_malformed_pcapng_block_fails_closed(self) -> None:
        with self.assertRaises(PacketCaptureError):
            parse_packet_records(b"\x0a\x0d\x0d\x0a" + b"\x00" * 24, "packet-pcapng")

    def test_valid_pcapng_packet_records_parse(self) -> None:
        data = pcapng_bytes(b"start-marker-0001", b"target-token-0001", b"finish-marker-001")
        records = parse_packet_records(data, "packet-pcapng")
        self.assertEqual(len(records), 3)
        self.assertIn(b"target-token-0001", records[1].payload)

    def test_token_in_pcapng_option_metadata_does_not_count(self) -> None:
        case = self.document["cases"][0]
        capture = pcapng_bytes(
            case["window_start_token"].encode(),
            case["token"].encode(),
            case["window_end_token"].encode(),
            token_in_option=True,
        )
        case["artifact"]["kind"] = "packet-pcapng"
        case["artifact"]["path"] = case["artifact"]["path"].removesuffix(".pcap") + ".pcapng"
        target = self.root / case["artifact"]["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(capture)
        case["artifact"]["size"] = len(capture)
        import hashlib

        case["artifact"]["sha256"] = hashlib.sha256(capture).hexdigest()
        with self.assertRaisesRegex(PacketEvidenceError, "unique token is absent"):
            self.validate()

    def test_reused_marker_token_fails_closed(self) -> None:
        self.document["cases"][1]["window_start_token"] = self.document["cases"][0][
            "window_start_token"
        ]
        with self.assertRaisesRegex(PacketEvidenceError, "reused"):
            self.validate()

    def test_server_observation_or_manual_method_field_is_rejected(self) -> None:
        self.document["cases"][0]["method"] = "server_observation"
        with self.assertRaisesRegex(PacketEvidenceError, "unknown fields"):
            self.validate()

    def test_handwritten_random_capture_digest_fails(self) -> None:
        self.document["cases"][0]["artifact"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(PacketEvidenceError, "does not match"):
            self.validate()

    def test_report_is_strict_json_shape(self) -> None:
        value = copy.deepcopy(self.document)
        value["extra"] = canonical_json({}).decode()
        with self.assertRaisesRegex(PacketEvidenceError, "unknown fields"):
            self.validate(value)


if __name__ == "__main__":
    unittest.main()
