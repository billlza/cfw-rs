from __future__ import annotations

import copy
import hashlib
import json
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


def _pcap_frames(data: bytes) -> list[bytes]:
    frames: list[bytes] = []
    offset = 24
    while offset < len(data):
        _seconds, _micros, captured, _original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        frames.append(data[offset : offset + captured])
        offset += captured
    return frames


def _pcap_frame_offsets(data: bytes) -> list[int]:
    offsets: list[int] = []
    offset = 24
    while offset < len(data):
        _seconds, _micros, captured, _original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        offsets.append(offset)
        offset += captured
    return offsets


def pcapng_bytes(
    start: bytes,
    token: bytes,
    end: bytes,
    *,
    token_in_option: bool = False,
    protocol: str = "tcp",
    family: str = "ipv4",
    local_address: str | None = None,
    remote_address: str | None = None,
    local_port: int = 41000,
    remote_port: int | None = None,
    interface_name: str = "utun5",
) -> bytes:
    section = _block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    name = interface_name.encode("ascii")
    interface_options = struct.pack("<HH", 2, len(name)) + name
    interface_options += b"\x00" * ((4 - len(name) % 4) % 4)
    interface_options += b"\x00\x00\x00\x00"
    interface = _block(1, struct.pack("<HHI", 1, 0, 65535) + interface_options)
    epoch_us = 1_785_153_600 * 1_000_000

    classic = pcap_bytes(
        start_marker=start,
        token=b"metadata-decoy-0001" if token_in_option else token,
        end_marker=end,
        include_token=True,
        protocol=protocol,
        family=family,
        local_address=local_address,
        remote_address=remote_address,
        local_port=local_port,
        remote_port=remote_port,
    )
    frames = _pcap_frames(classic)

    def packet(timestamp: int, frame: bytes, option: bytes = b"") -> bytes:
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

    return (
        section
        + interface
        + packet(epoch_us, frames[0])
        + packet(epoch_us + 1_000_000, frames[1], token if token_in_option else b"")
        + packet(epoch_us + 5_000_000, frames[2])
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

    def capture_arguments(self, case: dict) -> dict:
        provenance = json.loads(
            (self.root / case["provenance_artifact"]["path"]).read_text(encoding="utf-8")
        )
        endpoints = {entry["role"]: entry for entry in provenance["endpoint_set"]}
        return {
            "protocol": case["protocol"],
            "family": case["family"],
            "local_address": endpoints["local"]["address"],
            "remote_address": endpoints["remote"]["address"],
            "local_port": endpoints["local"]["port"],
            "remote_port": endpoints["remote"]["port"],
            "link_type": provenance["interface"]["link_type"],
        }

    def test_complete_capture_set_reopens_and_passes(self) -> None:
        result = self.validate()
        absence_cases = sum(not spec.token_observed for spec in REQUIRED_CASES.values())
        self.assertEqual(len(result["artifacts"]), len(REQUIRED_CASES) * 2 + absence_cases)

    def test_schema_versions_require_json_integers(self) -> None:
        for invalid in (3.0, True):
            with self.subTest(scope="report", invalid=invalid):
                document = copy.deepcopy(self.document)
                document["schema_version"] = invalid
                with self.assertRaisesRegex(PacketEvidenceError, "schema_version must be 3"):
                    self.validate(document)

        case = self.document["cases"][0]
        descriptor = case["provenance_artifact"]
        path = self.root / descriptor["path"]
        original = json.loads(path.read_text(encoding="utf-8"))
        try:
            for invalid in (1.0, True):
                with self.subTest(scope="capture-provenance", invalid=invalid):
                    provenance = copy.deepcopy(original)
                    provenance["schema_version"] = invalid
                    self.fixture.rewrite_json(descriptor, provenance)
                    with self.assertRaisesRegex(
                        PacketEvidenceError, "provenance schema_version must be 1"
                    ):
                        self.validate()
        finally:
            self.fixture.rewrite_json(descriptor, original)

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
            **self.capture_arguments(case),
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

    def test_multiple_pcapng_sections_fail_closed(self) -> None:
        section = pcapng_bytes(
            b"start-marker-0001", b"target-token-0001", b"finish-marker-001"
        )
        with self.assertRaisesRegex(PacketCaptureError, "multiple sections"):
            parse_packet_records(section + section, "packet-pcapng")

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
            interface_name="utun5",
            **{
                key: value
                for key, value in self.capture_arguments(case).items()
                if key != "link_type"
            },
        )
        case["artifact"]["kind"] = "packet-pcapng"
        case["artifact"]["path"] = case["artifact"]["path"].removesuffix(".pcap") + ".pcapng"
        target = self.root / case["artifact"]["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(capture)
        case["artifact"]["size"] = len(capture)
        case["artifact"]["sha256"] = hashlib.sha256(capture).hexdigest()
        with self.assertRaisesRegex(PacketEvidenceError, "unique token is absent"):
            self.validate()

    def test_pcapng_interface_name_must_match_signed_provenance(self) -> None:
        case = self.document["cases"][0]
        arguments = {
            key: value
            for key, value in self.capture_arguments(case).items()
            if key != "link_type"
        }
        capture = pcapng_bytes(
            case["window_start_token"].encode(),
            case["token"].encode(),
            case["window_end_token"].encode(),
            interface_name="en99",
            **arguments,
        )
        case["artifact"]["kind"] = "packet-pcapng"
        case["artifact"]["path"] = case["artifact"]["path"].removesuffix(".pcap") + ".pcapng"
        target = self.root / case["artifact"]["path"]
        target.write_bytes(capture)
        case["artifact"]["size"] = len(capture)
        case["artifact"]["sha256"] = hashlib.sha256(capture).hexdigest()
        with self.assertRaisesRegex(PacketEvidenceError, "interface name differs"):
            self.validate()

    def test_supported_link_types_and_vlan_stacks_are_decoded(self) -> None:
        case = self.document["cases"][0]
        provenance_path = self.root / case["provenance_artifact"]["path"]
        link_contracts = (
            (0, 0),
            (1, 1),
            (1, 2),
            (101, 0),
            (108, 0),
            (113, 0),
            (276, 0),
        )
        for link_type, vlan_tags in link_contracts:
            with self.subTest(link_type=link_type, vlan_tags=vlan_tags):
                arguments = self.capture_arguments(case)
                arguments["link_type"] = link_type
                capture = pcap_bytes(
                    start_marker=case["window_start_token"].encode(),
                    token=case["token"].encode(),
                    end_marker=case["window_end_token"].encode(),
                    include_token=True,
                    vlan_tags=vlan_tags,
                    **arguments,
                )
                self.fixture.rewrite(case["artifact"], capture)
                provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
                provenance["interface"]["link_type"] = link_type
                self.fixture.rewrite_json(case["provenance_artifact"], provenance)
                self.validate()

    def test_invalid_ether_type_fails_closed(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["artifact"]["path"]
        capture = bytearray(path.read_bytes())
        capture[24 + 16 + 12 : 24 + 16 + 14] = b"\x00\x00"
        self.fixture.rewrite(case["artifact"], bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "does not contain IPv4 or IPv6"):
            self.validate()

    def test_fragmented_ipv4_evidence_fails_closed(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["artifact"]["path"]
        capture = bytearray(path.read_bytes())
        flags_offset = 24 + 16 + 14 + 6
        capture[flags_offset : flags_offset + 2] = (0x2000).to_bytes(2, "big")
        self.fixture.rewrite(case["artifact"], bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "fragmented IPv4"):
            self.validate()

    def test_fragmented_ipv6_evidence_fails_closed(self) -> None:
        case = next(item for item in self.document["cases"] if item["id"] == "tcp-ipv6")
        path = self.root / case["artifact"]["path"]
        capture = bytearray(path.read_bytes())
        ipv6_next_header = _pcap_frame_offsets(capture)[0] + 14 + 6
        capture[ipv6_next_header] = 44
        self.fixture.rewrite(case["artifact"], bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "fragmented IPv6"):
            self.validate()

    def test_tcp_data_offset_and_reassembly_gap_fail_closed(self) -> None:
        for defect in ("offset", "gap"):
            with self.subTest(defect=defect):
                case = self.document["cases"][0]
                capture = bytearray(
                    pcap_bytes(
                        start_marker=case["window_start_token"].encode(),
                        token=case["token"].encode(),
                        end_marker=case["window_end_token"].encode(),
                        include_token=True,
                        **self.capture_arguments(case),
                    )
                )
                frames = _pcap_frame_offsets(capture)
                if defect == "offset":
                    capture[frames[0] + 14 + 20 + 12] = 0
                    expected = "TCP data offset"
                else:
                    sequence_offset = frames[1] + 14 + 20 + 4
                    capture[sequence_offset : sequence_offset + 4] = (9000).to_bytes(4, "big")
                    expected = "reassembly gap"
                self.fixture.rewrite(case["artifact"], bytes(capture))
                with self.assertRaisesRegex(PacketEvidenceError, expected):
                    self.validate()

    def test_tcp_token_split_across_contiguous_segments_is_reassembled(self) -> None:
        case = self.document["cases"][0]
        original = pcap_bytes(
            start_marker=case["window_start_token"].encode(),
            token=case["token"].encode(),
            end_marker=case["window_end_token"].encode(),
            include_token=True,
            **self.capture_arguments(case),
        )
        frames = _pcap_frames(original)
        middle = frames[1]
        application_offset = 14 + 20 + 20
        application = middle[application_offset:]
        split = len(application) // 2

        def segment(payload: bytes, sequence_delta: int) -> bytes:
            frame = bytearray(middle[:application_offset] + payload)
            frame[14 + 2 : 14 + 4] = (20 + 20 + len(payload)).to_bytes(2, "big")
            sequence_offset = 14 + 20 + 4
            sequence = int.from_bytes(frame[sequence_offset : sequence_offset + 4], "big")
            frame[sequence_offset : sequence_offset + 4] = (
                sequence + sequence_delta
            ).to_bytes(4, "big")
            return bytes(frame)

        split_frames = (
            frames[0],
            segment(application[:split], 0),
            segment(application[split:], split),
            frames[2],
        )
        timestamps = (1_785_153_600, 1_785_153_601, 1_785_153_602, 1_785_153_605)
        capture = bytearray(original[:24])
        for timestamp, frame in zip(timestamps, split_frames, strict=True):
            capture.extend(struct.pack("<IIII", timestamp, 0, len(frame), len(frame)))
            capture.extend(frame)
        self.fixture.rewrite(case["artifact"], bytes(capture))
        self.validate()

    def test_udp_length_must_bound_application_payload(self) -> None:
        case = next(item for item in self.document["cases"] if item["id"] == "udp")
        path = self.root / case["artifact"]["path"]
        capture = bytearray(path.read_bytes())
        udp_length = _pcap_frame_offsets(capture)[0] + 14 + 20 + 4
        capture[udp_length : udp_length + 2] = (65535).to_bytes(2, "big")
        self.fixture.rewrite(case["artifact"], bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "UDP length"):
            self.validate()

    def test_dns_question_type_must_match_declared_address_family(self) -> None:
        case = next(item for item in self.document["cases"] if item["id"] == "dns-a-primary")
        path = self.root / case["artifact"]["path"]
        capture = bytearray(path.read_bytes())
        suffix = b"\x08evidence\x04test\x00"
        suffix_offset = capture.find(suffix)
        self.assertGreaterEqual(suffix_offset, 0)
        question_type = suffix_offset + len(suffix)
        capture[question_type : question_type + 2] = (28).to_bytes(2, "big")
        self.fixture.rewrite(case["artifact"], bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "required A/AAAA question"):
            self.validate()

    def test_quic_header_contract_fails_closed(self) -> None:
        for defect in ("fixed-bit", "version", "grease-version", "dcid"):
            with self.subTest(defect=defect):
                case = next(item for item in self.document["cases"] if item["id"] == "quic")
                capture = bytearray(
                    pcap_bytes(
                        start_marker=case["window_start_token"].encode(),
                        token=case["token"].encode(),
                        end_marker=case["window_end_token"].encode(),
                        include_token=True,
                        **self.capture_arguments(case),
                    )
                )
                quic = _pcap_frame_offsets(capture)[0] + 14 + 20 + 8
                if defect == "fixed-bit":
                    capture[quic] &= ~0x40
                elif defect == "version":
                    capture[quic + 1 : quic + 5] = b"\x00" * 4
                elif defect == "grease-version":
                    capture[quic + 1 : quic + 5] = (0x0A0A0A0A).to_bytes(4, "big")
                else:
                    capture[quic + 5] = 0
                self.fixture.rewrite(case["artifact"], bytes(capture))
                with self.assertRaisesRegex(PacketEvidenceError, "QUIC"):
                    self.validate()

    def test_quic_capture_version_must_match_signed_provenance(self) -> None:
        case = next(item for item in self.document["cases"] if item["id"] == "quic")
        path = self.root / case["provenance_artifact"]["path"]
        provenance = json.loads(path.read_text(encoding="utf-8"))
        provenance["quic_version"] = 0x6B3343CF
        self.fixture.rewrite_json(case["provenance_artifact"], provenance)
        with self.assertRaisesRegex(PacketEvidenceError, "different QUIC versions"):
            self.validate()

    def test_token_in_ethernet_trailer_does_not_count_as_application_data(self) -> None:
        case = self.document["cases"][0]
        capture = bytearray(
            pcap_bytes(
                start_marker=case["window_start_token"].encode(),
                token=case["token"].encode(),
                end_marker=case["window_end_token"].encode(),
                include_token=False,
                **self.capture_arguments(case),
            )
        )
        first_length = int.from_bytes(capture[32:36], "little")
        first_end = 40 + first_length
        token = case["token"].encode()
        capture[first_end:first_end] = token
        new_length = first_length + len(token)
        capture[32:36] = new_length.to_bytes(4, "little")
        capture[36:40] = new_length.to_bytes(4, "little")
        self.fixture.rewrite(case["artifact"], bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "unique token is absent"):
            self.validate()

    def test_capture_provenance_timestamps_must_be_ordered(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["provenance_artifact"]["path"]
        provenance = json.loads(path.read_text(encoding="utf-8"))
        provenance["signed_at"] = "2026-07-27T11:59:59Z"
        self.fixture.rewrite_json(case["provenance_artifact"], provenance)
        with self.assertRaisesRegex(PacketEvidenceError, "timestamps are reversed"):
            self.validate()

    def test_capture_must_match_both_signed_endpoints(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["provenance_artifact"]["path"]
        provenance = json.loads(path.read_text(encoding="utf-8"))
        provenance["endpoint_set"][0]["address"] = "192.0.2.200"
        self.fixture.rewrite_json(case["provenance_artifact"], provenance)
        with self.assertRaisesRegex(PacketEvidenceError, "signed endpoint tuple"):
            self.validate()

    def test_identical_signed_endpoints_are_rejected(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["provenance_artifact"]["path"]
        provenance = json.loads(path.read_text(encoding="utf-8"))
        remote = provenance["endpoint_set"][1]
        provenance["endpoint_set"][0].update(
            address=remote["address"],
            port=remote["port"],
            transport=remote["transport"],
        )
        self.fixture.rewrite_json(case["provenance_artifact"], provenance)
        with self.assertRaisesRegex(PacketEvidenceError, "local and remote endpoints"):
            self.validate()

    def test_absence_case_requires_successful_bound_send_attempt(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "stop-cleanup"
        )
        original_descriptor = copy.deepcopy(case["attempt_artifact"])
        original_attempt = json.loads(
            (self.root / original_descriptor["path"]).read_text(encoding="utf-8")
        )
        defects = (
            "missing",
            "failed",
            "token",
            "capture-binding",
            "outside-window",
            "recording-causality",
        )
        for defect in defects:
            with self.subTest(defect=defect):
                case["attempt_artifact"] = copy.deepcopy(original_descriptor)
                self.fixture.rewrite_json(
                    case["attempt_artifact"], copy.deepcopy(original_attempt)
                )
                if defect == "missing":
                    case["attempt_artifact"] = None
                    expected = "artifact must be a JSON object"
                else:
                    path = self.root / case["attempt_artifact"]["path"]
                    attempt = json.loads(path.read_text(encoding="utf-8"))
                    if defect == "failed":
                        attempt["exit_code"] = 1
                        expected = "complete token submission"
                    elif defect == "token":
                        attempt["token_sha256"] = "0" * 64
                        expected = "token digest differs"
                    elif defect == "capture-binding":
                        attempt["capture_provenance_sha256"] = "0" * 64
                        expected = "capture-provenance binding differs"
                    elif defect == "outside-window":
                        attempt["started_at"] = "2026-07-27T11:59:58Z"
                        attempt["completed_at"] = "2026-07-27T11:59:59Z"
                        expected = "outside its marker-bounded capture window"
                    else:
                        attempt["recorded_at"] = "2026-07-27T12:00:09Z"
                        expected = "timestamps are not causal"
                    self.fixture.rewrite_json(case["attempt_artifact"], attempt)
                with self.assertRaisesRegex(PacketEvidenceError, expected):
                    self.validate()

    def test_capture_and_send_command_digests_are_not_interchangeable(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "stop-cleanup"
        )
        path = self.root / case["attempt_artifact"]["path"]
        attempt = json.loads(path.read_text(encoding="utf-8"))
        case["send_command_sha256"] = case["capture_command_sha256"]
        attempt["send_command_sha256"] = case["capture_command_sha256"]
        self.fixture.rewrite_json(case["attempt_artifact"], attempt)
        with self.assertRaisesRegex(PacketEvidenceError, "independently bound"):
            self.validate()

    def test_report_capture_command_must_match_signed_provenance(self) -> None:
        case = self.document["cases"][0]
        case["capture_command_sha256"] = "0" * 64
        with self.assertRaisesRegex(PacketEvidenceError, "different capture commands"):
            self.validate()

    def test_quic_tcp_fallback_for_same_endpoint_and_window_fails(self) -> None:
        case = next(item for item in self.document["cases"] if item["id"] == "quic")
        capture = pcap_bytes(
            start_marker=case["window_start_token"].encode(),
            token=case["token"].encode(),
            end_marker=case["window_end_token"].encode(),
            include_token=True,
            include_tcp_fallback=True,
            **self.capture_arguments(case),
        )
        self.fixture.rewrite(case["artifact"], capture)
        with self.assertRaisesRegex(PacketEvidenceError, "TCP fallback"):
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
