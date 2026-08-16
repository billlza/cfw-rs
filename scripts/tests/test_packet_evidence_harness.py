from __future__ import annotations

import copy
import hashlib
import json
import re
import struct
import tempfile
import unittest
from pathlib import Path

from scripts.harness.packet_capture import (
    PacketCaptureError,
    StagedCaptureEndpoint,
    parse_packet_records,
    validate_capture_tokens,
    validate_staged_capture_tokens,
)
from scripts.harness import packet_evidence as packet_contract
from scripts.harness.packet_evidence import (
    REQUIRED_CASES,
    PacketEvidenceError,
    validate_packet_evidence,
)
from scripts.harness.raw_artifacts import ArtifactReader, canonical_json
from scripts.tests.physical_evidence_fixture import (
    FIXTURE_LAN_ENDPOINT_ADDRESS,
    FIXTURE_LAN_ENDPOINT_IDENTITY_SHA256,
    PhysicalEvidenceFixture,
    fixture_packet_policy,
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
    stage_local_addresses: tuple[str, str, str] | None = None,
    remote_address: str | None = None,
    local_port: int = 41000,
    stage_local_ports: tuple[int, int, int] | None = None,
    remote_port: int | None = None,
    link_type: int = 101,
    interface_name: str = "pktap,all",
) -> bytes:
    section = _block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    name = interface_name.encode("ascii")
    interface_options = struct.pack("<HH", 2, len(name)) + name
    interface_options += b"\x00" * ((4 - len(name) % 4) % 4)
    interface_options += b"\x00\x00\x00\x00"
    interface = _block(
        1, struct.pack("<HHI", link_type, 0, 65535) + interface_options
    )
    epoch_us = 1_785_153_600 * 1_000_000

    classic = pcap_bytes(
        start_marker=start,
        token=b"metadata-decoy-0001" if token_in_option else token,
        end_marker=end,
        include_token=True,
        protocol=protocol,
        family=family,
        local_address=local_address,
        stage_local_addresses=stage_local_addresses,
        remote_address=remote_address,
        local_port=local_port,
        stage_local_ports=stage_local_ports,
        remote_port=remote_port,
        link_type=link_type,
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


class PacketFixturePolicyIsolationTests(unittest.TestCase):
    def test_fixture_lan_policy_is_explicit_and_does_not_leak(self) -> None:
        self.assertEqual(packet_contract.LAN_ENDPOINT_ADDRESS, "172.20.10.2")
        self.assertEqual(
            packet_contract.LAN_ENDPOINT_IDENTITY_SHA256,
            "7db9a43d88a58b544b006fba4b7b14f426e122bcc798a81ccb91dce071e77ce3",
        )
        with fixture_packet_policy():
            self.assertEqual(
                packet_contract.LAN_ENDPOINT_ADDRESS,
                FIXTURE_LAN_ENDPOINT_ADDRESS,
            )
            self.assertEqual(
                packet_contract.LAN_ENDPOINT_IDENTITY_SHA256,
                FIXTURE_LAN_ENDPOINT_IDENTITY_SHA256,
            )
        self.assertEqual(packet_contract.LAN_ENDPOINT_ADDRESS, "172.20.10.2")
        self.assertEqual(
            packet_contract.LAN_ENDPOINT_IDENTITY_SHA256,
            "7db9a43d88a58b544b006fba4b7b14f426e122bcc798a81ccb91dce071e77ce3",
        )


class PacketEvidenceHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_context = fixture_packet_policy()
        self.policy_context.__enter__()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = PhysicalEvidenceFixture(self.root)
        self.document = self.fixture.report_documents[0]["packet"]

    def tearDown(self) -> None:
        try:
            self.temporary.cleanup()
        finally:
            self.policy_context.__exit__(None, None, None)

    def validate(self, document: dict | None = None) -> dict:
        with ArtifactReader(self.root) as artifacts:
            return validate_packet_evidence(
                self.document if document is None else document, artifacts
            )

    def capture_arguments(self, case: dict) -> dict:
        attempt = json.loads(
            (self.root / case["attempt_artifact"]["path"]).read_text(
                encoding="utf-8"
            )
        )
        stages = attempt["stages"]
        endpoint_sets = [
            {entry["role"]: entry for entry in stage["endpoint_set"]}
            for stage in stages
        ]
        provenance = json.loads(
            (self.root / case["provenance_artifact"]["path"]).read_text(
                encoding="utf-8"
            )
        )
        return {
            "protocol": case["protocol"],
            "family": case["family"],
            "local_address": endpoint_sets[0]["local"]["address"],
            "stage_local_addresses": tuple(
                endpoints["local"]["address"] for endpoints in endpoint_sets
            ),
            "remote_address": endpoint_sets[0]["remote"]["address"],
            "local_port": endpoint_sets[0]["local"]["port"],
            "stage_local_ports": tuple(
                endpoints["local"]["port"] for endpoints in endpoint_sets
            ),
            "remote_port": endpoint_sets[0]["remote"]["port"],
            "link_type": provenance["capture_device"]["link_type"],
        }

    def rewrite_provenance(self, case: dict, provenance: dict) -> None:
        self.fixture.rewrite_json(case["provenance_artifact"], provenance)
        attempt_path = self.root / case["attempt_artifact"]["path"]
        attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
        attempt["capture_provenance_sha256"] = case["provenance_artifact"][
            "sha256"
        ]
        self.fixture.rewrite_json(case["attempt_artifact"], attempt)

    def rewrite_capture(self, case: dict, capture: bytes) -> None:
        self.fixture.rewrite(case["artifact"], capture)
        self.rebind_capture(case)

    def rewrite_attempt(self, case: dict, attempt: dict) -> None:
        self.fixture.rewrite_json(case["attempt_artifact"], attempt)

    def rewrite_state_and_bind(self, case: dict, observation: dict) -> None:
        self.fixture.rewrite_json(case["state_artifact"], observation)
        provenance_path = self.root / case["provenance_artifact"]["path"]
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        provenance["state_observation_sha256"] = case["state_artifact"]["sha256"]
        self.fixture.rewrite_json(case["provenance_artifact"], provenance)
        attempt_path = self.root / case["attempt_artifact"]["path"]
        attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
        attempt["state_observation_sha256"] = case["state_artifact"]["sha256"]
        attempt["capture_provenance_sha256"] = case["provenance_artifact"][
            "sha256"
        ]
        self.fixture.rewrite_json(case["attempt_artifact"], attempt)

    def rebind_capture(self, case: dict) -> None:
        provenance_path = self.root / case["provenance_artifact"]["path"]
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        provenance["capture_artifact_sha256"] = case["artifact"]["sha256"]
        provenance["capture_command"]["stdout_size"] = case["artifact"]["size"]
        provenance["capture_command"]["stdout_sha256"] = case["artifact"][
            "sha256"
        ]
        case["capture_command_sha256"] = provenance["capture_command"][
            "argv_sha256"
        ]
        self.rewrite_provenance(case, provenance)

    def test_complete_capture_set_reopens_and_passes(self) -> None:
        result = self.validate()
        self.assertEqual(len(result["artifacts"]), len(REQUIRED_CASES) * 4 + 2)

    def test_schema_versions_require_json_integers(self) -> None:
        for invalid in (3.0, True):
            with self.subTest(scope="report", invalid=invalid):
                document = copy.deepcopy(self.document)
                document["schema_version"] = invalid
                with self.assertRaisesRegex(PacketEvidenceError, "schema_version must be 4"):
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
                        PacketEvidenceError, "capture provenance identity differs"
                    ):
                        self.validate()
        finally:
            self.fixture.rewrite_json(descriptor, original)

    def test_presence_declaration_with_token_absent_fails(self) -> None:
        case = self.document["cases"][0]
        capture = pcap_bytes(
            start_marker=case["window_start_token"].encode(),
            token=case["token"].encode(),
            end_marker=case["window_end_token"].encode(),
            include_token=False,
            **self.capture_arguments(case),
        )
        self.rewrite_capture(case, capture)
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
        self.rewrite_capture(case, capture)
        with self.assertRaisesRegex(PacketEvidenceError, "forbidden unique token is present"):
            self.validate()

    def test_malformed_pcap_fails_closed(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["artifact"]["path"]
        self.rewrite_capture(case, path.read_bytes()[:-1])
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
            interface_name="pktap,all",
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
        self.rebind_capture(case)
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
        self.rebind_capture(case)
        with self.assertRaisesRegex(PacketEvidenceError, "interface name differs"):
            self.validate()

    def test_supported_link_types_and_vlan_stacks_are_decoded(self) -> None:
        case = self.document["cases"][0]
        arguments = self.capture_arguments(case)
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
                capture = pcap_bytes(
                    start_marker=case["window_start_token"].encode(),
                    token=case["token"].encode(),
                    end_marker=case["window_end_token"].encode(),
                    include_token=True,
                    protocol=case["protocol"],
                    family=case["family"],
                    local_address=arguments["local_address"],
                    remote_address=arguments["remote_address"],
                    local_port=arguments["local_port"],
                    remote_port=arguments["remote_port"],
                    link_type=link_type,
                    vlan_tags=vlan_tags,
                )
                proof = validate_capture_tokens(
                    capture,
                    "packet-pcap",
                    protocol=case["protocol"],
                    family=case["family"],
                    local_address=arguments["local_address"],
                    local_port=arguments["local_port"],
                    remote_address=arguments["remote_address"],
                    remote_port=arguments["remote_port"],
                    expected_link_type=link_type,
                    expected_interface_name="unused-for-classic-pcap",
                    expected_quic_version=None,
                    token=case["token"].encode(),
                    start_marker=case["window_start_token"].encode(),
                    end_marker=case["window_end_token"].encode(),
                    expect_token=True,
                    declared_observation_ms=5_000,
                )
                self.assertEqual(proof.link_type, link_type)

    def test_raw_capture_invalid_ip_version_fails_closed(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["artifact"]["path"]
        capture = bytearray(path.read_bytes())
        capture[_pcap_frame_offsets(capture)[0]] = 0
        self.rewrite_capture(case, bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "does not contain IPv4 or IPv6"):
            self.validate()

    def test_fragmented_ipv4_evidence_fails_closed(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["artifact"]["path"]
        capture = bytearray(path.read_bytes())
        flags_offset = _pcap_frame_offsets(capture)[0] + 6
        capture[flags_offset : flags_offset + 2] = (0x2000).to_bytes(2, "big")
        self.rewrite_capture(case, bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "fragmented IPv4"):
            self.validate()

    def test_fragmented_ipv6_evidence_fails_closed(self) -> None:
        case = next(item for item in self.document["cases"] if item["id"] == "tcp-ipv6")
        path = self.root / case["artifact"]["path"]
        capture = bytearray(path.read_bytes())
        ipv6_next_header = _pcap_frame_offsets(capture)[0] + 6
        capture[ipv6_next_header] = 44
        self.rewrite_capture(case, bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "fragmented IPv6"):
            self.validate()

    def test_tcp_data_offset_fails_closed(self) -> None:
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
        capture[_pcap_frame_offsets(capture)[0] + 20 + 12] = 0
        self.rewrite_capture(case, bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "TCP data offset"):
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
        application_offset = 20 + 20
        application = middle[application_offset:]
        split = len(application) // 2

        def segment(payload: bytes, sequence_delta: int) -> bytes:
            frame = bytearray(middle[:application_offset] + payload)
            frame[2:4] = (20 + 20 + len(payload)).to_bytes(2, "big")
            sequence_offset = 20 + 4
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
        arguments = self.capture_arguments(case)
        endpoints = tuple(
            StagedCaptureEndpoint(
                stage=stage,
                local_address=arguments["stage_local_addresses"][index],
                local_port=arguments["stage_local_ports"][index],
                remote_address=arguments["remote_address"],
                remote_port=arguments["remote_port"],
            )
            for index, stage in enumerate(("start", "target", "end"))
        )
        proof = validate_staged_capture_tokens(
            bytes(capture),
            case["artifact"]["kind"],
            protocol=case["protocol"],
            family=case["family"],
            endpoints=endpoints,
            expected_link_type=arguments["link_type"],
            expected_interface_name="pktap,all",
            expected_quic_version=None,
            token=case["token"].encode(),
            start_marker=case["window_start_token"].encode(),
            end_marker=case["window_end_token"].encode(),
            expect_token=True,
            declared_observation_ms=5_000,
        )
        self.assertEqual(proof.token_occurrences, 1)
        self.rewrite_capture(case, bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "tcpdump receipt count"):
            self.validate()

        gap_capture = bytearray(capture)
        second_target = _pcap_frame_offsets(gap_capture)[2]
        sequence_offset = second_target + 20 + 4
        sequence = int.from_bytes(
            gap_capture[sequence_offset : sequence_offset + 4], "big"
        )
        gap_capture[sequence_offset : sequence_offset + 4] = (
            sequence + 1
        ).to_bytes(4, "big")
        with self.assertRaisesRegex(PacketCaptureError, "reassembly gap"):
            validate_staged_capture_tokens(
                bytes(gap_capture),
                case["artifact"]["kind"],
                protocol=case["protocol"],
                family=case["family"],
                endpoints=endpoints,
                expected_link_type=arguments["link_type"],
                expected_interface_name="pktap,all",
                expected_quic_version=None,
                token=case["token"].encode(),
                start_marker=case["window_start_token"].encode(),
                end_marker=case["window_end_token"].encode(),
                expect_token=True,
                declared_observation_ms=5_000,
            )

    def test_capture_window_bounds_are_exactly_one_through_thirty_seconds(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "tcp-ipv4"
        )
        arguments = self.capture_arguments(case)
        endpoints = tuple(
            StagedCaptureEndpoint(
                stage=stage,
                local_address=arguments["stage_local_addresses"][index],
                local_port=arguments["stage_local_ports"][index],
                remote_address=arguments["remote_address"],
                remote_port=arguments["remote_port"],
            )
            for index, stage in enumerate(("start", "target", "end"))
        )
        original = pcap_bytes(
            start_marker=case["window_start_token"].encode(),
            token=case["token"].encode(),
            end_marker=case["window_end_token"].encode(),
            include_token=True,
            **arguments,
        )

        def capture_with_window(milliseconds: int) -> bytes:
            capture = bytearray(original)
            offsets = _pcap_frame_offsets(capture)
            start_seconds = struct.unpack_from("<I", capture, offsets[0] - 16)[0]
            seconds, remainder_ms = divmod(milliseconds, 1_000)
            struct.pack_into(
                "<II",
                capture,
                offsets[-1] - 16,
                start_seconds + seconds,
                remainder_ms * 1_000,
            )
            return bytes(capture)

        def validate(milliseconds: int):
            return validate_staged_capture_tokens(
                capture_with_window(milliseconds),
                case["artifact"]["kind"],
                protocol=case["protocol"],
                family=case["family"],
                endpoints=endpoints,
                expected_link_type=arguments["link_type"],
                expected_interface_name="pktap,all",
                expected_quic_version=None,
                token=case["token"].encode(),
                start_marker=case["window_start_token"].encode(),
                end_marker=case["window_end_token"].encode(),
                expect_token=True,
                declared_observation_ms=milliseconds,
            )

        with self.assertRaisesRegex(PacketCaptureError, "outside 1s..30s"):
            validate(999)
        self.assertEqual(validate(1_000).observation_ms, 1_000)
        self.assertEqual(validate(30_000).observation_ms, 30_000)
        with self.assertRaisesRegex(PacketCaptureError, "outside 1s..30s"):
            validate(30_001)

    def test_udp_length_must_bound_application_payload(self) -> None:
        case = next(item for item in self.document["cases"] if item["id"] == "udp")
        path = self.root / case["artifact"]["path"]
        capture = bytearray(path.read_bytes())
        udp_length = _pcap_frame_offsets(capture)[0] + 20 + 4
        capture[udp_length : udp_length + 2] = (65535).to_bytes(2, "big")
        self.rewrite_capture(case, bytes(capture))
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
        self.rewrite_capture(case, bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "required A/AAAA question"):
            self.validate()

    def test_dns_requires_exact_answer_and_sender_pcap_agreement(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "dns-a-primary"
        )
        arguments = self.capture_arguments(case)
        query_only = pcap_bytes(
            start_marker=case["window_start_token"].encode(),
            token=case["token"].encode(),
            end_marker=case["window_end_token"].encode(),
            include_token=True,
            include_dns_responses=False,
            **arguments,
        )
        self.rewrite_capture(case, query_only)
        with self.assertRaisesRegex(PacketEvidenceError, "one query and one"):
            self.validate()

        wrong_answer = bytearray(
            pcap_bytes(
                start_marker=case["window_start_token"].encode(),
                token=case["token"].encode(),
                end_marker=case["window_end_token"].encode(),
                include_token=True,
                **arguments,
            )
        )
        answer = bytes((192, 0, 2, 1))
        answer_offset = wrong_answer.find(answer)
        self.assertGreaterEqual(answer_offset, 0)
        wrong_answer[answer_offset : answer_offset + len(answer)] = bytes((192, 0, 2, 2))
        self.rewrite_capture(case, bytes(wrong_answer))
        with self.assertRaisesRegex(PacketEvidenceError, "answer address"):
            self.validate()

        valid = pcap_bytes(
            start_marker=case["window_start_token"].encode(),
            token=case["token"].encode(),
            end_marker=case["window_end_token"].encode(),
            include_token=True,
            **arguments,
        )
        self.rewrite_capture(case, valid)
        attempt_path = self.root / case["attempt_artifact"]["path"]
        attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
        target_command = attempt["stages"][1]["command"]
        result = json.loads(target_command["stdout"])
        result["dns_result"]["query"]["name"] = "wrong.evidence.test"
        stdout = canonical_json(result).decode("utf-8") + "\n"
        target_command["stdout"] = stdout
        target_command["stdout_size"] = len(stdout.encode("utf-8"))
        target_command["stdout_sha256"] = hashlib.sha256(
            stdout.encode("utf-8")
        ).hexdigest()
        self.rewrite_attempt(case, attempt)
        with self.assertRaisesRegex(PacketEvidenceError, "DNS result differs"):
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
                quic = _pcap_frame_offsets(capture)[0] + 20 + 8
                if defect == "fixed-bit":
                    capture[quic] &= ~0x40
                elif defect == "version":
                    capture[quic + 1 : quic + 5] = b"\x00" * 4
                elif defect == "grease-version":
                    capture[quic + 1 : quic + 5] = (0x0A0A0A0A).to_bytes(4, "big")
                else:
                    capture[quic + 5] = 0
                self.rewrite_capture(case, bytes(capture))
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
        self.rewrite_capture(case, bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "unique token is absent"):
            self.validate()

    def test_capture_provenance_timestamps_must_be_ordered(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["provenance_artifact"]["path"]
        provenance = json.loads(path.read_text(encoding="utf-8"))
        provenance["completed_at"] = "2026-07-27T11:59:59Z"
        self.fixture.rewrite_json(case["provenance_artifact"], provenance)
        with self.assertRaisesRegex(PacketEvidenceError, "capture timeline is not causal"):
            self.validate()

    def test_target_packet_must_fall_inside_the_retained_target_send(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "tcp-ipv4"
        )
        capture = bytearray((self.root / case["artifact"]["path"]).read_bytes())
        frame_offsets = _pcap_frame_offsets(capture)
        first_header = frame_offsets[0] - 16
        target_header = frame_offsets[1] - 16
        start_seconds = struct.unpack_from("<I", capture, first_header)[0]
        struct.pack_into("<II", capture, target_header, start_seconds, 500_000)
        self.rewrite_capture(case, bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "retained target send"):
            self.validate()

    def test_dns_query_and_response_must_both_fall_inside_the_stage_send(self) -> None:
        case = next(
            item
            for item in self.document["cases"]
            if item["id"] == "dns-a-primary"
        )
        capture = bytearray((self.root / case["artifact"]["path"]).read_bytes())
        first_header = _pcap_frame_offsets(capture)[0] - 16
        seconds = struct.unpack_from("<I", capture, first_header)[0]
        struct.pack_into("<II", capture, first_header, seconds - 1, 0)
        self.rewrite_capture(case, bytes(capture))
        with self.assertRaisesRegex(PacketEvidenceError, "marker packets"):
            self.validate()

    def test_capture_record_count_must_match_the_fixed_tcpdump_receipt(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "tcp-ipv4"
        )
        original = (self.root / case["artifact"]["path"]).read_bytes()
        frames = _pcap_frames(original)
        frame_offsets = _pcap_frame_offsets(original)
        end_header = frame_offsets[-1] - 16
        end_seconds = struct.unpack_from("<I", original, end_header)[0]
        extra = bytearray(original)
        extra.extend(
            struct.pack(
                "<IIII", end_seconds + 1, 0, len(frames[1]), len(frames[1])
            )
        )
        extra.extend(frames[1])
        self.rewrite_capture(case, bytes(extra))
        with self.assertRaisesRegex(PacketEvidenceError, "tcpdump receipt count"):
            self.validate()

    def test_capture_must_match_both_signed_endpoints(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["attempt_artifact"]["path"]
        attempt = json.loads(path.read_text(encoding="utf-8"))
        attempt["stages"][0]["endpoint_set"][0]["address"] = "192.0.2.200"
        self.rewrite_attempt(case, attempt)
        with self.assertRaisesRegex(PacketEvidenceError, "local address differs"):
            self.validate()

    def test_identical_signed_endpoints_are_rejected(self) -> None:
        case = self.document["cases"][0]
        path = self.root / case["attempt_artifact"]["path"]
        attempt = json.loads(path.read_text(encoding="utf-8"))
        endpoints = attempt["stages"][0]["endpoint_set"]
        remote = endpoints[1]
        endpoints[0].update(
            address=remote["address"],
            port=remote["port"],
            transport=remote["transport"],
        )
        self.rewrite_attempt(case, attempt)
        with self.assertRaisesRegex(PacketEvidenceError, "local endpoint is invalid"):
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
                attempt = copy.deepcopy(original_attempt)
                self.rewrite_attempt(case, attempt)
                if defect == "missing":
                    case["attempt_artifact"] = None
                    expected = "artifact must be a JSON object"
                else:
                    if defect == "failed":
                        attempt["stages"][1]["command"]["exit_code"] = 1
                        expected = "did not complete successfully"
                    elif defect == "token":
                        attempt["stages"][1]["token_sha256"] = "0" * 64
                        expected = "target stage identity differs"
                    elif defect == "capture-binding":
                        attempt["capture_provenance_sha256"] = "0" * 64
                        expected = "identity/binding differs"
                    elif defect == "outside-window":
                        command = attempt["stages"][0]["command"]
                        command["started_at"] = "2026-07-27T12:00:00.300Z"
                        command["completed_at"] = "2026-07-27T12:00:00.600Z"
                        command["duration_ms"] = 300
                        expected = "marker packets"
                    else:
                        attempt["recorded_at"] = "2026-07-27T12:00:05.100Z"
                        expected = "send attempt recording is not causal"
                    self.rewrite_attempt(case, attempt)
                with self.assertRaisesRegex(PacketEvidenceError, expected):
                    self.validate()

    def test_capture_and_send_command_digests_are_not_interchangeable(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "stop-cleanup"
        )
        case["send_command_sha256"] = case["capture_command_sha256"]
        with self.assertRaisesRegex(PacketEvidenceError, "independently bound"):
            self.validate()

    def test_report_capture_command_must_match_signed_provenance(self) -> None:
        case = self.document["cases"][0]
        case["capture_command_sha256"] = "0" * 64
        with self.assertRaisesRegex(PacketEvidenceError, "different capture commands"):
            self.validate()

    def test_every_case_requires_a_typed_product_state_observation(self) -> None:
        case = self.document["cases"][0]
        case["state_artifact"] = None
        with self.assertRaisesRegex(PacketEvidenceError, "artifact must be a JSON object"):
            self.validate()

    def test_product_state_cannot_be_tampered_or_replaced_by_a_declaration(self) -> None:
        case = self.document["cases"][0]
        descriptor = case["state_artifact"]
        original = json.loads(
            (self.root / descriptor["path"]).read_text(encoding="utf-8")
        )
        defects = (
            ("phase", "proxy_active"),
            ("generation", 0),
            ("config_digest", None),
            ("owner", None),
            ("ready", False),
            ("ipv6_enabled", False),
        )
        for field, replacement in defects:
            with self.subTest(field=field):
                observation = copy.deepcopy(original)
                observation["event"]["payload"]["state"][field] = replacement
                event = observation["event"]
                observation["log_entry"]["eventMessage"] = (
                    "cfw-release-observation-v1 "
                    + canonical_json(event).decode("utf-8")
                )
                observation["query_command"]["stdout"] = (
                    canonical_json(observation["log_entry"]).decode("utf-8") + "\n"
                )
                stdout = observation["query_command"]["stdout"].encode("utf-8")
                observation["query_command"]["stdout_size"] = len(stdout)
                observation["query_command"]["stdout_sha256"] = hashlib.sha256(
                    stdout
                ).hexdigest()
                self.fixture.rewrite_json(descriptor, observation)
                with self.assertRaises(PacketEvidenceError):
                    self.validate()
        self.fixture.rewrite_json(descriptor, original)

    def test_product_query_requires_object_ndjson_and_the_unique_latest_event(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "tcp-ipv4"
        )
        descriptor = case["state_artifact"]
        original = json.loads(
            (self.root / descriptor["path"]).read_text(encoding="utf-8")
        )
        try:
            duplicate_key = copy.deepcopy(original)
            query = duplicate_key["query_command"]
            query["stdout"] = query["stdout"].replace(
                '{"category":', '{"processID":4242,"category":', 1
            )
            stdout = query["stdout"].encode("utf-8")
            query["stdout_size"] = len(stdout)
            query["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
            self.rewrite_state_and_bind(case, duplicate_key)
            with self.assertRaisesRegex(PacketEvidenceError, "strict NDJSON"):
                self.validate()

            non_object = copy.deepcopy(original)
            query = non_object["query_command"]
            query["stdout"] += "42\n"
            stdout = query["stdout"].encode("utf-8")
            query["stdout_size"] = len(stdout)
            query["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
            self.rewrite_state_and_bind(case, non_object)
            with self.assertRaisesRegex(PacketEvidenceError, "strict NDJSON"):
                self.validate()

            numeric_alias = copy.deepcopy(original)
            query = numeric_alias["query_command"]
            entry = json.loads(query["stdout"])
            entry["processID"] = float(entry["processID"])
            query["stdout"] = canonical_json(entry).decode("utf-8") + "\n"
            stdout = query["stdout"].encode("utf-8")
            query["stdout_size"] = len(stdout)
            query["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
            self.rewrite_state_and_bind(case, numeric_alias)
            with self.assertRaisesRegex(PacketEvidenceError, "unique latest"):
                self.validate()

            stale = copy.deepcopy(original)
            newer_event = copy.deepcopy(stale["event"])
            newer_event["sequence"] += 1
            newer_event["recorded_unix_ms"] += 100
            newer_event["payload"]["state"]["generation"] += 1
            newer_entry = copy.deepcopy(stale["log_entry"])
            newer_entry["timestamp"] = "2026-07-27T11:59:58.600000Z"
            newer_entry["eventMessage"] = (
                "cfw-release-observation-v1 "
                + canonical_json(newer_event).decode("utf-8")
            )
            query = stale["query_command"]
            query["stdout"] += canonical_json(newer_entry).decode("utf-8") + "\n"
            stdout = query["stdout"].encode("utf-8")
            query["stdout_size"] = len(stdout)
            query["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
            self.rewrite_state_and_bind(case, stale)
            with self.assertRaisesRegex(PacketEvidenceError, "unique latest"):
                self.validate()
        finally:
            self.rewrite_state_and_bind(case, original)

    def test_codesign_identity_is_unique_and_follows_the_product_query(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "tcp-ipv4"
        )
        descriptor = case["state_artifact"]
        original = json.loads(
            (self.root / descriptor["path"]).read_text(encoding="utf-8")
        )
        try:
            ambiguous = copy.deepcopy(original)
            codesign = ambiguous["codesign_command"]
            codesign["stderr"] += f"CDHash={'0' * 40}\n"
            stderr = codesign["stderr"].encode("utf-8")
            codesign["stderr_size"] = len(stderr)
            codesign["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
            self.rewrite_state_and_bind(case, ambiguous)
            with self.assertRaisesRegex(PacketEvidenceError, "installed Host identity"):
                self.validate()

            stale = copy.deepcopy(original)
            codesign = stale["codesign_command"]
            codesign["started_at"] = "2026-07-27T11:59:58.100000Z"
            codesign["completed_at"] = "2026-07-27T11:59:58.200000Z"
            codesign["duration_ms"] = 100
            self.rewrite_state_and_bind(case, stale)
            with self.assertRaisesRegex(PacketEvidenceError, "predates its product query"):
                self.validate()
        finally:
            self.rewrite_state_and_bind(case, original)

    def test_missing_os_capture_or_send_step_fails_closed(self) -> None:
        case = self.document["cases"][0]
        provenance_descriptor = case["provenance_artifact"]
        provenance = json.loads(
            (self.root / provenance_descriptor["path"]).read_text(encoding="utf-8")
        )
        for field in (
            "capture_device",
            "host_transaction",
            "remote_key_generation_command",
            "remote_public_key_command",
            "remote_key_import_command",
            "remote_interface",
            "remote_interface_command",
            "capture_command",
        ):
            with self.subTest(scope="provenance", field=field):
                mutated = copy.deepcopy(provenance)
                del mutated[field]
                self.fixture.rewrite_json(provenance_descriptor, mutated)
                with self.assertRaisesRegex(PacketEvidenceError, "missing required fields"):
                    self.validate()

        self.fixture.rewrite_json(provenance_descriptor, provenance)

        attempt_descriptor = case["attempt_artifact"]
        attempt = json.loads(
            (self.root / attempt_descriptor["path"]).read_text(encoding="utf-8")
        )
        for field in ("route_command", "interface_command", "interface", "command"):
            with self.subTest(scope="stage", field=field):
                mutated = copy.deepcopy(attempt)
                del mutated["stages"][0][field]
                self.fixture.rewrite_json(attempt_descriptor, mutated)
                with self.assertRaisesRegex(PacketEvidenceError, "missing required fields"):
                    self.validate()

    def test_host_transaction_snapshots_require_exact_types_and_ready_baseline(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "tcp-ipv4"
        )
        descriptor = case["provenance_artifact"]
        original = json.loads(
            (self.root / descriptor["path"]).read_text(encoding="utf-8")
        )
        test_generation = original["host_transaction"]["test"]["generation"]
        defects = (
            ("generation", test_generation - 0.5, test_generation + 0.5),
            ("desired_mode", 123, 123),
            ("phase", ["tunnel_active"], ["tunnel_active"]),
            ("ready", 1, 1),
            ("ipv6_enabled", "yes", "yes"),
            ("owner", {"role": "packet"}, {"role": "packet"}),
            ("config_digest", False, False),
            ("ipv6_enabled", False, False),
        )
        try:
            for field, baseline_value, restore_value in defects:
                with self.subTest(field=field, replacement=baseline_value):
                    provenance = copy.deepcopy(original)
                    provenance["host_transaction"]["baseline"][field] = baseline_value
                    provenance["host_transaction"]["restore"][field] = restore_value
                    self.rewrite_provenance(case, provenance)
                    with self.assertRaises(PacketEvidenceError):
                        self.validate()
        finally:
            self.rewrite_provenance(case, original)

    def test_host_transaction_session_ids_are_unique_across_cases(self) -> None:
        first, second = self.document["cases"][:2]
        first_provenance = json.loads(
            (self.root / first["provenance_artifact"]["path"]).read_text(
                encoding="utf-8"
            )
        )
        second_descriptor = second["provenance_artifact"]
        original = json.loads(
            (self.root / second_descriptor["path"]).read_text(encoding="utf-8")
        )
        try:
            replayed = copy.deepcopy(original)
            replayed["host_transaction"]["session_id"] = first_provenance[
                "host_transaction"
            ]["session_id"]
            self.rewrite_provenance(second, replayed)
            with self.assertRaisesRegex(PacketEvidenceError, "reuse one Host"):
                self.validate()
        finally:
            self.rewrite_provenance(second, original)

    def test_sender_results_require_exact_json_numeric_types(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "tcp-ipv4"
        )
        descriptor = case["attempt_artifact"]
        original = json.loads(
            (self.root / descriptor["path"]).read_text(encoding="utf-8")
        )
        try:
            for field in (
                "schema_version",
                "bytes_submitted",
                "local_port",
                "remote_port",
            ):
                with self.subTest(field=field):
                    attempt = copy.deepcopy(original)
                    command = attempt["stages"][0]["command"]
                    result = json.loads(command["stdout"])
                    result[field] = float(result[field])
                    stdout = canonical_json(result).decode("utf-8") + "\n"
                    command["stdout"] = stdout
                    command["stdout_size"] = len(stdout.encode("utf-8"))
                    command["stdout_sha256"] = hashlib.sha256(
                        stdout.encode("utf-8")
                    ).hexdigest()
                    self.rewrite_attempt(case, attempt)
                    with self.assertRaisesRegex(
                        PacketEvidenceError, "non-exact numeric types"
                    ):
                        self.validate()
            duplicate_key = copy.deepcopy(original)
            command = duplicate_key["stages"][0]["command"]
            command["stdout"] = command["stdout"].replace(
                '{"bytes_submitted":',
                '{"schema_version":2,"bytes_submitted":',
                1,
            )
            stdout = command["stdout"].encode("utf-8")
            command["stdout_size"] = len(stdout)
            command["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
            self.rewrite_attempt(case, duplicate_key)
            with self.assertRaisesRegex(PacketEvidenceError, "send result is not JSON"):
                self.validate()
        finally:
            self.rewrite_attempt(case, original)

    def test_capture_device_link_type_requires_an_exact_json_integer(self) -> None:
        cases = (
            ("tcp-ipv4", 101.0),
            ("dns-a-primary", True),
        )
        for case_id, replacement in cases:
            with self.subTest(case_id=case_id, replacement=replacement):
                case = next(
                    item for item in self.document["cases"] if item["id"] == case_id
                )
                descriptor = case["provenance_artifact"]
                original = json.loads(
                    (self.root / descriptor["path"]).read_text(encoding="utf-8")
                )
                try:
                    provenance = copy.deepcopy(original)
                    provenance["capture_device"]["link_type"] = replacement
                    self.rewrite_provenance(case, provenance)
                    with self.assertRaisesRegex(
                        PacketEvidenceError, "non-exact field types"
                    ):
                        self.validate()
                finally:
                    self.rewrite_provenance(case, original)

    def test_remote_interface_output_must_bind_the_declared_kernel_index(self) -> None:
        case = next(
            item
            for item in self.document["cases"]
            if item["id"] == "dns-a-primary"
        )
        descriptor = case["provenance_artifact"]
        original = json.loads(
            (self.root / descriptor["path"]).read_text(encoding="utf-8")
        )
        try:
            provenance = copy.deepcopy(original)
            command = provenance["remote_interface_command"]
            command["stdout"] = re.sub(
                r" index [0-9]+(?=\s|$)", "", command["stdout"], count=1
            )
            stdout = command["stdout"].encode("utf-8")
            command["stdout_size"] = len(stdout)
            command["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
            self.rewrite_provenance(case, provenance)
            with self.assertRaisesRegex(PacketEvidenceError, "output differs"):
                self.validate()
        finally:
            self.rewrite_provenance(case, original)

    def test_stage_route_observations_are_causal_and_nonoverlapping(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "tcp-ipv4"
        )
        descriptor = case["attempt_artifact"]
        original = json.loads(
            (self.root / descriptor["path"]).read_text(encoding="utf-8")
        )
        try:
            stale = copy.deepcopy(original)
            stale_route = stale["stages"][0]["route_command"]
            stale_interface = stale["stages"][0]["interface_command"]
            stale_route["started_at"] = "2026-07-27T11:59:58.000000Z"
            stale_route["completed_at"] = "2026-07-27T11:59:58.100000Z"
            stale_interface["started_at"] = "2026-07-27T11:59:58.100000Z"
            stale_interface["completed_at"] = "2026-07-27T11:59:58.200000Z"
            self.rewrite_attempt(case, stale)
            with self.assertRaises(PacketEvidenceError):
                self.validate()

            overlap = copy.deepcopy(original)
            target_route = overlap["stages"][1]["route_command"]
            target_interface = overlap["stages"][1]["interface_command"]
            target_route["started_at"] = "2026-07-27T12:00:00.150000Z"
            target_route["completed_at"] = "2026-07-27T12:00:00.250000Z"
            target_interface["started_at"] = "2026-07-27T12:00:00.250000Z"
            target_interface["completed_at"] = "2026-07-27T12:00:00.350000Z"
            self.rewrite_attempt(case, overlap)
            with self.assertRaisesRegex(PacketEvidenceError, "sender stages overlap"):
                self.validate()
        finally:
            self.rewrite_attempt(case, original)

    def test_remote_dns_capture_identity_and_authentication_are_source_pinned(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "dns-a-primary"
        )
        descriptor = case["provenance_artifact"]
        original = json.loads(
            (self.root / descriptor["path"]).read_text(encoding="utf-8")
        )
        defects = (
            ("endpoint", "endpoint_identity_sha256", "0" * 64),
            ("host-key", "host_key_bytes_sha256", "0" * 64),
            ("service-account", "service_account", "capture@example.invalid"),
            ("internal-ip", "internal_ip_address", "10.42.40.99"),
            ("known-hosts", "known_hosts_snapshot_sha256", "0" * 64),
            ("sudoers", "sudoers_policy_sha256", "0" * 64),
        )
        try:
            for defect, field, replacement in defects:
                with self.subTest(defect=defect):
                    provenance = copy.deepcopy(original)
                    if defect == "endpoint":
                        provenance[field] = replacement
                    else:
                        provenance["remote_access"][field] = replacement
                    self.rewrite_provenance(case, provenance)
                    with self.assertRaises(PacketEvidenceError):
                        self.validate()
        finally:
            self.rewrite_provenance(case, original)

    def test_remote_dns_key_import_capture_and_binary_receipts_fail_closed(self) -> None:
        case = next(
            item for item in self.document["cases"] if item["id"] == "dns-a-primary"
        )
        descriptor = case["provenance_artifact"]
        original = json.loads(
            (self.root / descriptor["path"]).read_text(encoding="utf-8")
        )
        try:
            key_import = copy.deepcopy(original)
            argv = key_import["remote_key_import_command"]["argv"]
            argv[argv.index("--ttl=2m")] = "--ttl=5m"
            key_import["remote_key_import_command"]["argv_sha256"] = hashlib.sha256(
                canonical_json(argv)
            ).hexdigest()
            self.rewrite_provenance(case, key_import)
            with self.assertRaisesRegex(PacketEvidenceError, "OS Login key import differs"):
                self.validate()

            count = copy.deepcopy(original)
            argv = count["capture_command"]["argv"]
            command_index = next(
                index
                for index, argument in enumerate(argv)
                if argument.startswith("--command=")
            )
            argv[command_index] = argv[command_index].replace("-c 6", "-c 5")
            count["capture_command"]["argv_sha256"] = hashlib.sha256(
                canonical_json(argv)
            ).hexdigest()
            self.rewrite_provenance(case, count)
            with self.assertRaisesRegex(PacketEvidenceError, "remote capture command differs"):
                self.validate()

            binary = copy.deepcopy(original)
            binary["capture_command"]["stdout_sha256"] = "0" * 64
            self.rewrite_provenance(case, binary)
            with self.assertRaisesRegex(PacketEvidenceError, "exact binary artifact"):
                self.validate()

            diagnostic = copy.deepcopy(original)
            diagnostic["capture_command"]["stderr"] += "unexpected warning\n"
            stderr = diagnostic["capture_command"]["stderr"].encode("utf-8")
            diagnostic["capture_command"]["stderr_size"] = len(stderr)
            diagnostic["capture_command"]["stderr_sha256"] = hashlib.sha256(
                stderr
            ).hexdigest()
            self.rewrite_provenance(case, diagnostic)
            with self.assertRaisesRegex(PacketEvidenceError, "remote capture command differs"):
                self.validate()
        finally:
            self.rewrite_provenance(case, original)

    def test_local_capture_rejects_remote_access_and_offload_declarations(self) -> None:
        local_case = next(
            item for item in self.document["cases"] if item["id"] == "tcp-ipv4"
        )
        dns_case = next(
            item for item in self.document["cases"] if item["id"] == "dns-a-primary"
        )
        local_descriptor = local_case["provenance_artifact"]
        local = json.loads(
            (self.root / local_descriptor["path"]).read_text(encoding="utf-8")
        )
        dns = json.loads(
            (self.root / dns_case["provenance_artifact"]["path"]).read_text(
                encoding="utf-8"
            )
        )
        original = copy.deepcopy(local)
        try:
            local["remote_access"] = dns["remote_access"]
            local["remote_key_generation_command"] = dns[
                "remote_key_generation_command"
            ]
            local["remote_public_key_command"] = dns["remote_public_key_command"]
            local["remote_key_import_command"] = dns["remote_key_import_command"]
            local["remote_interface"] = dns["remote_interface"]
            local["remote_interface_command"] = dns["remote_interface_command"]
            local["capture_offload_context"] = dns["capture_offload_context"]
            self.rewrite_provenance(local_case, local)
            with self.assertRaisesRegex(PacketEvidenceError, "local capture"):
                self.validate()
        finally:
            self.rewrite_provenance(local_case, original)

    def test_absence_requires_exact_state_and_bounded_causal_window(self) -> None:
        def rewrite_state(descriptor: dict, observation: dict) -> None:
            observation["log_entry"]["eventMessage"] = (
                "cfw-release-observation-v1 "
                + canonical_json(observation["event"]).decode("utf-8")
            )
            observation["query_command"]["stdout"] = (
                canonical_json(observation["log_entry"]).decode("utf-8") + "\n"
            )
            stdout = observation["query_command"]["stdout"].encode("utf-8")
            observation["query_command"]["stdout_size"] = len(stdout)
            observation["query_command"]["stdout_sha256"] = hashlib.sha256(
                stdout
            ).hexdigest()
            self.fixture.rewrite_json(descriptor, observation)

        stop = next(
            case for case in self.document["cases"] if case["id"] == "stop-cleanup"
        )
        original_stop_state = json.loads(
            (self.root / stop["state_artifact"]["path"]).read_text(encoding="utf-8")
        )
        stop_state = copy.deepcopy(original_stop_state)
        stop_state["event"]["payload"]["state"]["desired_mode"] = "tunnel"
        rewrite_state(stop["state_artifact"], stop_state)
        with self.assertRaisesRegex(PacketEvidenceError, "exact case"):
            self.validate()
        rewrite_state(stop["state_artifact"], original_stop_state)

        disabled = next(
            case
            for case in self.document["cases"]
            if case["id"] == "ipv6-disabled-absence"
        )
        original_disabled_state = json.loads(
            (self.root / disabled["state_artifact"]["path"]).read_text(
                encoding="utf-8"
            )
        )
        disabled_state = copy.deepcopy(original_disabled_state)
        disabled_state["event"]["payload"]["state"]["ipv6_enabled"] = True
        rewrite_state(disabled["state_artifact"], disabled_state)
        with self.assertRaisesRegex(PacketEvidenceError, "exact case"):
            self.validate()
        rewrite_state(disabled["state_artifact"], original_disabled_state)

        stop["observation_ms"] = 30_001
        with self.assertRaisesRegex(PacketEvidenceError, "fixed bound"):
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
        self.rewrite_capture(case, capture)
        with self.assertRaisesRegex(PacketEvidenceError, "transport fallback"):
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
