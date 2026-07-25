from __future__ import annotations

import copy
import unittest

from scripts.harness.packet_evidence import (
    REQUIRED_CASES,
    PacketEvidenceError,
    validate_packet_evidence,
)


CANDIDATE_MANIFEST = "a" * 64


def fixture() -> dict:
    """A complete, well-bound packet-evidence document across every case."""

    cases = []
    for index, (case_id, spec) in enumerate(REQUIRED_CASES.items()):
        method = "server_observation" if spec.protocol == "dns" else "packet_capture"
        cases.append(
            {
                "id": case_id,
                "protocol": spec.protocol,
                "family": spec.family,
                "resolver_role": spec.resolver_role,
                "token": f"unique-packet-token-{index:03d}",
                "method": method,
                "vantage": spec.vantage,
                "token_observed": spec.token_observed,
                "capture_sha256": f"{index:064x}",
                "observation_ms": 5_000,
                "captured_at": "2026-07-22T00:00:00Z",
                "candidate_app_manifest_sha256": CANDIDATE_MANIFEST,
            }
        )
    return {
        "schema_version": 1,
        "product": {"version": "0.4.0", "build_number": "40000"},
        "candidate": {
            "app_manifest_sha256": CANDIDATE_MANIFEST,
            "signed_app_tree_sha256": "b" * 64,
        },
        "platform": {
            "architecture": "arm64",
            "macos_version": "15.0",
            "hardware_model": "Mac fixture",
            "clean_install": True,
        },
        "captured_at": "2026-07-22T00:00:00Z",
        "cases": cases,
    }


class PacketEvidenceHarnessTests(unittest.TestCase):
    def test_complete_unique_token_captures_pass(self) -> None:
        document = validate_packet_evidence(fixture())
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(len(document["cases"]), len(REQUIRED_CASES))

    def test_all_required_protocols_are_covered(self) -> None:
        # TCPv4/v6, UDP, QUIC, DNS A/AAAA (two roles), LAN, routes, stop, IPv6-off.
        expected = {
            "tcp-ipv4",
            "tcp-ipv6",
            "udp",
            "quic",
            "dns-a-primary",
            "dns-a-secondary",
            "dns-aaaa-primary",
            "dns-aaaa-secondary",
            "lan-bypass",
            "included-routes",
            "excluded-routes",
            "stop-cleanup",
            "ipv6-disabled-absence",
        }
        self.assertEqual(set(REQUIRED_CASES), expected)

    def test_nevpn_status_proof_is_rejected(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["method"] = "nevpn_status"
        with self.assertRaisesRegex(PacketEvidenceError, "nevpn_status"):
            validate_packet_evidence(value)

    def test_interface_presence_proof_is_rejected(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["method"] = "interface_presence"
        with self.assertRaisesRegex(PacketEvidenceError, "interface_presence"):
            validate_packet_evidence(value)

    def test_localhost_control_traffic_proof_is_rejected(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["method"] = "localhost_control_traffic"
        with self.assertRaisesRegex(PacketEvidenceError, "localhost_control_traffic"):
            validate_packet_evidence(value)

    def test_component_log_proof_is_rejected(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["method"] = "component_log"
        with self.assertRaisesRegex(PacketEvidenceError, "component_log"):
            validate_packet_evidence(value)

    def test_loopback_vantage_is_rejected(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["vantage"] = "loopback"
        with self.assertRaisesRegex(PacketEvidenceError, "cannot prove real data-plane egress"):
            validate_packet_evidence(value)

    def test_missing_token_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["token"] = ""
        with self.assertRaisesRegex(PacketEvidenceError, "token is missing or too short"):
            validate_packet_evidence(value)

    def test_reused_token_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][1]["token"] = value["cases"][0]["token"]
        with self.assertRaisesRegex(PacketEvidenceError, "token is reused"):
            validate_packet_evidence(value)

    def test_wrong_candidate_binding_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["candidate_app_manifest_sha256"] = "c" * 64
        with self.assertRaisesRegex(PacketEvidenceError, "different candidate"):
            validate_packet_evidence(value)

    def test_malformed_capture_digest_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["capture_sha256"] = "not-a-sha"
        with self.assertRaisesRegex(PacketEvidenceError, "capture_sha256"):
            validate_packet_evidence(value)

    def test_absent_case_dropped_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        del value["cases"][0]
        with self.assertRaisesRegex(PacketEvidenceError, "each required case exactly once"):
            validate_packet_evidence(value)

    def test_missing_required_case_replaced_by_duplicate_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        # Replace one case with a duplicate of another (count stays correct).
        value["cases"][0] = copy.deepcopy(value["cases"][1])
        value["cases"][0]["token"] = "unique-packet-token-dup"
        with self.assertRaisesRegex(PacketEvidenceError, "duplicated"):
            validate_packet_evidence(value)

    def test_absence_case_claiming_presence_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        for case in value["cases"]:
            if case["id"] == "stop-cleanup":
                case["token_observed"] = True
        with self.assertRaisesRegex(PacketEvidenceError, "absent proof"):
            validate_packet_evidence(value)

    def test_presence_case_claiming_absence_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        for case in value["cases"]:
            if case["id"] == "tcp-ipv4":
                case["token_observed"] = False
        with self.assertRaisesRegex(PacketEvidenceError, "present proof"):
            validate_packet_evidence(value)

    def test_zero_length_observation_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["cases"][0]["observation_ms"] = 0
        with self.assertRaisesRegex(PacketEvidenceError, "observation window is too short"):
            validate_packet_evidence(value)

    def test_non_apple_silicon_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["platform"]["architecture"] = "x86_64"
        with self.assertRaisesRegex(PacketEvidenceError, "clean Apple Silicon"):
            validate_packet_evidence(value)

    def test_wrong_product_version_fails_closed(self) -> None:
        value = copy.deepcopy(fixture())
        value["product"]["version"] = "0.3.0"
        with self.assertRaisesRegex(PacketEvidenceError, "not for version 0.4.0"):
            validate_packet_evidence(value)


if __name__ == "__main__":
    unittest.main()
