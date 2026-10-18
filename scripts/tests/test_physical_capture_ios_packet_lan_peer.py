from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import unittest

from scripts.harness.raw_artifacts import canonical_json, load_json_bytes
from scripts.physical_capture.ios_packet_lan_peer import (
    CASE_ID,
    EVIDENCE_ROLE,
    LISTENER_PORT,
    READY_DOCUMENT,
    RESULT_DOCUMENT,
    SCHEMA_VERSION,
    STAGES,
    TRANSPORT,
    create_session,
    validate_ready,
    validate_result,
    validate_session,
)
from scripts.physical_capture.ios_transport_peer import (
    BUNDLE_IDENTIFIER,
    IOSPeerContractError,
)


def _canonical(value: object) -> bytes:
    return canonical_json(value) + b"\n"


class IOSPacketLanPeerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 22, 5, 0, tzinfo=timezone.utc)
        self.tokens = (
            "s0123456789abcdef012",
            "t0123456789abcdef012",
            "e0123456789abcdef012",
        )
        self.session_bytes = create_session(tokens=self.tokens, now=self.now)
        self.session = validate_session(self.session_bytes, now=self.now)
        self.ready = {
            "schema_version": SCHEMA_VERSION,
            "document": READY_DOCUMENT,
            "evidence_role": EVIDENCE_ROLE,
            "claim_eligible": False,
            "session_id": self.session["session_id"],
            "bundle_identifier": BUNDLE_IDENTIFIER,
            "process_id": 42,
            "started_at": "2026-08-22T05:00:01.000000Z",
            "expires_at": self.session["expires_at"],
            "network": {"interface_name": "en0", "ipv4": "192.168.1.20"},
            "listener": {"port": LISTENER_PORT, "transport": TRANSPORT},
            "session_file_removed": True,
        }
        self.ready_bytes = _canonical(self.ready)
        self.validated_ready = validate_ready(
            self.ready_bytes,
            session=self.session,
            now=self.now + timedelta(seconds=2),
        )
        self.result = self._closed_result()

    def _closed_result(self) -> dict[str, object]:
        connections = []
        for index, stage in enumerate(STAGES):
            connections.append(
                {
                    "stage": stage,
                    "admission_sequence": index + 1,
                    "token_sha256": hashlib.sha256(
                        self.tokens[index].encode("ascii")
                    ).hexdigest(),
                    "bytes_received": 20,
                    "eof_observed": True,
                    "peer_ipv4": "192.168.1.10",
                    "peer_port": 50_001 + index,
                }
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "document": RESULT_DOCUMENT,
            "evidence_role": EVIDENCE_ROLE,
            "claim_eligible": False,
            "session_id": self.session["session_id"],
            "ready_sha256": hashlib.sha256(self.ready_bytes).hexdigest(),
            "bundle_identifier": BUNDLE_IDENTIFIER,
            "process_id": 42,
            "completed_at": "2026-08-22T05:00:03.000000Z",
            "status": "closed",
            "failure_phase": "none",
            "failure_reason": "none",
            "network": copy.deepcopy(self.ready["network"]),
            "listener": copy.deepcopy(self.ready["listener"]),
            "listener_closed": True,
            "session_file_removed": True,
            "connections": connections,
        }

    def test_session_contains_only_token_digests(self) -> None:
        self.assertEqual(self.session["case_id"], CASE_ID)
        self.assertNotIn(b"s0123456789abcdef012", self.session_bytes)
        self.assertEqual(
            self.session["stage_token_sha256"]["start"],
            hashlib.sha256(self.tokens[0].encode("ascii")).hexdigest(),
        )

    def test_session_rejects_naive_time_and_wrong_stage_token(self) -> None:
        with self.assertRaises(IOSPeerContractError):
            create_session(tokens=self.tokens, now=self.now.replace(tzinfo=None))
        wrong = list(self.tokens)
        wrong[1] = "s1123456789abcdef012"
        with self.assertRaises(IOSPeerContractError):
            create_session(tokens=wrong, now=self.now)

    def test_ready_is_canonical_fresh_and_non_claimable(self) -> None:
        self.assertIs(self.validated_ready["claim_eligible"], False)
        self.assertEqual(self.validated_ready["listener"]["port"], 44_333)

        unknown = copy.deepcopy(self.ready)
        unknown["fallback"] = True
        with self.assertRaises(IOSPeerContractError):
            validate_ready(
                _canonical(unknown),
                session=self.session,
                now=self.now + timedelta(seconds=2),
            )
        generic = copy.deepcopy(self.ready)
        generic["document"] = "cfm-ios-transport-peer-ready-v1"
        with self.assertRaises(IOSPeerContractError):
            validate_ready(
                _canonical(generic),
                session=self.session,
                now=self.now + timedelta(seconds=2),
            )

    def test_closed_result_binds_all_three_server_observations(self) -> None:
        validated = validate_result(
            _canonical(self.result),
            session=self.session,
            ready=self.validated_ready,
        )
        self.assertEqual(validated["status"], "closed")
        self.assertEqual(
            [value["stage"] for value in validated["connections"]],
            list(STAGES),
        )

    def test_result_mutations_fail_closed(self) -> None:
        mutations = []
        for path, value in (
            (("ready_sha256",), "f" * 64),
            (("claim_eligible",), True),
            (("listener_closed",), False),
            (("session_file_removed",), False),
            (("network", "ipv4"), "192.168.1.21"),
            (("listener", "port"), 44_334),
            (("connections", 0, "token_sha256"), "e" * 64),
            (("connections", 0, "bytes_received"), 19),
            (("connections", 0, "eof_observed"), False),
            (("connections", 0, "peer_ipv4"), "203.0.113.10"),
            (("connections", 0, "peer_port"), 4_433),
            (("connections", 1, "stage"), "start"),
            (("connections", 1, "admission_sequence"), 1),
            (("connections", 1, "peer_port"), 50_001),
        ):
            document = copy.deepcopy(self.result)
            target = document
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            mutations.append(document)
        missing = copy.deepcopy(self.result)
        missing["connections"] = missing["connections"][:-1]
        mutations.append(missing)
        extra = copy.deepcopy(self.result)
        extra["connections"].append(copy.deepcopy(extra["connections"][-1]))
        mutations.append(extra)

        for document in mutations:
            with self.subTest(document=document):
                with self.assertRaises(IOSPeerContractError):
                    validate_result(
                        _canonical(document),
                        session=self.session,
                        ready=self.validated_ready,
                    )

    def test_failed_result_requires_typed_phase_and_reason(self) -> None:
        failed = copy.deepcopy(self.result)
        failed["status"] = "failed"
        failed["failure_phase"] = "payload_delivery"
        failed["failure_reason"] = "payload_invalid"
        failed["connections"] = failed["connections"][:1]
        validate_result(
            _canonical(failed),
            session=self.session,
            ready=self.validated_ready,
        )

        failed["failure_phase"] = "connection_admission"
        with self.assertRaises(IOSPeerContractError):
            validate_result(
                _canonical(failed),
                session=self.session,
                ready=self.validated_ready,
            )

    def test_noncanonical_and_duplicate_json_are_rejected(self) -> None:
        noncanonical = self.session_bytes.replace(b'"case_id"', b'"case_id" ')
        with self.assertRaises(IOSPeerContractError):
            validate_session(noncanonical, now=self.now)

        text = self.session_bytes.decode("utf-8")
        duplicate = text.replace(
            '"schema_version":1',
            '"schema_version":1,"schema_version":1',
            1,
        ).encode("utf-8")
        with self.assertRaises(IOSPeerContractError):
            validate_session(duplicate, now=self.now)

        parsed = load_json_bytes(self.session_bytes, "session")
        self.assertEqual(parsed["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
