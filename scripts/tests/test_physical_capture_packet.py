from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.harness import packet_evidence as packet_contract
from scripts.harness.packet_evidence import (
    HOST_SIGNING_IDENTIFIER,
    HOST_TEAM_ID,
    INSTALLED_EXECUTABLE,
    PACKET_OWNER,
    PRODUCT_LOG_CATEGORY,
    PRODUCT_LOG_SUBSYSTEM,
    PRODUCT_OBSERVATION_DOCUMENT,
    PRODUCT_OBSERVATION_PREFIX,
    REQUIRED_CASES,
)
from scripts.harness.raw_artifacts import EVIDENCE_PROFILE, canonical_json
from scripts.physical_capture import observation, packet
from scripts.physical_capture.execution import CommandResult, command_sha256
from scripts.physical_capture.packet import PacketCaptureAdapterError
from scripts.physical_capture.session import CaptureEvent, PhysicalCaptureSession


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class PacketPhysicalCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        (self.repository / "target").mkdir()
        self.session = PhysicalCaptureSession.create(
            self.repository,
            "physical-capture/run-packet",
            intent_sha256=_sha256("intent"),
        )
        self.session.append(
            CaptureEvent.COLLECTION_STARTED,
            binding_sha256=_sha256("collection"),
        )
        self.candidate = {
            "version": "0.4.0",
            "build_number": "40035",
            "app_manifest_sha256": _sha256("app"),
            "signed_app_tree_sha256": _sha256("tree"),
            "artifact_hash_manifest_sha256": _sha256("artifacts"),
            "built_at": "2026-08-01T00:00:00Z",
        }
        self.context = {
            "schema_version": 1,
            "document": "cfw-physical-run-context-v1",
            "evidence_profile_sha256": _sha256("profile"),
            "candidate": copy.deepcopy(self.candidate),
            "run": {
                "os": "current-macos",
                "macos_version": "26.6",
                "macos_build": "25G72",
                "machine_sha256": _sha256("machine"),
                "machine_identity_scheme": EVIDENCE_PROFILE[
                    "machine_identity_scheme"
                ],
                "hardware_model": "Mac16,1",
                "virtualization_present": False,
                "boot_environment_sha256": _sha256("boot"),
                "boot_environment_scheme": EVIDENCE_PROFILE[
                    "boot_environment_scheme"
                ],
                "clean_install": True,
                "run_id": "run-packet",
            },
            "initialized_at": "2026-08-02T00:00:00Z",
        }
        self.now = datetime(2026, 8, 2, 0, 5, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.session.close()
        self.temporary.cleanup()

    def lan_coordinator(self) -> packet._PacketCaseCoordinator:
        return packet._PacketCaseCoordinator(
            session=self.session,
            context=self.context,
            case_id="lan-bypass",
            plan=packet.SOURCE_PINNED_ENDPOINTS["lan-bypass"],
            tokens=("s" * 20, "t" * 20, "e" * 20),
        )

    def test_consumed_ios_close_failure_is_not_replaced_by_a_second_abort(self) -> None:
        class ConsumedFailureLease:
            def __init__(self) -> None:
                self.is_closed = False
                self.abort_calls = 0

            def as_document(self) -> dict[str, object]:
                return {"document": "synthetic-admission"}

            def close_with_receipt(self) -> dict[str, object]:
                self.is_closed = True
                raise packet.ios_packet_lan_peer_adapter.IOSPacketLanPeerError(
                    "synthetic_close_failed", "synthetic terminal cleanup failure"
                )

            def abort(self) -> dict[str, object]:
                self.abort_calls += 1
                raise AssertionError("closed lease must not be aborted again")

        coordinator = self.lan_coordinator()
        lease = ConsumedFailureLease()
        coordinator.runtime.ios_peer_lease = lease
        with self.assertRaises(PacketCaptureAdapterError) as captured:
            coordinator._close_ios_peer()
        self.assertEqual(captured.exception.code, "lan_peer_cleanup_failed")
        self.assertIsNone(coordinator.runtime.ios_peer_lease)
        coordinator.cleanup()
        self.assertEqual(lease.abort_calls, 0)

    def test_unexpected_consumed_ios_close_failure_preserves_the_original_cause(self) -> None:
        failure = OSError("synthetic workspace release failure")

        class ConsumedUnexpectedFailureLease:
            def __init__(self) -> None:
                self.is_closed = False
                self.abort_calls = 0

            def as_document(self) -> dict[str, object]:
                return {"document": "synthetic-admission"}

            def close_with_receipt(self) -> dict[str, object]:
                self.is_closed = True
                raise failure

            def abort(self) -> dict[str, object]:
                self.abort_calls += 1
                raise AssertionError("closed lease must not be aborted again")

        coordinator = self.lan_coordinator()
        lease = ConsumedUnexpectedFailureLease()
        coordinator.runtime.ios_peer_lease = lease
        with self.assertRaises(PacketCaptureAdapterError) as captured:
            coordinator._close_ios_peer()
        self.assertEqual(captured.exception.code, "lan_peer_cleanup_failed")
        self.assertIs(captured.exception.__cause__, failure)
        self.assertIsNone(coordinator.runtime.ios_peer_lease)
        coordinator.cleanup()
        self.assertEqual(lease.abort_calls, 0)

    def test_consumed_ios_abort_failure_is_terminal_for_followup_cleanup(self) -> None:
        class ConsumedAbortFailureLease:
            def __init__(self) -> None:
                self.is_closed = False
                self.abort_calls = 0

            def abort(self) -> dict[str, object]:
                self.abort_calls += 1
                self.is_closed = True
                raise packet.ios_packet_lan_peer_adapter.IOSPacketLanPeerError(
                    "synthetic_abort_failed", "synthetic terminal abort failure"
                )

        coordinator = self.lan_coordinator()
        lease = ConsumedAbortFailureLease()
        coordinator.runtime.ios_peer_lease = lease
        with self.assertRaises(PacketCaptureAdapterError) as captured:
            coordinator.cleanup()
        self.assertEqual(captured.exception.code, "packet_cleanup_failed")
        self.assertIsNone(coordinator.runtime.ios_peer_lease)
        coordinator.cleanup()
        self.assertEqual(lease.abort_calls, 1)

    def event(
        self,
        *,
        case_id: str,
        sequence: int = 7,
        recorded_at: datetime | None = None,
        process_image_path: str = INSTALLED_EXECUTABLE,
    ) -> tuple[dict, dict]:
        when = self.now - timedelta(seconds=1) if recorded_at is None else recorded_at
        off = case_id == "stop-cleanup"
        ipv6_enabled = case_id != "ipv6-disabled-absence" and not off
        state = {
            "desired_mode": "off" if off else "tunnel",
            "generation": 9,
            "config_digest": None if off else _sha256(f"{case_id}-config"),
            "phase": "off" if off else "tunnel_active",
            "owner": None if off else PACKET_OWNER,
            "ready": not off,
            "ipv6_enabled": ipv6_enabled,
        }
        event = {
            "schema_version": 1,
            "document": PRODUCT_OBSERVATION_DOCUMENT,
            "component": "host",
            "event": "engine_snapshot",
            "sequence": sequence,
            "recorded_unix_ms": int(when.timestamp() * 1000),
            "process": {
                "pid": 987,
                "start_unix_ms": int((when - timedelta(hours=1)).timestamp() * 1000),
            },
            "candidate": {
                "version": self.candidate["version"],
                "build_number": self.candidate["build_number"],
            },
            "payload": {"state": state},
        }
        entry = {
            "timestamp": when.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "processImagePath": process_image_path,
            "processID": 987,
            "subsystem": PRODUCT_LOG_SUBSYSTEM,
            "category": PRODUCT_LOG_CATEGORY,
            "eventMessage": PRODUCT_OBSERVATION_PREFIX
            + canonical_json(event).decode("utf-8"),
            "messageType": "Info",
        }
        return event, entry

    def command_result(
        self,
        spec: object,
        *,
        log_entries: list[dict] | None = None,
        codesign_ok: bool = True,
    ) -> CommandResult:
        if spec.role == packet.PRODUCT_QUERY_ROLE:
            stdout = b"".join(
                canonical_json(entry) + b"\n" for entry in (log_entries or [])
            )
            stderr = b""
        else:
            cdhash = _sha256("installed-host")[:40]
            identifier = HOST_SIGNING_IDENTIFIER if codesign_ok else "com.example.other"
            stdout = b""
            stderr = (
                f"Executable={INSTALLED_EXECUTABLE}\n"
                f"Identifier={identifier}\n"
                f"CDHash={cdhash}\n"
                f"TeamIdentifier={HOST_TEAM_ID}\n"
            ).encode("utf-8")
        start_offset = 100 if spec.role == packet.PRODUCT_QUERY_ROLE else 600
        completion_offset = start_offset + 400
        return CommandResult(
            role=spec.role,
            argv_sha256=command_sha256(spec.argv),
            started_at=(self.now + timedelta(milliseconds=start_offset)).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z"),
            completed_at=(self.now + timedelta(milliseconds=completion_offset)).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z"),
            duration_ms=400,
            exit_code=0,
            stdout=stdout,
            stderr=stderr,
        )

    def capture(self, case_id: str, entries: list[dict], *, codesign_ok: bool = True):
        def result(spec):
            return self.command_result(
                spec,
                log_entries=entries,
                codesign_ok=codesign_ok,
            )

        with patch.object(packet, "validate_context", return_value=self.context), patch.object(
            observation, "run_fixed_command", side_effect=result
        ):
            return packet.capture_product_state_observation(
                session=self.session,
                context=self.context,
                case_id=case_id,
                observed_at=self.now,
            )

    def endpoint_policy(self) -> dict[str, packet.PacketEndpointPlan]:
        policy: dict[str, packet.PacketEndpointPlan] = {}
        for index, (case_id, spec) in enumerate(REQUIRED_CASES.items(), start=1):
            if spec.family == "ipv4":
                remote = f"198.51.100.{index}"
                scope = "ipv4-route-interface"
            else:
                remote = f"2001:db8:2::{index}"
                scope = "ipv6-route-interface"
            if spec.protocol == "dns":
                primary = spec.resolver_role == "primary"
                role = "gcp-primary-dns" if primary else "gcp-secondary-dns"
                host = "dns-primary.example" if primary else "dns-secondary.example"
                identity = _sha256("dns-primary" if primary else "dns-secondary")
                capture_location = "remote-server"
                selector = "exact-remote-interface"
                expected_interface = "eth0"
                host_key = _sha256(f"{host}-key")
                remote_identity = identity
                port = packet.PACKET_ENDPOINT_DNS_PORT
                service_id = "dns-primary" if primary else "dns-secondary"
            elif spec.vantage == "lan_segment":
                remote = None
                role = "controlled-lan-peer"
                capture_location = "local-mac"
                selector = "route-selected-lan"
                expected_interface = "non-utun"
                host = host_key = remote_identity = None
                port = packet.PACKET_ENDPOINT_TRANSPORT_PORT
                service_id = (
                    "ios://packet-lan-peer/"
                    f"{packet.SOURCE_IOS_LAN_PEER_IDENTITY.identity_sha256}"
                )
                identity = packet.SOURCE_IOS_LAN_PEER_IDENTITY.identity_sha256
            elif spec.vantage == "direct_wan":
                role = "gcp-direct-wan-target"
                capture_location = "local-mac"
                selector = "route-selected-physical-wan"
                expected_interface = "non-utun"
                host = host_key = remote_identity = None
                port = packet.PACKET_ENDPOINT_TRANSPORT_PORT
                service_id = "gcp-direct-wan-target"
                identity = _sha256(service_id)
            else:
                role = "gcp-dual-stack-transport"
                capture_location = "local-mac"
                selector = "route-selected-tunnel"
                expected_interface = "utun*"
                host = host_key = remote_identity = None
                port = packet.PACKET_ENDPOINT_TRANSPORT_PORT
                service_id = "gcp-dual-stack-transport"
                identity = _sha256(service_id)
            policy[case_id] = packet.PacketEndpointPlan(
                remote_address=remote,
                runtime_endpoint_source=(
                    packet.ios_packet_lan_peer_adapter.READY_DOCUMENT
                    if spec.vantage == "lan_segment"
                    else None
                ),
                remote_port=port,
                local_bind_strategy="route-interface-kernel-ephemeral",
                local_address_scope=scope,
                local_port_min=49152,
                local_port_max=65535,
                vantage=spec.vantage,
                network_role=role,
                endpoint_service_id=service_id,
                endpoint_service_identity_sha256=identity,
                endpoint_binary_sha256=(
                    packet.SOURCE_IOS_LAN_PEER_IDENTITY.executable_sha256
                    if spec.vantage == "lan_segment"
                    else packet.PACKET_ENDPOINT_BINARY_SHA256
                ),
                endpoint_service_unit_sha256=(
                    packet.PACKET_LAN_PEER_NOT_APPLICABLE_SHA256
                    if spec.vantage == "lan_segment"
                    else packet.PACKET_ENDPOINT_SYSTEMD_UNIT_SHA256
                ),
                endpoint_install_script_sha256=(
                    packet.PACKET_LAN_PEER_NOT_APPLICABLE_SHA256
                    if spec.vantage == "lan_segment"
                    else packet.PACKET_ENDPOINT_INSTALL_SCRIPT_SHA256
                ),
                endpoint_resolver_config_sha256=(
                    packet.PACKET_LAN_PEER_NOT_APPLICABLE_SHA256
                    if spec.vantage == "lan_segment"
                    else packet.PACKET_ENDPOINT_RESOLVER_CONFIG_SHA256
                ),
                endpoint_capture_sudoers_sha256=(
                    packet.PACKET_LAN_PEER_NOT_APPLICABLE_SHA256
                    if spec.vantage == "lan_segment"
                    else packet.PACKET_ENDPOINT_CAPTURE_SUDOERS_SHA256
                ),
                capture_location=capture_location,
                interface_selector=selector,
                expected_interface=expected_interface,
                remote_capture_host=host,
                remote_host_key_sha256=host_key,
                remote_server_identity_sha256=remote_identity,
                remote_capture_service_account=(
                    packet.PACKET_CAPTURE_SERVICE_ACCOUNT
                    if spec.protocol == "dns"
                    else None
                ),
                remote_capture_service_account_unique_id=(
                    packet.PACKET_CAPTURE_SERVICE_ACCOUNT_UNIQUE_ID
                    if spec.protocol == "dns"
                    else None
                ),
                remote_capture_os_login_role=(
                    packet.PACKET_CAPTURE_OS_LOGIN_ROLE
                    if spec.protocol == "dns"
                    else None
                ),
                remote_capture_iap_role=(
                    packet.PACKET_CAPTURE_IAP_ROLE
                    if spec.protocol == "dns"
                    else None
                ),
                remote_capture_iap_destination_port=(
                    packet.PACKET_CAPTURE_IAP_DESTINATION_PORT
                    if spec.protocol == "dns"
                    else None
                ),
                remote_capture_internal_ipv4_address=(
                    packet.PACKET_CAPTURE_INTERNAL_IPV4[spec.resolver_role]
                    if spec.protocol == "dns"
                    else None
                ),
            )
        return policy

    def test_latest_signed_host_event_is_archived_as_typed_observation(self) -> None:
        _event, entry = self.event(case_id="tcp-ipv4")
        captured = self.capture("tcp-ipv4", [entry])
        self.assertEqual(captured.generation, 9)
        self.assertEqual(captured.config_digest, _sha256("tcp-ipv4-config"))
        self.assertEqual(
            captured.artifact.descriptor.path,
            "raw/packet/observations/tcp-ipv4-product-state.json",
        )
        retained = json.loads(
            (
                self.repository
                / "target/physical-capture/run-packet"
                / captured.artifact.descriptor.path
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(retained["event"]["payload"]["state"]["owner"], PACKET_OWNER)
        self.assertIn("messageType", retained["query_command"]["stdout"])

    def test_latest_event_cannot_be_skipped_for_an_older_expected_state(self) -> None:
        _expected, expected_entry = self.event(
            case_id="tcp-ipv4", sequence=7, recorded_at=self.now - timedelta(seconds=2)
        )
        wrong_event, wrong_entry = self.event(case_id="stop-cleanup", sequence=8)
        del wrong_event
        with self.assertRaisesRegex(PacketCaptureAdapterError, "latest Host state"):
            self.capture("tcp-ipv4", [expected_entry, wrong_entry])

    def test_wrong_process_or_codesign_identity_fails_closed(self) -> None:
        _event, wrong_path = self.event(
            case_id="tcp-ipv4", process_image_path="/tmp/forged-host"
        )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "no installed Host"):
            self.capture("tcp-ipv4", [wrong_path])
        _event, entry = self.event(case_id="tcp-ipv4")
        with self.assertRaisesRegex(PacketCaptureAdapterError, "code identity"):
            self.capture("tcp-ipv4", [entry], codesign_ok=False)

    def test_postnonce_state_capture_is_rejected_before_command_execution(self) -> None:
        artifact = self.session.observation_capture().write_bytes(
            subject="tcp-ipv4:product-state",
            kind="packet-product-state-observation",
            relative="raw/packet/observations/tcp-ipv4-product-state.json",
            data=b"{}\n",
        )
        self.session.complete_observations(
            {"tcp-ipv4:product-state": artifact.descriptor.as_dict()}
        )
        for event in (
            CaptureEvent.NONCE_REQUEST_PREPARED,
            CaptureEvent.NONCE_ATTEMPT_STARTED,
            CaptureEvent.NONCE_RESPONSE_RECORDED,
        ):
            self.session.append(event, binding_sha256=_sha256(event.value))
        with patch.object(
            observation,
            "run_fixed_command",
            side_effect=AssertionError("postnonce command executed"),
        ) as runner, self.assertRaisesRegex(PacketCaptureAdapterError, "context/session"):
            packet.capture_product_state_observation(
                session=self.session,
                context=self.context,
                case_id="tcp-ipv4",
                observed_at=self.now,
            )
        runner.assert_not_called()

    def test_matrix_remains_fail_closed_for_unresolved_source_controls(self) -> None:
        with patch.object(packet, "validate_context", return_value=self.context):
            with patch.object(packet, "UNRESOLVED_PACKET_CONTROLS", frozenset({"synthetic-control"})):
                with self.assertRaisesRegex(
                    PacketCaptureAdapterError, "unresolved source-owned case/control"
                ):
                    packet.capture_packet_observations(
                        session=self.session,
                        context=self.context,
                    )

    def test_source_policy_binds_declared_gce_and_ios_lan_identities(self) -> None:
        self.assertEqual(
            set(packet.SOURCE_PINNED_ENDPOINTS),
            set(REQUIRED_CASES),
        )
        transport = packet.SOURCE_PINNED_ENDPOINTS["tcp-ipv6"]
        self.assertEqual(transport.remote_address, "2600:1900:4030:5afb::")
        self.assertEqual(transport.remote_port, packet.PACKET_ENDPOINT_TRANSPORT_PORT)
        self.assertEqual(
            transport.endpoint_service_identity_sha256,
            "7e878c338d56a79e69f91d6c8d7091f8f524912c249e69ebb814b4ae91be76fa",
        )
        self.assertEqual(
            transport.endpoint_service_identity_sha256,
            packet_contract.TRANSPORT_ENDPOINT_IDENTITY_SHA256,
        )
        primary = packet.SOURCE_PINNED_ENDPOINTS["dns-a-primary"]
        secondary = packet.SOURCE_PINNED_ENDPOINTS["dns-aaaa-secondary"]
        self.assertEqual(primary.remote_capture_host, "34.80.107.183")
        self.assertEqual(primary.expected_interface, "ens4")
        self.assertEqual(secondary.remote_capture_host, "35.200.12.109")
        self.assertNotEqual(
            primary.endpoint_service_identity_sha256,
            secondary.endpoint_service_identity_sha256,
        )
        self.assertEqual(
            primary.endpoint_service_identity_sha256,
            packet_contract.DNS_REMOTE_CAPTURE_POLICIES["primary"][
                "identity_sha256"
            ],
        )
        self.assertEqual(
            secondary.endpoint_service_identity_sha256,
            packet_contract.DNS_REMOTE_CAPTURE_POLICIES["secondary"][
                "identity_sha256"
            ],
        )
        lan = packet.SOURCE_PINNED_ENDPOINTS["lan-bypass"]
        self.assertIsNone(lan.remote_address)
        self.assertEqual(
            lan.runtime_endpoint_source,
            packet.ios_packet_lan_peer_adapter.READY_DOCUMENT,
        )
        self.assertEqual(
            lan.remote_port, packet.ios_packet_lan_peer_adapter.LISTENER_PORT
        )
        self.assertEqual(
            lan.endpoint_service_identity_sha256,
            packet.SOURCE_IOS_LAN_PEER_IDENTITY.identity_sha256,
        )
        self.assertEqual(
            lan.endpoint_binary_sha256,
            packet.SOURCE_IOS_LAN_PEER_IDENTITY.executable_sha256,
        )

    def test_source_pin_revalidation_rejects_stale_endpoint_artifact(self) -> None:
        stale_policy = self.endpoint_policy()
        stale_policy["tcp-ipv4"] = replace(
            stale_policy["tcp-ipv4"], endpoint_binary_sha256="0" * 64
        )

        with patch.object(packet, "_source_endpoint_policy", return_value=stale_policy):
            with self.assertRaises(PacketCaptureAdapterError) as raised:
                packet._revalidate_source_pins()

        self.assertEqual(
            raised.exception.code, "packet_endpoint_artifact_identity_stale"
        )

    def test_source_policy_rejects_identity_bytes_without_matching_canonical_hash(self) -> None:
        policy = json.loads(packet.ENDPOINT_POLICY_PATH.read_text(encoding="utf-8"))
        policy["identities"][0]["identity"]["instance_id"] = "1"
        tampered = self.repository / "tampered-packet-endpoints.json"
        tampered.write_text(json.dumps(policy), encoding="utf-8")
        with patch.object(packet, "ENDPOINT_POLICY_PATH", tampered), patch.object(
            packet,
            "ENDPOINT_POLICY_SHA256",
            hashlib.sha256(tampered.read_bytes()).hexdigest(),
        ):
            with self.assertRaisesRegex(
                PacketCaptureAdapterError, "canonical instance identity"
            ):
                packet._source_endpoint_policy()

    def test_source_policy_rejects_whole_file_or_known_hosts_drift(self) -> None:
        policy_bytes = packet.ENDPOINT_POLICY_PATH.read_bytes() + b"\n"
        tampered_policy = self.repository / "tampered-packet-endpoints.json"
        tampered_policy.write_bytes(policy_bytes)
        with patch.object(packet, "ENDPOINT_POLICY_PATH", tampered_policy):
            with self.assertRaisesRegex(
                PacketCaptureAdapterError, "unavailable or malformed"
            ):
                packet._source_endpoint_policy()

        known_hosts = self.repository / "packet_known_hosts"
        known_hosts.write_bytes(packet.PACKET_KNOWN_HOSTS_PATH.read_bytes() + b"\n")
        with patch.object(packet, "PACKET_KNOWN_HOSTS_PATH", known_hosts), patch.object(
            packet,
            "PACKET_KNOWN_HOSTS_SHA256",
            hashlib.sha256(known_hosts.read_bytes()).hexdigest(),
        ):
            with self.assertRaisesRegex(
                PacketCaptureAdapterError, "known-hosts policy"
            ):
                packet._source_endpoint_policy()

    def test_endpoint_policy_requires_independent_dns_host_and_identity(self) -> None:
        policy = self.endpoint_policy()
        self.assertEqual(set(packet._validate_endpoint_policy(policy)), set(REQUIRED_CASES))
        primary = policy["dns-a-primary"]
        secondary_cases = ("dns-a-secondary", "dns-aaaa-secondary")

        same_host = copy.deepcopy(policy)
        for case_id in secondary_cases:
            same_host[case_id] = replace(
                same_host[case_id], remote_capture_host=primary.remote_capture_host
            )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "independently identified"):
            packet._validate_endpoint_policy(same_host)

        same_identity = copy.deepcopy(policy)
        for case_id in secondary_cases:
            same_identity[case_id] = replace(
                same_identity[case_id],
                endpoint_service_identity_sha256=primary.endpoint_service_identity_sha256,
                remote_server_identity_sha256=primary.remote_server_identity_sha256,
            )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "independently identified"):
            packet._validate_endpoint_policy(same_identity)

    def test_endpoint_policy_binds_reviewed_binary_unit_and_ports(self) -> None:
        policy = self.endpoint_policy()
        wrong_binary = copy.deepcopy(policy)
        wrong_binary["tcp-ipv4"] = replace(
            wrong_binary["tcp-ipv4"], endpoint_binary_sha256="0" * 64
        )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "contract is invalid"):
            packet._validate_endpoint_policy(wrong_binary)

        wrong_unit = copy.deepcopy(policy)
        wrong_unit["dns-a-primary"] = replace(
            wrong_unit["dns-a-primary"], endpoint_service_unit_sha256="0" * 64
        )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "contract is invalid"):
            packet._validate_endpoint_policy(wrong_unit)

        wrong_installer = copy.deepcopy(policy)
        wrong_installer["dns-a-secondary"] = replace(
            wrong_installer["dns-a-secondary"],
            endpoint_install_script_sha256="0" * 64,
        )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "contract is invalid"):
            packet._validate_endpoint_policy(wrong_installer)

        wrong_resolver = copy.deepcopy(policy)
        wrong_resolver["dns-aaaa-primary"] = replace(
            wrong_resolver["dns-aaaa-primary"],
            endpoint_resolver_config_sha256="0" * 64,
        )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "contract is invalid"):
            packet._validate_endpoint_policy(wrong_resolver)

        wrong_port = copy.deepcopy(policy)
        wrong_port["quic"] = replace(
            wrong_port["quic"], remote_port=443
        )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "transport port"):
            packet._validate_endpoint_policy(wrong_port)

    def test_remote_dns_command_specs_bind_short_lived_os_login_and_iap(self) -> None:
        plan = packet.SOURCE_PINNED_ENDPOINTS["dns-a-primary"]
        key_path = packet._remote_key_path(self.session)
        key_import = packet._remote_key_import_spec(
            self.session,
            plan=plan,
        )
        self.assertEqual(key_import.role, "packet-remote-key-import")
        self.assertIn("--ttl=2m", key_import.argv)
        self.assertIn(f"--key-file={key_path}.pub", key_import.argv)
        self.assertEqual(
            key_import.argv[-1], "--format=value(loginProfile.name)"
        )

        interface = packet._remote_interface_spec(
            self.session,
            plan=plan,
        )
        capture = packet._remote_capture_spec(
            self.session,
            plan=plan,
        )
        for spec in (interface, capture):
            self.assertEqual(spec.argv[0], "/opt/homebrew/bin/gcloud")
            self.assertIn("--plain", spec.argv)
            self.assertIn("--tunnel-through-iap", spec.argv)
            self.assertIn(
                "--impersonate-service-account="
                + packet.PACKET_CAPTURE_SERVICE_ACCOUNT,
                spec.argv,
            )
            self.assertIn("HostKeyAlias=compute.3054958859983781235", spec.argv)
            self.assertIn("StrictHostKeyChecking=yes", spec.argv)
            self.assertIn("/dev/null", spec.argv)
            self.assertIn("ClearAllForwardings=yes", spec.argv)
            self.assertIn("PermitLocalCommand=no", spec.argv)
            self.assertIn("ForwardAgent=no", spec.argv)
            self.assertIn("ForwardX11=no", spec.argv)
            self.assertIn(
                f"UserKnownHostsFile={packet.PACKET_KNOWN_HOSTS_PATH}",
                spec.argv,
            )
            self.assertNotIn("--ssh-key-expire-after=2m", spec.argv)
        self.assertIn(
            "--command=/sbin/ifconfig -v ens4",
            interface.argv,
        )
        self.assertIn(
            "--command=sudo -n /usr/bin/tcpdump -i ens4 -n -U -s 0 "
            "-c 6 -w - udp and port 53",
            capture.argv,
        )

        untrusted = replace(
            plan,
            remote_capture_iap_destination_port=44333,
        )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "instance-scoped"):
            packet._remote_capture_spec(
                self.session,
                plan=untrusted,
            )
        with self.assertRaisesRegex(PacketCaptureAdapterError, "locked physical session"):
            packet._remote_key_path(object())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
