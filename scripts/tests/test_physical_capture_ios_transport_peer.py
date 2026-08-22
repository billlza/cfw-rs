from __future__ import annotations

import hashlib
import json
import plistlib
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.harness.raw_artifacts import canonical_json
from scripts.physical_capture.ios_packet_lan_peer import (
    DEVICE_DIRECTORY as PACKET_LAN_DEVICE_DIRECTORY,
    DIRECTORY_NAME as PACKET_LAN_DIRECTORY_NAME,
    LAUNCH_ARGUMENT as PACKET_LAN_LAUNCH_ARGUMENT,
    READY_FILE_NAME as PACKET_LAN_READY_FILE_NAME,
    RESULT_FILE_NAME as PACKET_LAN_RESULT_FILE_NAME,
)
from scripts.physical_capture.ios_transport_peer import (
    APP_EXECUTABLE,
    BUNDLE_IDENTIFIER,
    PRIMER_BONJOUR_DOMAIN,
    PRIMER_BONJOUR_NAME,
    PRIMER_BONJOUR_TYPE,
    PRIMER_LAUNCH_ARGUMENT,
    PRIMER_MODE,
    PRIMER_PORT,
    PRIMER_RESULT_DOCUMENT,
    PRIMER_RESULT_FILE_NAME,
    QUIC_ALPN,
    QUIC_ECHO_PORT,
    READY_FILE_NAME,
    RESULT_FILE_NAME,
    TCP_SINK_PORT,
    TLS13_ECHO_PORT,
    TLS_ALPN,
    TRANSPORT_RUN_ARGUMENT,
    IOSPeerArtifact,
    IOSPeerCommandPlan,
    IOSPeerContractError,
    IOSPeerDevice,
    IOSPeerInstallationOwnership,
    IOSPeerPreflight,
    IOSPeerPrimerProcessCleanupAuthority,
    IOSPeerPrimerProcessOwnership,
    IOSPeerProcessCleanupAuthority,
    IOSPeerProcessOwnership,
    PrimerStoppedOwnership,
    device_identifier_sha256,
    provisioning_udid_sha256,
    transport_payload_receipt_sha256,
    validate_primer_receipt,
    validate_ready_receipt,
    validate_result_receipt,
    validate_session_document,
)

DEVICE = "A0D0DA54-90DF-58E3-92B4-146CECE10AC7"
PROVISIONING_UDID = "00008110-0012345678901234"
SESSION_ID = "1" * 64
CERTIFICATE_SHA256 = "2" * 64
PRIVATE_KEY_SHA256 = "3" * 64
EXECUTABLE_SHA256 = "4" * 64
APP_TREE_SHA256 = "5" * 64
NOW = datetime(2026, 8, 20, 4, 5, 6, 123456, tzinfo=timezone.utc)
LAUNCH_SERVICES_IDENTIFIER = "bGF1bmNoLXNlcnZpY2VzLWlkZW50aWZpZXI="
REMOTE_EXECUTABLE = (
    "/private/var/containers/Bundle/Application/"
    "11111111-2222-3333-4444-555555555555/"
    "CFMPhysicalTransportPeer.app/CFMPhysicalTransportPeer"
)


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical(document: dict[str, object]) -> bytes:
    return canonical_json(document) + b"\n"


def _session() -> dict[str, object]:
    return {
        "certificate_sha256": CERTIFICATE_SHA256,
        "created_at": _timestamp(NOW - timedelta(seconds=1)),
        "document": "cfm-ios-transport-peer-session-v1",
        "expires_at": _timestamp(NOW + timedelta(minutes=10)),
        "private_key_sha256": PRIVATE_KEY_SHA256,
        "schema_version": 1,
        "session_id": SESSION_ID,
    }


def _ready() -> dict[str, object]:
    return {
        "bundle_identifier": BUNDLE_IDENTIFIER,
        "certificate_sha256": CERTIFICATE_SHA256,
        "document": "cfm-ios-transport-peer-ready-v1",
        "expires_at": _timestamp(NOW + timedelta(minutes=10)),
        "listeners": {
            "quic_echo": {
                "alpn": QUIC_ALPN,
                "port": QUIC_ECHO_PORT,
                "transport": "quic-tls13",
            },
            "tcp_sink": {"alpn": None, "port": TCP_SINK_PORT, "transport": "tcp4"},
            "tls13_echo": {
                "alpn": TLS_ALPN,
                "port": TLS13_ECHO_PORT,
                "transport": "tls13-tcp4",
            },
        },
        "network": {"interface_name": "en0", "ipv4": "192.168.1.20"},
        "process_id": 4321,
        "schema_version": 1,
        "session_id": SESSION_ID,
        "started_at": _timestamp(NOW - timedelta(seconds=1)),
    }


def _result() -> dict[str, object]:
    def payload_sha256(service: str) -> str:
        return transport_payload_receipt_sha256(service, SESSION_ID)

    secure_outcome = {
        "accepted": 0,
        "evidence_disposition": "pair_required",
        "bytes_received": 32,
        "bytes_sent": 34,
        "control_bytes_received": 1,
        "control_bytes_submitted": 1,
        "delivery_confirmation_completion": "processed",
        "peer_terminal_observed": False,
        "delivery_acknowledgement_final_context_observed": True,
        "tls_version": 0x0304,
        "cipher_suite": 0x1301,
        "early_data_accepted": False,
    }
    return {
        "bundle_identifier": BUNDLE_IDENTIFIER,
        "certificate_sha256": CERTIFICATE_SHA256,
        "completed_at": _timestamp(NOW + timedelta(seconds=2)),
        "connections": {
            "quic_echo": {
                **secure_outcome,
                "transport": "quic-tls13",
                "alpn": QUIC_ALPN,
                "payload_sha256": payload_sha256("quic_echo"),
            },
            "tcp_sink": {
                "accepted": 1,
                "evidence_disposition": "accepted",
                "bytes_received": 32,
                "bytes_sent": 0,
                "control_bytes_received": 0,
                "control_bytes_submitted": 0,
                "delivery_confirmation_completion": None,
                "peer_terminal_observed": True,
                "delivery_acknowledgement_final_context_observed": False,
                "transport": "tcp4",
                "tls_version": None,
                "cipher_suite": None,
                "alpn": None,
                "early_data_accepted": None,
                "payload_sha256": payload_sha256("tcp_sink"),
            },
            "tls13_echo": {
                **secure_outcome,
                "transport": "tls13-tcp4",
                "alpn": TLS_ALPN,
                "payload_sha256": payload_sha256("tls13_echo"),
            },
        },
        "claim_eligible": False,
        "document": "cfm-ios-transport-peer-result-v5",
        "evidence_role": "server_observation_only",
        "failed_service": "none",
        "failure_phase": "none",
        "failure_reason": "none",
        "blocking_service": None,
        "blocking_phase": None,
        "blocking_admission_sequence": None,
        "incoming_admission_sequence": None,
        "incoming_matches_blocker_object": None,
        "blocking_quic_stream_identifier": None,
        "identity_files_removed": True,
        "listeners_closed": True,
        "phase_reached": "completed",
        "process_id": 4321,
        "schema_version": 5,
        "session_id": SESSION_ID,
        "status": "pair_required",
    }


def _primer_receipt(process_id: int = 4321) -> dict[str, object]:
    return {
        "bundle_identifier": BUNDLE_IDENTIFIER,
        "claim_eligible": False,
        "document": PRIMER_RESULT_DOCUMENT,
        "listener": {
            "bonjour_domain": PRIMER_BONJOUR_DOMAIN,
            "bonjour_name": PRIMER_BONJOUR_NAME,
            "bonjour_type": PRIMER_BONJOUR_TYPE,
            "port": PRIMER_PORT,
            "transport": "tcp4",
        },
        "listener_cancelled": True,
        "listener_cancelled_at": _timestamp(NOW),
        "listener_ready": True,
        "listener_ready_at": _timestamp(NOW - timedelta(seconds=1)),
        "mode": PRIMER_MODE,
        "network": {"interface_name": "en0", "ipv4": "192.168.1.20"},
        "process_id": process_id,
        "schema_version": 1,
        "service_registered": True,
        "service_registered_at": _timestamp(NOW - timedelta(seconds=2)),
        "started_at": _timestamp(NOW - timedelta(seconds=3)),
    }


def _preflight() -> IOSPeerPreflight:
    return IOSPeerPreflight(
        device_identifier_sha256=device_identifier_sha256(DEVICE),
        app_inventory_receipt_sha256="a" * 64,
        process_inventory_receipt_sha256="9" * 64,
        observed_at=_timestamp(NOW),
        app_absent=True,
        process_absent=True,
    )


def _installation(
    launch_services_identifier: str = LAUNCH_SERVICES_IDENTIFIER,
) -> IOSPeerInstallationOwnership:
    return IOSPeerInstallationOwnership(
        device_identifier_sha256=device_identifier_sha256(DEVICE),
        app_tree_sha256=APP_TREE_SHA256,
        install_receipt_sha256="b" * 64,
        app_inventory_receipt_sha256="8" * 64,
        launch_services_identifier=launch_services_identifier,
        installed_at=_timestamp(NOW),
    )


def _process() -> IOSPeerProcessOwnership:
    return IOSPeerProcessOwnership(
        device_identifier_sha256=device_identifier_sha256(DEVICE),
        app_tree_sha256=APP_TREE_SHA256,
        session_id=SESSION_ID,
        process_id=4321,
        launch_services_identifier=LAUNCH_SERVICES_IDENTIFIER,
        executable_path=REMOTE_EXECUTABLE,
        launch_receipt_sha256="c" * 64,
        process_inventory_receipt_sha256="d" * 64,
        ready_receipt_sha256="e" * 64,
    )


def _cleanup_authority() -> IOSPeerProcessCleanupAuthority:
    return IOSPeerProcessCleanupAuthority(
        process=_process(),
        revalidated_process_inventory_receipt_sha256="f" * 64,
        revalidated_ready_receipt_sha256="e" * 64,
        observed_at=_timestamp(NOW),
    )


def _primer_process() -> IOSPeerPrimerProcessOwnership:
    return IOSPeerPrimerProcessOwnership(
        device_identifier_sha256=device_identifier_sha256(DEVICE),
        app_tree_sha256=APP_TREE_SHA256,
        process_id=4321,
        launch_services_identifier=LAUNCH_SERVICES_IDENTIFIER,
        executable_path=REMOTE_EXECUTABLE,
        launch_receipt_sha256="1" * 64,
        process_inventory_receipt_sha256="2" * 64,
        primer_receipt_sha256=hashlib.sha256(_canonical(_primer_receipt())).hexdigest(),
    )


def _primer_cleanup_authority() -> IOSPeerPrimerProcessCleanupAuthority:
    process = _primer_process()
    return IOSPeerPrimerProcessCleanupAuthority(
        process=process,
        revalidated_process_inventory_receipt_sha256="3" * 64,
        revalidated_primer_receipt_sha256=process.primer_receipt_sha256,
        observed_at=_timestamp(NOW),
    )


def _primer_stopped() -> PrimerStoppedOwnership:
    return PrimerStoppedOwnership(
        process=_primer_process(),
        terminate_receipt_sha256="4" * 64,
        post_terminate_process_inventory_receipt_sha256="5" * 64,
        stopped_at=_timestamp(NOW + timedelta(seconds=1)),
        process_absent=True,
    )


def _device() -> IOSPeerDevice:
    return IOSPeerDevice(
        DEVICE,
        device_identifier_sha256(DEVICE),
        PROVISIONING_UDID,
        provisioning_udid_sha256(PROVISIONING_UDID),
    )


class IOSPeerContractTests(unittest.TestCase):
    def test_ios_peer_remains_outside_product_graph_and_has_no_privileged_capabilities(
        self,
    ) -> None:
        repository = Path(__file__).resolve().parents[2]
        tool = repository / "tools/physical-transport-peer-ios"
        project_spec = (tool / "project.yml").read_text(encoding="utf-8")
        project_file = (
            tool / "CFMPhysicalTransportPeerIOS.xcodeproj/project.pbxproj"
        ).read_text(encoding="utf-8")
        info = plistlib.loads((tool / "Info.plist").read_bytes())

        self.assertIn("SUPPORTED_PLATFORMS: iphoneos", project_spec)
        self.assertIn("ARCHS: arm64", project_spec)
        self.assertIn("CODE_SIGN_STYLE: Manual", project_spec)
        self.assertIn('TARGETED_DEVICE_FAMILY: "1"', project_spec)
        self.assertNotIn("TARGETED_DEVICE_FAMILY: \"1,2\"", project_spec)
        self.assertNotIn("UISupportedInterfaceOrientations~ipad", project_spec)
        self.assertNotIn("UISupportedInterfaceOrientations~ipad", info)
        for forbidden in (
            "NetworkExtension.framework",
            "com.apple.developer.networking.networkextension",
            "com.apple.security.application-groups",
            "keychain-access-groups",
            "allowProvisioningUpdates",
            "CODE_SIGN_STYLE: Automatic",
            "native/macos",
            "CFWNative",
        ):
            self.assertNotIn(forbidden, project_spec)
            self.assertNotIn(forbidden, project_file)
        self.assertEqual(
            info["NSLocalNetworkUsageDescription"],
            "This test-only peer receives bounded CFM transport validation "
            "traffic on the local Wi-Fi network.",
        )
        self.assertEqual(info["NSBonjourServices"], [PRIMER_BONJOUR_TYPE])
        self.assertEqual(project_spec.count(PRIMER_BONJOUR_TYPE), 1)
        self.assertIs(info["UIApplicationExitsOnSuspend"], True)
        self.assertIs(info["UIRequiresFullScreen"], True)
        for forbidden_key in (
            "UIBackgroundModes",
            "NSLocalNetworkUsageDescriptionFallback",
        ):
            self.assertNotIn(forbidden_key, info)

        cargo = (repository / "Cargo.toml").read_text(encoding="utf-8")
        native = (repository / "native/macos/project.yml").read_text(encoding="utf-8")
        self.assertNotIn("physical-transport-peer-ios", cargo)
        self.assertNotIn("physical-transport-peer-ios", native)

    def test_device_hash_is_domain_bound_and_canonical(self) -> None:
        digest = device_identifier_sha256(DEVICE)
        self.assertEqual(len(digest), 64)
        device = _device()
        self.assertEqual(device.core_device_identifier, DEVICE)
        with self.assertRaises(IOSPeerContractError):
            IOSPeerDevice(
                DEVICE.lower(),
                digest,
                PROVISIONING_UDID,
                provisioning_udid_sha256(PROVISIONING_UDID),
            )
        with self.assertRaises(IOSPeerContractError):
            IOSPeerDevice(
                DEVICE,
                "0" * 64,
                PROVISIONING_UDID,
                provisioning_udid_sha256(PROVISIONING_UDID),
            )

    def test_command_plan_has_only_fixed_devicectl_surface(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            app = root / f"{APP_EXECUTABLE}.app"
            app.mkdir()
            session = root / "CFMTransportPeer"
            session.mkdir()
            packet_lan_session = root / PACKET_LAN_DIRECTORY_NAME
            packet_lan_session.mkdir()
            artifact = IOSPeerArtifact(app, EXECUTABLE_SHA256, APP_TREE_SHA256)
            plan = IOSPeerCommandPlan(
                root,
                _device(),
                artifact,
            )

            commands = [
                plan.device_details(root / "device-details.json"),
                plan.lock_state(root / "lock-state.json"),
                plan.app_inventory(root / "app-inventory.json"),
                plan.install(_preflight(), root / "install.json"),
                plan.launch_primer(_installation(), root / "primer-launch.json"),
                plan.copy_primer_receipt(
                    _installation(),
                    root / PRIMER_RESULT_FILE_NAME,
                    root / "primer-result-copy.json",
                ),
                plan.terminate_primer(
                    _primer_cleanup_authority(), root / "primer-terminate.json"
                ),
                plan.copy_session_to_device(
                    _primer_stopped(), session, root / "session-copy.json"
                ),
                plan.launch_transport(_installation(), root / "transport-launch.json"),
                plan.copy_packet_lan_session_to_device(
                    _primer_stopped(),
                    packet_lan_session,
                    root / "packet-lan-session-copy.json",
                ),
                plan.launch_packet_lan(
                    _installation(), root / "packet-lan-launch.json"
                ),
                plan.process_inventory(root / "process-inventory.json"),
                plan.copy_receipt_from_device(
                    _installation(),
                    READY_FILE_NAME,
                    root / READY_FILE_NAME,
                    root / "ready-copy.json",
                ),
                plan.copy_receipt_from_device(
                    _process(),
                    RESULT_FILE_NAME,
                    root / RESULT_FILE_NAME,
                    root / "result-copy.json",
                ),
                plan.copy_packet_lan_receipt_from_device(
                    _installation(),
                    PACKET_LAN_READY_FILE_NAME,
                    root / PACKET_LAN_READY_FILE_NAME,
                    root / "packet-lan-ready-copy.json",
                ),
                plan.copy_packet_lan_receipt_from_device(
                    _process(),
                    PACKET_LAN_RESULT_FILE_NAME,
                    root / PACKET_LAN_RESULT_FILE_NAME,
                    root / "packet-lan-result-copy.json",
                ),
                plan.terminate(_cleanup_authority(), root / "terminate.json"),
                plan.uninstall(_installation(), root / "uninstall.json"),
            ]
            self.assertEqual(len({command.role for command in commands}), len(commands))
            for command in commands:
                self.assertEqual(command.argv[:2], ("/usr/bin/xcrun", "devicectl"))
                self.assertEqual(command.cwd, root)
                self.assertIn("--device", command.argv)
                self.assertIn(DEVICE, command.argv)
                self.assertNotIn("--kill", command.argv)
                self.assertIn("--quiet", command.argv)
                self.assertIn("--timeout", command.argv)
                self.assertNotIn("--include-all-apps", command.argv)

            primer_launch = plan.launch_primer(
                _installation(), root / "primer-launch-again.json"
            )
            transport_launch = plan.launch_transport(
                _installation(), root / "transport-launch-again.json"
            )
            packet_lan_launch = plan.launch_packet_lan(
                _installation(), root / "packet-lan-launch-again.json"
            )
            for launch in (primer_launch, transport_launch, packet_lan_launch):
                self.assertIn("--activate", launch.argv)
                self.assertIn("--launch-persistent-identifier", launch.argv)
                self.assertIn(LAUNCH_SERVICES_IDENTIFIER, launch.argv)
                self.assertNotIn("--terminate-existing", launch.argv)
            self.assertEqual(
                primer_launch.argv[-2:],
                (BUNDLE_IDENTIFIER, PRIMER_LAUNCH_ARGUMENT),
            )
            self.assertEqual(
                transport_launch.argv[-2:],
                (BUNDLE_IDENTIFIER, TRANSPORT_RUN_ARGUMENT),
            )
            self.assertEqual(
                packet_lan_launch.argv[-2:],
                (BUNDLE_IDENTIFIER, PACKET_LAN_LAUNCH_ARGUMENT),
            )
            launch_without_token = plan.launch_transport(
                _installation("unknown"), root / "transport-launch-without-token.json"
            )
            self.assertNotIn(
                "--launch-persistent-identifier", launch_without_token.argv
            )
            self.assertNotIn("unknown", launch_without_token.argv)
            self.assertEqual(
                launch_without_token.argv[-2:],
                (BUNDLE_IDENTIFIER, TRANSPORT_RUN_ARGUMENT),
            )
            session_copy = plan.copy_session_to_device(
                _primer_stopped(), session, root / "session-copy-again.json"
            )
            destination_index = session_copy.argv.index("--destination")
            self.assertEqual(
                session_copy.argv[destination_index + 1], "Documents/CFMTransportPeer"
            )
            packet_lan_copy = plan.copy_packet_lan_session_to_device(
                _primer_stopped(),
                packet_lan_session,
                root / "packet-lan-session-copy-again.json",
            )
            packet_destination_index = packet_lan_copy.argv.index("--destination")
            self.assertEqual(
                packet_lan_copy.argv[packet_destination_index + 1],
                PACKET_LAN_DEVICE_DIRECTORY,
            )
            primer_copy = plan.copy_primer_receipt(
                _installation(),
                root / PRIMER_RESULT_FILE_NAME,
                root / "primer-result-copy-again.json",
            )
            primer_source_index = primer_copy.argv.index("--source")
            self.assertEqual(
                primer_copy.argv[primer_source_index + 1],
                "Documents/CFMTransportPrimer/primer-result.json",
            )
            primer_terminate = plan.terminate_primer(
                _primer_cleanup_authority(), root / "primer-terminate-again.json"
            )
            primer_pid_index = primer_terminate.argv.index("--pid")
            self.assertEqual(primer_terminate.argv[primer_pid_index + 1], "4321")
            self.assertNotIn("--search", primer_terminate.argv)
            self.assertNotIn("--filter", primer_terminate.argv)
            inventory = plan.process_inventory(root / "process-inventory-again.json")
            self.assertNotIn("--search", inventory.argv)
            self.assertNotIn("--filter", inventory.argv)
            self.assertEqual(
                plan.uninstall(_installation(), root / "uninstall-again.json").argv[-1],
                BUNDLE_IDENTIFIER,
            )

    def test_command_plan_rejects_unreviewed_paths_and_processes(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            app = root / f"{APP_EXECUTABLE}.app"
            app.mkdir()
            plan = IOSPeerCommandPlan(
                root,
                _device(),
                IOSPeerArtifact(app, EXECUTABLE_SHA256, APP_TREE_SHA256),
            )
            session = root / "CFMTransportPeer"
            session.mkdir()
            packet_lan_session = root / PACKET_LAN_DIRECTORY_NAME
            packet_lan_session.mkdir()
            with self.assertRaises(IOSPeerContractError):
                plan.copy_session_to_device(
                    _installation(),
                    session,
                    root / "session-copy.json",  # type: ignore[arg-type]
                )
            with self.assertRaises(IOSPeerContractError):
                plan.copy_session_to_device(
                    _primer_stopped(), root, root / "session-copy.json"
                )
            foreign_process = replace(
                _primer_process(), device_identifier_sha256="d" * 64
            )
            foreign_stopped = replace(_primer_stopped(), process=foreign_process)
            with self.assertRaises(IOSPeerContractError):
                plan.copy_session_to_device(
                    foreign_stopped, session, root / "session-copy.json"
                )
            with self.assertRaises(IOSPeerContractError):
                plan.copy_packet_lan_session_to_device(
                    _primer_stopped(), root, root / "packet-lan-session-copy.json"
                )
            with self.assertRaises(IOSPeerContractError):
                PrimerStoppedOwnership(
                    process=_primer_process(),
                    terminate_receipt_sha256="4" * 64,
                    post_terminate_process_inventory_receipt_sha256="5" * 64,
                    stopped_at=_timestamp(NOW),
                    process_absent=False,
                )
            with self.assertRaises(IOSPeerContractError):
                IOSPeerPrimerProcessCleanupAuthority(
                    process=_primer_process(),
                    revalidated_process_inventory_receipt_sha256="3" * 64,
                    revalidated_primer_receipt_sha256="6" * 64,
                    observed_at=_timestamp(NOW),
                )
            with self.assertRaises(IOSPeerContractError):
                plan.terminate_primer(
                    _cleanup_authority(),  # type: ignore[arg-type]
                    root / "primer-terminate.json",
                )
            with self.assertRaises(IOSPeerContractError):
                plan.copy_primer_receipt(
                    _installation(),
                    root / "other.json",
                    root / "primer-result-copy.json",
                )
            with self.assertRaises(IOSPeerContractError):
                plan.copy_receipt_from_device(
                    _process(),
                    "other.json",
                    root / "other.json",
                    root / "other-copy.json",
                )
            revalidated_ready = plan.copy_receipt_from_device(
                _process(),
                READY_FILE_NAME,
                root / READY_FILE_NAME,
                root / "ready-copy.json",
            )
            self.assertEqual(revalidated_ready.role, "ios-peer-ready-copy")
            with self.assertRaises(IOSPeerContractError):
                plan.copy_receipt_from_device(
                    _installation(),
                    RESULT_FILE_NAME,
                    root / RESULT_FILE_NAME,
                    root / "result-copy.json",
                )
            with self.assertRaises(IOSPeerContractError):
                plan.copy_packet_lan_receipt_from_device(
                    _process(),
                    "other.json",
                    root / "other.json",
                    root / "packet-lan-other-copy.json",
                )
            revalidated_packet_ready = plan.copy_packet_lan_receipt_from_device(
                _process(),
                PACKET_LAN_READY_FILE_NAME,
                root / PACKET_LAN_READY_FILE_NAME,
                root / "packet-lan-ready-copy.json",
            )
            self.assertEqual(
                revalidated_packet_ready.role, "ios-peer-packet-lan-ready-copy"
            )
            with self.assertRaises(IOSPeerContractError):
                plan.copy_packet_lan_receipt_from_device(
                    _installation(),
                    PACKET_LAN_RESULT_FILE_NAME,
                    root / PACKET_LAN_RESULT_FILE_NAME,
                    root / "packet-lan-result-copy.json",
                )
            foreign_process = replace(_process(), app_tree_sha256="9" * 64)
            with self.assertRaises(IOSPeerContractError):
                plan.copy_receipt_from_device(
                    foreign_process,
                    READY_FILE_NAME,
                    root / READY_FILE_NAME,
                    root / "foreign-ready-copy.json",
                )
            with self.assertRaises(IOSPeerContractError):
                plan.copy_packet_lan_receipt_from_device(
                    foreign_process,
                    PACKET_LAN_READY_FILE_NAME,
                    root / PACKET_LAN_READY_FILE_NAME,
                    root / "foreign-packet-lan-ready-copy.json",
                )
            with self.assertRaises(IOSPeerContractError):
                IOSPeerProcessCleanupAuthority(
                    IOSPeerProcessOwnership(
                        device_identifier_sha256=device_identifier_sha256(DEVICE),
                        app_tree_sha256=APP_TREE_SHA256,
                        session_id=SESSION_ID,
                        process_id=0,
                        launch_services_identifier=LAUNCH_SERVICES_IDENTIFIER,
                        executable_path=REMOTE_EXECUTABLE,
                        launch_receipt_sha256="c" * 64,
                        process_inventory_receipt_sha256="d" * 64,
                        ready_receipt_sha256="e" * 64,
                    ),
                    "f" * 64,
                    "e" * 64,
                    _timestamp(NOW),
                )
            with self.assertRaises(IOSPeerContractError):
                plan.uninstall(
                    IOSPeerInstallationOwnership(
                        device_identifier_sha256="d" * 64,
                        app_tree_sha256=APP_TREE_SHA256,
                        install_receipt_sha256="b" * 64,
                        app_inventory_receipt_sha256="8" * 64,
                        launch_services_identifier=LAUNCH_SERVICES_IDENTIFIER,
                        installed_at=_timestamp(NOW),
                    ),
                    root / "uninstall.json",
                )

    def test_install_refuses_preexisting_app_and_cross_device_ownership(self) -> None:
        with self.assertRaises(IOSPeerContractError) as raised:
            IOSPeerPreflight(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_inventory_receipt_sha256="a" * 64,
                process_inventory_receipt_sha256="9" * 64,
                observed_at=_timestamp(NOW),
                app_absent=False,
                process_absent=True,
            )
        self.assertEqual(raised.exception.code, "ios_peer_preexisting_app")

    def test_primer_receipt_requires_fresh_canonical_closed_lifecycle(self) -> None:
        receipt = _primer_receipt()
        document = validate_primer_receipt(
            _canonical(receipt), expected_process_id=4321, now=NOW
        )
        self.assertEqual(document, receipt)
        self.assertIs(document["claim_eligible"], False)

        noncanonical = json.dumps(receipt, indent=2).encode() + b"\n"
        with self.assertRaises(IOSPeerContractError) as raised:
            validate_primer_receipt(noncanonical, expected_process_id=4321, now=NOW)
        self.assertEqual(raised.exception.code, "ios_peer_receipt_invalid")

        unknown = _primer_receipt()
        unknown["fallback"] = True
        with self.assertRaises(IOSPeerContractError):
            validate_primer_receipt(
                _canonical(unknown), expected_process_id=4321, now=NOW
            )

    def test_primer_receipt_rejects_identity_and_policy_drift(self) -> None:
        for field, value in (
            ("schema_version", True),
            ("claim_eligible", True),
            ("service_registered", False),
            ("listener_ready", False),
            ("listener_cancelled", False),
        ):
            mutation = _primer_receipt()
            mutation[field] = value
            with self.subTest(field=field), self.assertRaises(IOSPeerContractError):
                validate_primer_receipt(
                    _canonical(mutation), expected_process_id=4321, now=NOW
                )

        with self.assertRaises(IOSPeerContractError):
            validate_primer_receipt(
                _canonical(_primer_receipt()), expected_process_id=4322, now=NOW
            )
        with self.assertRaises(IOSPeerContractError):
            validate_primer_receipt(
                _canonical(_primer_receipt()), expected_process_id=True, now=NOW
            )

        for listener_field, value in (
            ("port", 1),
            ("transport", "udp4"),
            ("bonjour_name", "Other"),
            ("bonjour_type", "_other._tcp"),
            ("bonjour_domain", "example."),
        ):
            mutation = _primer_receipt()
            mutation["listener"][listener_field] = value  # type: ignore[index]
            with (
                self.subTest(listener_field=listener_field),
                self.assertRaises(IOSPeerContractError),
            ):
                validate_primer_receipt(
                    _canonical(mutation), expected_process_id=4321, now=NOW
                )

        for interface_name, address in (
            ("pdp_ip0", "192.168.1.20"),
            ("en0", "203.0.113.1"),
            ("en0", "192.168.001.020"),
        ):
            mutation = _primer_receipt()
            mutation["network"] = {
                "interface_name": interface_name,
                "ipv4": address,
            }
            with self.subTest(address=address), self.assertRaises(IOSPeerContractError):
                validate_primer_receipt(
                    _canonical(mutation), expected_process_id=4321, now=NOW
                )

    def test_primer_receipt_rejects_stale_future_and_out_of_order_proof(self) -> None:
        stale = _primer_receipt()
        stale["started_at"] = _timestamp(NOW - timedelta(minutes=16))
        with self.assertRaises(IOSPeerContractError) as raised:
            validate_primer_receipt(
                _canonical(stale), expected_process_id=4321, now=NOW
            )
        self.assertEqual(raised.exception.code, "ios_peer_primer_stale")

        future = _primer_receipt()
        future["listener_cancelled_at"] = _timestamp(NOW + timedelta(seconds=1))
        with self.assertRaises(IOSPeerContractError):
            validate_primer_receipt(
                _canonical(future), expected_process_id=4321, now=NOW
            )

        out_of_order = _primer_receipt()
        out_of_order["listener_ready_at"] = _timestamp(NOW + timedelta(seconds=1))
        with self.assertRaises(IOSPeerContractError):
            validate_primer_receipt(
                _canonical(out_of_order), expected_process_id=4321, now=NOW
            )

        with self.assertRaises(IOSPeerContractError) as raised:
            validate_primer_receipt(
                _canonical(_primer_receipt()),
                expected_process_id=4321,
                now=NOW.replace(tzinfo=None),
            )
        self.assertEqual(raised.exception.code, "ios_peer_time_invalid")

    def test_primer_types_bind_receipt_exact_pid_and_stopped_gate(self) -> None:
        process = _primer_process()
        self.assertEqual(process.process_id, 4321)
        self.assertEqual(
            process.primer_receipt_sha256,
            hashlib.sha256(_canonical(_primer_receipt())).hexdigest(),
        )
        authority = _primer_cleanup_authority()
        self.assertEqual(authority.process, process)
        stopped = _primer_stopped()
        self.assertTrue(stopped.process_absent)

    def test_session_accepts_only_fresh_canonical_document(self) -> None:
        document = validate_session_document(_canonical(_session()), now=NOW)
        self.assertEqual(document["session_id"], SESSION_ID)

        noncanonical = json.dumps(_session(), indent=2).encode() + b"\n"
        with self.assertRaises(IOSPeerContractError) as raised:
            validate_session_document(noncanonical, now=NOW)
        self.assertEqual(raised.exception.code, "ios_peer_receipt_invalid")

        stale = _session()
        stale["expires_at"] = _timestamp(NOW)
        with self.assertRaises(IOSPeerContractError) as raised:
            validate_session_document(_canonical(stale), now=NOW)
        self.assertEqual(raised.exception.code, "ios_peer_session_expired")

    def test_session_rejects_unknown_fields_and_oversized_lifetime(self) -> None:
        unknown = _session()
        unknown["fallback"] = True
        with self.assertRaises(IOSPeerContractError):
            validate_session_document(_canonical(unknown), now=NOW)

        long_lived = _session()
        long_lived["expires_at"] = _timestamp(NOW + timedelta(minutes=16))
        with self.assertRaises(IOSPeerContractError):
            validate_session_document(_canonical(long_lived), now=NOW)

    def test_ready_receipt_binds_all_three_fixed_listeners(self) -> None:
        document = validate_ready_receipt(
            _canonical(_ready()),
            expected_session_id=SESSION_ID,
            expected_certificate_sha256=CERTIFICATE_SHA256,
            now=NOW,
        )
        self.assertEqual(document["process_id"], 4321)

        for service in ("tcp_sink", "tls13_echo", "quic_echo"):
            mutation = _ready()
            mutation["listeners"][service]["port"] = 1  # type: ignore[index]
            with self.assertRaises(IOSPeerContractError):
                validate_ready_receipt(
                    _canonical(mutation),
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    now=NOW,
                )

    def test_ready_receipt_rejects_replay_and_identity_drift(self) -> None:
        with self.assertRaises(IOSPeerContractError):
            validate_ready_receipt(
                _canonical(_ready()),
                expected_session_id="8" * 64,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                now=NOW,
            )
        with self.assertRaises(IOSPeerContractError):
            validate_ready_receipt(
                _canonical(_ready()),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256="9" * 64,
                now=NOW,
            )
        with self.assertRaises(IOSPeerContractError) as raised:
            validate_ready_receipt(
                _canonical(_ready()),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                now=NOW + timedelta(minutes=11),
            )
        self.assertEqual(raised.exception.code, "ios_peer_ready_expired")

        oversized_window = _ready()
        oversized_window["expires_at"] = _timestamp(NOW + timedelta(minutes=16))
        with self.assertRaises(IOSPeerContractError) as raised:
            validate_ready_receipt(
                _canonical(oversized_window),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                now=NOW,
            )
        self.assertEqual(raised.exception.code, "ios_peer_ready_expired")

        for interface_name, address in (
            ("pdp_ip0", "192.168.1.20"),
            ("en0", "203.0.113.1"),
            ("en0", "192.168.001.020"),
        ):
            mutation = _ready()
            mutation["network"] = {
                "interface_name": interface_name,
                "ipv4": address,
            }
            with self.assertRaises(IOSPeerContractError):
                validate_ready_receipt(
                    _canonical(mutation),
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    now=NOW,
                )

    def test_payload_receipt_hashes_the_exact_session_derived_payload(self) -> None:
        domain = b"cfm-ios-transport-peer-tls-payload-v1\0"
        payload = hashlib.sha256(domain + bytes.fromhex(SESSION_ID)).digest()
        receipt_digest = transport_payload_receipt_sha256("tls13_echo", SESSION_ID)
        self.assertNotEqual(receipt_digest, payload.hex())
        self.assertEqual(receipt_digest, hashlib.sha256(payload).hexdigest())

    def test_closed_result_requires_cleanup_without_claiming_transport_success(
        self,
    ) -> None:
        document = validate_result_receipt(
            _canonical(_result()),
            expected_session_id=SESSION_ID,
            expected_certificate_sha256=CERTIFICATE_SHA256,
            expected_process_id=4321,
        )
        self.assertEqual(document["status"], "pair_required")

        for field in ("listeners_closed", "identity_files_removed"):
            mutation = _result()
            mutation[field] = False
            with self.assertRaises(IOSPeerContractError) as raised:
                validate_result_receipt(
                    _canonical(mutation),
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    expected_process_id=4321,
                )
            self.assertEqual(raised.exception.code, "ios_peer_cleanup_unproven")

    def test_failed_result_may_describe_incomplete_cleanup_but_never_success(
        self,
    ) -> None:
        mutation = _result()
        mutation["status"] = "failed"
        mutation["failure_phase"] = "application_lifecycle"
        mutation["failed_service"] = "runtime"
        mutation["failure_reason"] = "application_lifecycle_requested"
        mutation["phase_reached"] = "application_started"
        mutation["listeners_closed"] = False
        mutation["identity_files_removed"] = False
        document = validate_result_receipt(
            _canonical(mutation),
            expected_session_id=SESSION_ID,
            expected_certificate_sha256=CERTIFICATE_SHA256,
            expected_process_id=4321,
        )
        self.assertEqual(document["status"], "failed")

    def test_result_v5_failure_identity_is_typed_and_service_scoped(self) -> None:
        admission_overlap = _result()
        admission_overlap["status"] = "failed"
        admission_overlap["failure_phase"] = "connection_admission"
        admission_overlap["failed_service"] = "tls13_echo"
        admission_overlap["failure_reason"] = "connection_admission_overlap"
        admission_overlap["phase_reached"] = "security_ready"
        admission_overlap["blocking_service"] = "tcp_sink"
        admission_overlap["blocking_phase"] = "security_ready"
        admission_overlap["blocking_admission_sequence"] = 1
        admission_overlap["incoming_admission_sequence"] = 2
        admission_overlap["incoming_matches_blocker_object"] = False
        admission_overlap["listeners_closed"] = False
        self.assertEqual(
            validate_result_receipt(
                _canonical(admission_overlap),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
            )["failure_reason"],
            "connection_admission_overlap",
        )

        quic_overlap = dict(admission_overlap)
        quic_overlap["failed_service"] = "quic_echo"
        quic_overlap["blocking_service"] = "quic_echo"
        quic_overlap["blocking_phase"] = "security_ready"
        quic_overlap["blocking_quic_stream_identifier"] = 0
        validate_result_receipt(
            _canonical(quic_overlap),
            expected_session_id=SESSION_ID,
            expected_certificate_sha256=CERTIFICATE_SHA256,
            expected_process_id=4321,
        )

        for field, value in (
            ("blocking_service", None),
            ("blocking_admission_sequence", True),
            ("incoming_admission_sequence", 1),
            ("blocking_quic_stream_identifier", 0),
        ):
            invalid_observation = dict(admission_overlap)
            invalid_observation[field] = value
            with self.assertRaises(IOSPeerContractError):
                validate_result_receipt(
                    _canonical(invalid_observation),
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    expected_process_id=4321,
                )

        invalid_cases = (
            ("runtime", "connection_overlap", "delivery_confirmation_submitted"),
            ("quic_echo", "application_lifecycle_requested", "application_started"),
            ("runtime", "connection_deadline_expired", "connection_accepted"),
            ("quic_echo", "unknown_reason", "delivery_confirmation_submitted"),
            ("quic_echo", "connection_deadline_expired", "completed"),
            ("tls13_echo", "connection_admission_overlap", "security_ready"),
        )
        for failed_service, failure_reason, phase_reached in invalid_cases:
            mutation = _result()
            mutation["status"] = "failed"
            mutation["failure_phase"] = "delivery_evidence"
            mutation["failed_service"] = failed_service
            mutation["failure_reason"] = failure_reason
            mutation["phase_reached"] = phase_reached
            with self.assertRaises(IOSPeerContractError):
                validate_result_receipt(
                    _canonical(mutation),
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    expected_process_id=4321,
                )

        nonfailed = _result()
        nonfailed["failed_service"] = "quic_echo"
        nonfailed["failure_reason"] = "connection_deadline_expired"
        nonfailed["phase_reached"] = "delivery_confirmation_submitted"
        with self.assertRaises(IOSPeerContractError):
            validate_result_receipt(
                _canonical(nonfailed),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
            )

        for field in ("failed_service", "failure_reason", "phase_reached"):
            malformed = _result()
            malformed[field] = []
            with self.assertRaises(IOSPeerContractError):
                validate_result_receipt(
                    _canonical(malformed),
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    expected_process_id=4321,
                )

    def test_pair_required_result_preserves_exact_server_observation(self) -> None:
        mutation = _result()
        quic = mutation["connections"]["quic_echo"]  # type: ignore[index]
        quic["delivery_confirmation_completion"] = "failed"
        document = validate_result_receipt(
            _canonical(mutation),
            expected_session_id=SESSION_ID,
            expected_certificate_sha256=CERTIFICATE_SHA256,
            expected_process_id=4321,
        )
        self.assertEqual(document["status"], "pair_required")
        self.assertEqual(
            document["connections"]["quic_echo"]["evidence_disposition"],
            "pair_required",
        )

        for field, value in (
            ("peer_terminal_observed", True),
            ("delivery_acknowledgement_final_context_observed", False),
            ("control_bytes_submitted", 0),
            ("delivery_confirmation_completion", None),
        ):
            invalid = _result()
            outcome = invalid["connections"]["quic_echo"]  # type: ignore[index]
            outcome["delivery_confirmation_completion"] = "failed"
            outcome[field] = value
            with self.assertRaises(IOSPeerContractError):
                validate_result_receipt(
                    _canonical(invalid),
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    expected_process_id=4321,
                )

    def test_result_v5_fixture_is_shared_with_swift_contract(self) -> None:
        fixture = (
            Path(__file__).resolve().parents[2]
            / "tools/physical-transport-peer-ios/Fixtures/result-v5-pair-required.json"
        ).read_bytes()
        expected = _result()
        self.assertEqual(fixture, _canonical(expected))
        document = validate_result_receipt(
            fixture,
            expected_session_id=SESSION_ID,
            expected_certificate_sha256=CERTIFICATE_SHA256,
            expected_process_id=4321,
        )
        self.assertEqual(document["status"], "pair_required")

    def test_result_v1_through_v4_are_rejected_without_compatibility_fallback(
        self,
    ) -> None:
        for version in (1, 2, 3, 4):
            legacy = _result()
            legacy["schema_version"] = version
            legacy["document"] = f"cfm-ios-transport-peer-result-v{version}"
            with self.assertRaises(IOSPeerContractError):
                validate_result_receipt(
                    _canonical(legacy),
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    expected_process_id=4321,
                )

    def test_result_rejects_counter_and_digest_drift(self) -> None:
        negative = _result()
        negative["connections"]["quic_echo"]["bytes_received"] = -1  # type: ignore[index]
        with self.assertRaises(IOSPeerContractError):
            validate_result_receipt(
                _canonical(negative),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
            )

        bad_digest = _result()
        bad_digest["connections"]["tls13_echo"]["payload_sha256"] = "UPPER"  # type: ignore[index]
        with self.assertRaises(IOSPeerContractError):
            validate_result_receipt(
                _canonical(bad_digest),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
            )

        incoherent_echo = _result()
        incoherent_echo["connections"]["tls13_echo"]["bytes_sent"] = 32  # type: ignore[index]
        with self.assertRaises(IOSPeerContractError):
            validate_result_receipt(
                _canonical(incoherent_echo),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
            )

        repeated_with_digest = _result()
        repeated_with_digest["connections"]["tcp_sink"]["accepted"] = 2  # type: ignore[index]
        repeated_with_digest["connections"]["tcp_sink"]["bytes_received"] = 64  # type: ignore[index]
        with self.assertRaises(IOSPeerContractError):
            validate_result_receipt(
                _canonical(repeated_with_digest),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
            )

    def test_result_rejects_more_than_eight_connections_across_services(self) -> None:
        mutation = _result()
        for service in ("tcp_sink", "tls13_echo", "quic_echo"):
            outcome = mutation["connections"][service]  # type: ignore[index]
            outcome["accepted"] = 3
            outcome["bytes_received"] = 96
            outcome["bytes_sent"] = 0 if service == "tcp_sink" else 102
            outcome["payload_sha256"] = None
        with self.assertRaises(IOSPeerContractError) as raised:
            validate_result_receipt(
                _canonical(mutation),
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
            )
        self.assertEqual(raised.exception.code, "ios_peer_result_invalid")


if __name__ == "__main__":
    unittest.main()
