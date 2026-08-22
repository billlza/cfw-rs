from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.harness.packet_evidence import (
    PacketEvidenceError,
    packet_capture_filter_argv,
)
from scripts.harness.raw_artifacts import canonical_json
from scripts.physical_capture.execution import (
    CommandResult,
    ProbeExecutionError,
    command_sha256,
)
from scripts.physical_capture.ios_packet_lan_peer_adapter import (
    IOSPacketLanPeerError,
    _create_workspace,
    _parse_device_selection,
    _read_stable_file,
    _reconcile_sender_and_server,
    _run,
    _source_tree_sha256,
    load_source_identity,
    validate_static_source_identity,
)
from scripts.physical_capture.ios_transport_peer import (
    IOSPeerDevice,
    device_identifier_sha256,
    device_inventory_command,
    provisioning_udid_sha256,
)


DEVICE = "A0D0DA54-90DF-58E3-92B4-146CECE10AC7"
UDID = "00008110-0012345678901234"


def _build_version() -> dict[str, object]:
    return {
        "majorLetterComponent": "F",
        "majorNumberComponent": 23,
        "name": "23F77",
        "revisionVersion": {
            "components": [23, 6, 77, 0, 0],
            "originalComponentsCount": 5,
            "stringValue": "23.6.77.0.0",
        },
        "trainProgram": "iOS",
        "updateNumberComponent": 77,
    }


def _device_item(*, connected: bool, unknown_state: bool = False) -> dict[str, object]:
    state: dict[str, object] = {
        "bootState": "booted",
        "developerModeStatus": {"enabled": {"mode": 1}},
        "name": "Test iPhone",
    }
    if connected:
        state["preparednessState"] = 7
    if unknown_state:
        state["unreviewedState"] = True
    build = _build_version()
    return {
        "capabilities": [],
        "identifier": DEVICE,
        "properties": {
            "connection": {
                "authenticationType": "manualPairing",
                "lastConnectionDate": "2026-08-22T00:00:00Z",
                "pairingState": "paired",
                "state": "connected" if connected else "disconnected",
                "transportType": "localNetwork",
                "tunnelTransportProtocol": "tcp",
            },
            "hardware": {
                "cpuType": {"subtype": 2, "type": 16_777_228},
                "deviceType": "iPhone",
                "hasActionButton": True,
                "marketingName": "iPhone",
                "platform": "iOS",
                "productType": "iPhone17,1",
                "reality": "physical",
                "supportedBiometrics": [],
                "supportedCPUTypes": [
                    {"subtype": 2, "type": 16_777_228}
                ],
                "supportedDeviceFamilies": [1],
                "supportsSiri": True,
                "udid": UDID,
            },
            "software": {
                "osBuildVersions": {
                    "buildVersion": build,
                    "supplementalBuildVersion": build,
                },
                "osVersionNumber": {
                    "components": [26, 5],
                    "originalComponentsCount": 2,
                    "stringValue": "26.5",
                },
                "supportsCheckedAllocations": True,
            },
            "state": state,
        },
        "propertyDisplayNames": None,
        "visibilityClass": "default",
    }


def _envelope(spec, source, item: dict[str, object]) -> bytes:
    return canonical_json(
        {
            "info": {
                "arguments": list(spec.argv[1:]),
                "commandType": "devicectl.list.devices",
                "environment": {"TERM": "dumb"},
                "jsonVersion": source.devicectl_runtime.json_version,
                "outcome": "success",
                "version": source.devicectl_runtime.version,
            },
            "result": {"devices": [item]},
        }
    )


class IOSPacketLanPeerAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        source = load_source_identity()
        self.source = replace(
            source,
            core_device_identifier_sha256=device_identifier_sha256(DEVICE),
            provisioning_udid_sha256=provisioning_udid_sha256(UDID),
        )

    def test_source_identity_binds_current_source_tree(self) -> None:
        source = load_source_identity()
        self.assertEqual(_source_tree_sha256(), source.source_tree_sha256)
        self.assertEqual(
            hashlib.sha256(canonical_json(source.as_identity())).hexdigest(),
            source.identity_sha256,
        )
        static = validate_static_source_identity(source)
        self.assertEqual(static["app_tree_sha256"], source.app_tree_sha256)

    def test_workspace_creation_failure_removes_new_owned_directory(self) -> None:
        workspace = Path(
            tempfile.mkdtemp(prefix="cfm-ios-packet-lan-", dir="/private/tmp")
        ).resolve()
        with patch(
            "scripts.physical_capture.ios_packet_lan_peer_adapter.tempfile.mkdtemp",
            return_value=str(workspace),
        ), patch.object(Path, "mkdir", side_effect=OSError("synthetic mkdir failure")):
            with self.assertRaises(OSError):
                _create_workspace()
        self.assertFalse(workspace.exists())

    def test_workspace_metadata_rejection_removes_new_owned_directory(self) -> None:
        workspace = Path(
            tempfile.mkdtemp(prefix="cfm-ios-packet-lan-", dir="/private/tmp")
        ).resolve()
        workspace.chmod(0o755)
        with patch(
            "scripts.physical_capture.ios_packet_lan_peer_adapter.tempfile.mkdtemp",
            return_value=str(workspace),
        ):
            with self.assertRaises(IOSPacketLanPeerError) as captured:
                _create_workspace()
        self.assertEqual(captured.exception.code, "ios_packet_lan_workspace_invalid")
        self.assertFalse(workspace.exists())

    def test_command_failure_keeps_only_bounded_diagnostic_context(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            root.chmod(0o700)
            spec = device_inventory_command(root, root / "device-list.json")
            secret = b"private CoreDevice failure details"
            result = CommandResult(
                role=spec.role,
                argv_sha256=command_sha256(spec.argv),
                started_at="2026-08-22T00:00:00.000000Z",
                completed_at="2026-08-22T00:00:00.001000Z",
                duration_ms=1,
                exit_code=1,
                stdout=b"",
                stderr=secret,
            )

            class FailingRunner:
                def run_command(self, _spec):
                    raise ProbeExecutionError("unexpected exit", result=result)

            with self.assertRaises(IOSPacketLanPeerError) as captured:
                _run(FailingRunner(), spec)
            message = str(captured.exception)
            self.assertIn("exit_code=1", message)
            self.assertIn(hashlib.sha256(secret).hexdigest(), message)
            self.assertNotIn(secret.decode(), message)

    def test_device_inventory_selects_hash_match_before_strict_admission(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            root.chmod(0o700)
            output = root / "device-list.json"
            spec = device_inventory_command(Path.cwd().resolve(), output)
            selection = _parse_device_selection(
                _envelope(spec, self.source, _device_item(connected=True)),
                spec=spec,
                source=self.source,
            )
            self.assertIsInstance(selection.device, IOSPeerDevice)
            self.assertEqual(selection.product_type, "iPhone17,1")
            self.assertEqual(selection.inventory_connection_state, "connected")
            self.assertEqual(selection.inventory_preparedness_state, 7)

            dormant = _parse_device_selection(
                _envelope(spec, self.source, _device_item(connected=False)),
                spec=spec,
                source=self.source,
            )
            self.assertEqual(dormant.inventory_connection_state, "disconnected")
            self.assertIsNone(dormant.inventory_preparedness_state)

            invalid = _device_item(connected=False)
            invalid["properties"]["state"]["preparednessState"] = 7
            with self.assertRaisesRegex(IOSPacketLanPeerError, "state differs"):
                _parse_device_selection(
                    _envelope(spec, self.source, invalid),
                    spec=spec,
                    source=self.source,
                )

            with self.assertRaisesRegex(IOSPacketLanPeerError, "fields differ"):
                _parse_device_selection(
                    _envelope(
                        spec,
                        self.source,
                        _device_item(connected=True, unknown_state=True),
                    ),
                    spec=spec,
                    source=self.source,
                )

    def test_private_coredevice_output_is_tightened_on_same_inode(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            root.chmod(0o700)
            output = root / "device-list.json"
            output.write_bytes(b"{}")
            output.chmod(0o644)
            inode = output.stat().st_ino
            self.assertEqual(
                _read_stable_file(output, maximum=64, private=True), b"{}"
            )
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

            unsafe = root / "unsafe.json"
            unsafe.write_bytes(b"{}")
            unsafe.chmod(0o666)
            with self.assertRaises(IOSPacketLanPeerError):
                _read_stable_file(unsafe, maximum=64, private=True)

    def test_sender_server_reconciliation_is_exact_and_ordered(self) -> None:
        peer = "192.168.50.9"
        local = "192.168.50.10"
        stages = []
        connections = []
        for index, stage in enumerate(("start", "target", "end"), start=1):
            digest = hashlib.sha256(f"{stage}-token".encode()).hexdigest()
            port = 51_000 + index
            stages.append(
                {
                    "stage": stage,
                    "token_sha256": digest,
                    "endpoint_set": [
                        {
                            "role": "local",
                            "address": local,
                            "port": port,
                            "transport": "tcp",
                        },
                        {
                            "role": "remote",
                            "address": peer,
                            "port": 44_333,
                            "transport": "tcp",
                        },
                    ],
                }
            )
            connections.append(
                {
                    "stage": stage,
                    "admission_sequence": index,
                    "token_sha256": digest,
                    "bytes_received": 20,
                    "eof_observed": True,
                    "peer_ipv4": local,
                    "peer_port": port,
                }
            )
        reconciled = _reconcile_sender_and_server(
            stages=stages,
            result={"connections": connections},
            peer_ipv4=peer,
        )
        self.assertEqual(
            [item["stage"] for item in reconciled], ["start", "target", "end"]
        )

        connections[1]["peer_port"] = 52_000
        with self.assertRaises(IOSPacketLanPeerError):
            _reconcile_sender_and_server(
                stages=stages,
                result={"connections": connections},
                peer_ipv4=peer,
            )

    def test_capture_filter_requires_runtime_private_lan_address(self) -> None:
        tokens = ("s" + "a" * 19, "t" + "b" * 19, "e" + "c" * 19)
        value = packet_capture_filter_argv(
            case_id="lan-bypass",
            tokens=tokens,
            lan_endpoint_address="192.168.50.9",
        )
        self.assertIn("192.168.50.9", value[0])
        for address in (None, "198.51.100.9", "192.168.50.09"):
            with self.subTest(address=address):
                with self.assertRaises(PacketEvidenceError):
                    packet_capture_filter_argv(
                        case_id="lan-bypass",
                        tokens=tokens,
                        lan_endpoint_address=address,
                    )
        with self.assertRaises(PacketEvidenceError):
            packet_capture_filter_argv(
                case_id="tcp-ipv4",
                tokens=tokens,
                lan_endpoint_address="192.168.50.9",
            )


if __name__ == "__main__":
    unittest.main()
