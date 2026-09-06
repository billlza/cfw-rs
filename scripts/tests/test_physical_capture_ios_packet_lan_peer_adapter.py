from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.physical_capture import ios_packet_lan_peer_adapter
from scripts.harness.packet_evidence import (
    PacketEvidenceError,
    packet_capture_filter_argv,
)
from scripts.harness.raw_artifacts import canonical_json
from scripts.physical_capture.execution import (
    CommandResult,
    CommandSpec,
    ProbeExecutionError,
    command_sha256,
)
from scripts.physical_capture.ios_packet_lan_peer_adapter import (
    IOSPacketLanPeerError,
    _create_workspace,
    _parse_device_selection,
    _read_stable_file,
    _reconcile_sender_and_server,
    _resolve_repository_path,
    _run,
    _source_tree_sha256,
    load_source_identity,
    validate_static_source_identity,
)
from scripts.physical_capture.ios_transport_peer import (
    APP_EXECUTABLE,
    BUNDLE_IDENTIFIER,
    IOSPeerDevice,
    device_identifier_sha256,
    device_inventory_command,
    provisioning_udid_sha256,
)


DEVICE = "A0D0DA54-90DF-58E3-92B4-146CECE10AC7"
UDID = "00008110-0012345678901234"


@contextmanager
def _source_checkout() -> Iterator[Path]:
    repository = ios_packet_lan_peer_adapter.REPOSITORY_ROOT
    identity_path = ios_packet_lan_peer_adapter.SOURCE_IDENTITY_PATH
    members = [identity_path.relative_to(repository)]
    members.extend(
        Path("tools/physical-transport-peer-ios") / relative
        for relative in ios_packet_lan_peer_adapter.SOURCE_TREE_PATHS
    )
    with tempfile.TemporaryDirectory() as root_text:
        root = Path(root_text).resolve()
        for relative in members:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repository / relative, destination)
        with patch.object(
            ios_packet_lan_peer_adapter, "REPOSITORY_ROOT", root
        ), patch.object(
            ios_packet_lan_peer_adapter,
            "SOURCE_IDENTITY_PATH",
            root / identity_path.relative_to(repository),
        ):
            yield root


def _run_environment_source_gate(repository: Path) -> None:
    script = Path(__file__).resolve().parents[1] / "verify_release_environment.sh"
    prefix, remainder = script.read_text(encoding="utf-8").split("<<'PY'\n", 1)
    gate = "\n" * (prefix.count("\n") + 1) + remainder.split("\nPY\n", 1)[0]
    with patch.object(sys, "argv", ["-", str(repository)]), patch.object(
        sys, "path", list(sys.path)
    ):
        exec(compile(gate, str(script), "exec"), {"__name__": "__main__"})


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

    def test_source_validation_requires_no_generated_deployment_inputs(self) -> None:
        with _source_checkout() as root:
            source = load_source_identity()
            self.assertFalse((root / "target").exists())
            observed = ios_packet_lan_peer_adapter.validate_source_identity(source)
            self.assertEqual(
                observed,
                {
                    "source_identity_file_sha256": source.file_sha256,
                    "source_identity_sha256": source.identity_sha256,
                    "source_tree_sha256": source.source_tree_sha256,
                },
            )
            self.assertFalse((root / "target").exists())
            for path in (
                source.artifact_path,
                source.profile_path,
                source.entitlements_path,
            ):
                self.assertFalse(path.exists())

    def test_environment_source_gate_accepts_missing_deployment_inputs(self) -> None:
        with _source_checkout() as root, redirect_stdout(io.StringIO()) as stdout:
            _run_environment_source_gate(root)
            self.assertEqual(
                stdout.getvalue(),
                "iPhone Packet LAN source identity and source tree verified\n",
            )
            self.assertFalse((root / "target").exists())

    def test_environment_source_gate_rejects_source_drift_without_success(self) -> None:
        with _source_checkout() as root, redirect_stdout(io.StringIO()) as stdout:
            source = root / "tools/physical-transport-peer-ios/App/AppDelegate.swift"
            source.write_bytes(source.read_bytes() + b"\n// changed source\n")
            with self.assertRaises(IOSPacketLanPeerError) as raised:
                _run_environment_source_gate(root)
            self.assertEqual(raised.exception.code, "ios_packet_lan_source_tree_stale")
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse((root / "target").exists())

    def test_source_validation_reopens_source_bytes_and_modes(self) -> None:
        for mutation in ("content", "mode"):
            with self.subTest(mutation=mutation), _source_checkout() as root:
                source = load_source_identity()
                member = root / "tools/physical-transport-peer-ios/App/AppDelegate.swift"
                if mutation == "content":
                    member.write_bytes(member.read_bytes() + b"\n// changed source\n")
                else:
                    original_mode = member.stat().st_mode & 0o777
                    member.chmod(0o600 if original_mode != 0o600 else 0o644)
                with self.assertRaises(IOSPacketLanPeerError) as raised:
                    ios_packet_lan_peer_adapter.validate_source_identity(source)
                self.assertEqual(
                    raised.exception.code, "ios_packet_lan_source_tree_stale"
                )

    def test_source_validation_reopens_the_identity_document(self) -> None:
        with _source_checkout():
            source = load_source_identity()
            identity = ios_packet_lan_peer_adapter.SOURCE_IDENTITY_PATH
            identity.write_bytes(identity.read_bytes() + b"\n")
            with self.assertRaises(IOSPacketLanPeerError) as raised:
                ios_packet_lan_peer_adapter.validate_source_identity(source)
            self.assertEqual(raised.exception.code, "ios_packet_lan_source_invalid")

    def test_source_validation_rejects_a_stale_expected_identity(self) -> None:
        with _source_checkout():
            source = replace(load_source_identity(), identity_sha256="0" * 64)
            with self.assertRaises(IOSPacketLanPeerError) as raised:
                ios_packet_lan_peer_adapter.validate_source_identity(source)
            self.assertEqual(raised.exception.code, "ios_packet_lan_source_changed")

    def test_source_validation_rejects_untyped_expected_identity(self) -> None:
        with self.assertRaises(IOSPacketLanPeerError) as raised:
            ios_packet_lan_peer_adapter.validate_source_identity(self.source.as_identity())
        self.assertEqual(raised.exception.code, "ios_packet_lan_source_invalid")

    def test_source_validation_rejects_unsafe_or_missing_source_members(self) -> None:
        for mutation in ("missing", "writable", "symlink"):
            with self.subTest(mutation=mutation), _source_checkout() as root:
                source = load_source_identity()
                member = root / "tools/physical-transport-peer-ios/App/AppDelegate.swift"
                if mutation == "missing":
                    member.unlink()
                elif mutation == "writable":
                    member.chmod(0o666)
                else:
                    moved = member.with_name("saved-source.swift")
                    member.rename(moved)
                    member.symlink_to(moved)
                with self.assertRaises(IOSPacketLanPeerError) as raised:
                    ios_packet_lan_peer_adapter.validate_source_identity(source)
                self.assertEqual(
                    raised.exception.code, "ios_packet_lan_source_tree_invalid"
                )

    def test_source_path_allows_a_missing_generated_tail(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            expected = root / "target/ios-packet-lan-peer/Peer.app"
            with patch.object(
                ios_packet_lan_peer_adapter, "REPOSITORY_ROOT", root
            ):
                resolved = _resolve_repository_path(
                    "target/ios-packet-lan-peer/Peer.app", label="app bundle"
                )
            self.assertEqual(resolved, expected)
            self.assertFalse(expected.parent.exists())

    def test_source_path_rejects_an_existing_symlink_escape(self) -> None:
        with (
            tempfile.TemporaryDirectory() as root_text,
            tempfile.TemporaryDirectory() as outside_text,
        ):
            root = Path(root_text).resolve()
            outside = Path(outside_text).resolve()
            (root / "target").symlink_to(outside, target_is_directory=True)
            with patch.object(
                ios_packet_lan_peer_adapter, "REPOSITORY_ROOT", root
            ), self.assertRaisesRegex(
                IOSPacketLanPeerError, "escapes the repository"
            ):
                _resolve_repository_path(
                    "target/ios-packet-lan-peer/Peer.app", label="app bundle"
                )

    def test_static_validation_still_requires_the_real_artifact(self) -> None:
        with _source_checkout():
            source = load_source_identity()
            self.assertFalse(source.artifact_path.exists())
            with self.assertRaisesRegex(
                IOSPacketLanPeerError, "signed iOS peer app is invalid"
            ) as raised:
                validate_static_source_identity(source)
            self.assertEqual(raised.exception.code, "ios_packet_lan_artifact_invalid")
            self.assertEqual(str(raised.exception.__cause__), "staged app is unavailable")

    def test_admission_rejects_invalid_inputs_before_device_mutation(self) -> None:
        cases = (
            ("missing-app", "ios_packet_lan_artifact_invalid"),
            ("stale-app", "ios_packet_lan_artifact_stale"),
            ("source-drift", "ios_packet_lan_source_tree_stale"),
        )
        for mutation, expected_code in cases:
            with self.subTest(mutation=mutation), _source_checkout() as root:
                identity_path = ios_packet_lan_peer_adapter.SOURCE_IDENTITY_PATH
                document = json.loads(identity_path.read_bytes())
                device = document["identity"]["device"]
                device["core_device_identifier_sha256"] = device_identifier_sha256(DEVICE)
                device["provisioning_udid_sha256"] = provisioning_udid_sha256(UDID)
                device["product_type"] = "iPhone17,1"
                device["os_version"] = "26.5"
                device["os_build"] = "23F77"
                document["identity_sha256"] = hashlib.sha256(
                    canonical_json(document["identity"])
                ).hexdigest()
                identity_data = canonical_json(document)
                identity_path.write_bytes(identity_data)
                with patch.object(
                    ios_packet_lan_peer_adapter,
                    "SOURCE_IDENTITY_FILE_SHA256",
                    hashlib.sha256(identity_data).hexdigest(),
                ), patch.object(
                    ios_packet_lan_peer_adapter,
                    "ADMISSION_LOCK_PATH",
                    root / "admission.lock",
                ):
                    source = load_source_identity()
                    if mutation == "stale-app":
                        source.artifact_path.mkdir(mode=0o700, parents=True)
                        info_path = source.artifact_path / "Info.plist"
                        info_path.write_bytes(
                            plistlib.dumps(
                                {
                                    "CFBundleExecutable": APP_EXECUTABLE,
                                    "CFBundleIdentifier": BUNDLE_IDENTIFIER,
                                }
                            )
                        )
                        info_path.chmod(0o600)
                        executable = source.artifact_path / APP_EXECUTABLE
                        executable.write_bytes(b"different peer executable")
                        executable.chmod(0o700)
                    elif mutation == "source-drift":
                        member = (
                            root / "tools/physical-transport-peer-ios/App/AppDelegate.swift"
                        )
                        member.write_bytes(member.read_bytes() + b"\n// changed source\n")

                    class InventoryOnlyRunner:
                        def __init__(self) -> None:
                            self.roles: list[str] = []
                            self.workspace: Path | None = None

                        def run_command(self, spec: CommandSpec) -> CommandResult:
                            self.roles.append(spec.role)
                            if spec.role != "ios-peer-device-list":
                                raise AssertionError("unexpected command after inventory")
                            output = Path(spec.argv[spec.argv.index("--json-output") + 1])
                            self.workspace = output.parent.parent
                            output.write_bytes(
                                _envelope(spec, source, _device_item(connected=True))
                            )
                            output.chmod(0o600)
                            return CommandResult(
                                role=spec.role,
                                argv_sha256=command_sha256(spec.argv),
                                started_at="2026-08-22T00:00:00.000000Z",
                                completed_at="2026-08-22T00:00:00.001000Z",
                                duration_ms=1,
                                exit_code=0,
                                stdout=b"",
                                stderr=b"",
                            )

                    runner = InventoryOnlyRunner()
                    with self.assertRaises(IOSPacketLanPeerError) as raised:
                        ios_packet_lan_peer_adapter.admit_ios_packet_lan_peer(
                            runner=runner,
                            tokens=("s" + "a" * 19, "t" + "b" * 19, "e" + "c" * 19),
                            expected_source=source,
                            time_source=lambda: datetime(2026, 8, 22, tzinfo=timezone.utc),
                        )
                    self.assertEqual(raised.exception.code, expected_code)
                    self.assertEqual(runner.roles, ["ios-peer-device-list"])
                    self.assertIsNotNone(runner.workspace)
                    self.assertFalse(runner.workspace.exists())
                    self.assertFalse(ios_packet_lan_peer_adapter._SOURCE_LOCK.locked())

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
