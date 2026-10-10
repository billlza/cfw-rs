from __future__ import annotations

import hashlib
import json
import os
import plistlib
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.harness.raw_artifacts import canonical_json
from scripts.physical_capture.execution import CommandSpec
from scripts.physical_capture.ios_packet_lan_peer import (
    DEVICE_DIRECTORY as PACKET_LAN_DEVICE_DIRECTORY,
    DIRECTORY_NAME as PACKET_LAN_DIRECTORY_NAME,
    EVIDENCE_ROLE as PACKET_LAN_EVIDENCE_ROLE,
    LAUNCH_ARGUMENT as PACKET_LAN_LAUNCH_ARGUMENT,
    LISTENER_PORT as PACKET_LAN_LISTENER_PORT,
    READY_DOCUMENT as PACKET_LAN_READY_DOCUMENT,
    SCHEMA_VERSION as PACKET_LAN_SCHEMA_VERSION,
    TRANSPORT as PACKET_LAN_TRANSPORT,
    create_session as create_packet_lan_session,
    validate_session as validate_packet_lan_session,
)
from scripts.physical_capture.ios_transport_peer import (
    APP_EXECUTABLE,
    BUNDLE_IDENTIFIER,
    CERTIFICATE_FILE_NAME,
    PRIMER_LAUNCH_ARGUMENT,
    PRIMER_RESULT_FILE_NAME,
    PRIVATE_KEY_FILE_NAME,
    SESSION_DIRECTORY_NAME,
    SESSION_FILE_NAME,
    TRANSPORT_RUN_ARGUMENT,
    IOSPeerArtifact,
    IOSPeerCommandPlan,
    IOSPeerContractError,
    IOSPeerDevice,
    IOSPeerInstallationOwnership,
    IOSPeerPreflight,
    IOSPeerPrimerProcessCleanupAuthority,
    IOSPeerPrimerProcessOwnership,
    IOSPeerProcessOwnership,
    PrimerStoppedOwnership,
    device_identifier_sha256,
    provisioning_udid_sha256,
    transport_payload_receipt_sha256,
    validate_result_receipt,
)
from scripts.physical_capture.ios_transport_peer_lab import (
    AppInventory,
    AppInventoryEntry,
    DeviceAdmission,
    DevicectlRuntime,
    DeviceProcess,
    IOSPeerLabError,
    IOSPeerSigningCommandPlan,
    IOSPeerSigningInputs,
    IOSPeerTransactionInputs,
    IOSPeerTransactionJournal,
    IOSPeerTransactionState,
    LegacyCFWExpectedState,
    LegacyCFWGuardPlan,
    LegacyProxyConfiguration,
    ManualSigningAuthorization,
    PrimerLaunchObservation,
    PrimerRetryAuthorization,
    ProcessInventory,
    ProcessTerminationObservation,
    SessionCopyObservation,
    UninstallObservation,
    authorize_cleanup_only_installation,
    authorize_exceptional_process_cleanup,
    authorize_packet_lan_process_cleanup,
    authorize_primer_process_cleanup,
    authorize_single_primer_retry,
    bind_primer_process,
    bind_packet_lan_process,
    bind_stopped_primer,
    bind_transport_process,
    build_legacy_cfw_guard_snapshot,
    build_preflight,
    inspect_ios_peer_artifact,
    minimal_entitlements_plist,
    parse_app_inventory,
    parse_decoded_provisioning_profile,
    parse_device_admission,
    parse_install_receipt,
    parse_lock_state,
    parse_packet_lan_launch_receipt,
    parse_packet_lan_session_copy_receipt,
    parse_packet_lan_terminate_receipt,
    parse_primer_launch_receipt,
    parse_primer_terminate_receipt,
    parse_process_inventory,
    parse_route_to_peer,
    parse_session_copy_receipt,
    parse_transport_launch_receipt,
    parse_transport_terminate_receipt,
    parse_uninstall_receipt,
    validate_codesign_details,
    validate_copied_receipt,
    validate_embedded_profile,
    validate_executable_architectures,
    validate_executable_build_version,
    validate_keychain_certificate_pem,
    validate_packet_lan_session_material,
    validate_session_material,
    verify_legacy_cfw_unchanged,
    verify_post_uninstall_absence,
    verify_transport_pair,
    _validate_local_directory_copy_source,
)

DEVICE = "A0D0DA54-90DF-58E3-92B4-146CECE10AC7"
PROVISIONING_UDID = "00008110-0012345678901234"
SESSION_ID = "1" * 64
CERTIFICATE_SHA256 = "2" * 64
APP_TREE_SHA256 = "3" * 64
LAUNCH_IDENTIFIER = "bGF1bmNoLXNlcnZpY2VzLWlkZW50aWZpZXI="
REMOTE_APP = (
    "/private/var/containers/Bundle/Application/"
    "11111111-2222-3333-4444-555555555555/CFMPhysicalTransportPeer.app"
)
REMOTE_APP_URL = f"file://{REMOTE_APP}/"
REMOTE_EXECUTABLE = f"{REMOTE_APP}/{APP_EXECUTABLE}"
REMOTE_SESSION = (
    "/private/var/mobile/Containers/Data/Application/"
    "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE/Documents/CFMTransportPeer"
)
REMOTE_PACKET_LAN_SESSION = (
    "/private/var/mobile/Containers/Data/Application/"
    "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE/"
    f"{PACKET_LAN_DEVICE_DIRECTORY}"
)
NOW = datetime(2026, 8, 21, 5, 6, 7, 123456, tzinfo=timezone.utc)
RUNTIME = DevicectlRuntime("642.9.1", 5)


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _device_timestamp(value: datetime) -> str:
    return f"{value.strftime('%Y-%m-%dT%H:%M:%S')}.{value.microsecond // 1000:03d}Z"


def _device() -> IOSPeerDevice:
    return IOSPeerDevice(
        DEVICE,
        device_identifier_sha256(DEVICE),
        PROVISIONING_UDID,
        provisioning_udid_sha256(PROVISIONING_UDID),
    )


def _device_admission() -> DeviceAdmission:
    return DeviceAdmission(
        receipt_sha256="d" * 64,
        core_device_identifier=DEVICE,
        provisioning_udid=PROVISIONING_UDID,
        platform="iOS",
        reality="physical",
        cpu_name="arm64",
        control_transport="localNetwork",
        authentication_type="manualPairing",
        tunnel_transport_protocol="tcp",
    )


def _artifact(root: Path) -> IOSPeerArtifact:
    app = root / f"{APP_EXECUTABLE}.app"
    app.mkdir()
    (app / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "CFBundleExecutable": APP_EXECUTABLE,
                "CFBundleIdentifier": BUNDLE_IDENTIFIER,
            }
        )
    )
    executable = app / APP_EXECUTABLE
    executable.write_bytes(b"fixed arm64 peer")
    executable.chmod(0o755)
    return inspect_ios_peer_artifact(app)


def _envelope(spec: CommandSpec, command_type: str, result: dict[str, object]) -> bytes:
    return canonical_json(
        {
            "info": {
                "arguments": list(spec.argv[1:]),
                "commandType": command_type,
                "environment": {"TERM": "dumb"},
                "jsonVersion": RUNTIME.json_version,
                "outcome": "success",
                "version": RUNTIME.version,
            },
            "result": result,
        }
    )


def _app_item(bundle: str | None = None, url: str | None = None) -> dict[str, object]:
    return {
        "appClip": False,
        "builtByDeveloper": bundle == BUNDLE_IDENTIFIER,
        "bundleIdentifier": bundle,
        "bundleVersion": "1" if bundle else None,
        "containerAccessible": bundle == BUNDLE_IDENTIFIER,
        "defaultApp": False,
        "hidden": False,
        "internalApp": False,
        "name": APP_EXECUTABLE if bundle else "Other",
        "removable": bundle == BUNDLE_IDENTIFIER,
        "url": url,
        "version": "1.0" if bundle else None,
    }


def _app_result(entries: list[dict[str, object]]) -> dict[str, object]:
    return {
        "apps": entries,
        "defaultAppsIncluded": True,
        "deviceIdentifier": DEVICE,
        "hiddenAppsIncluded": False,
        "internalAppsIncluded": False,
        "matchingBundleIdentifier": BUNDLE_IDENTIFIER,
        "removableAppsIncluded": True,
    }


def _process_result(entries: list[dict[str, object]]) -> dict[str, object]:
    return {"deviceIdentifier": DEVICE, "runningProcesses": entries}


def _launch_result(argument: str, process_id: int) -> dict[str, object]:
    return {
        "deviceIdentifier": DEVICE,
        "launchOptions": {
            "activatedWhenStarted": True,
            "arguments": [argument],
            "environmentVariables": {"TERM": "vt100"},
            "platformSpecificOptions": {},
            "startStopped": False,
            "terminateExistingInstances": False,
            "user": {"active": True},
        },
        "process": {
            "executable": f"file://{REMOTE_EXECUTABLE}",
            "processIdentifier": process_id,
        },
    }


def _terminate_result(process_id: int) -> dict[str, object]:
    return {
        "deviceIdentifier": DEVICE,
        "deviceTimestamp": _device_timestamp(NOW),
        "process": {
            "executable": f"file://{REMOTE_EXECUTABLE}",
            "processIdentifier": process_id,
        },
        "signal": {"name": "SIGTERM", "value": 15},
    }


def _session_copy_result(session_directory: Path) -> dict[str, object]:
    source = f"{session_directory.as_uri()}/"
    return {
        "destination": f"file://{REMOTE_SESSION}",
        "deviceIdentifier": DEVICE,
        "domain": "appDataContainer",
        "domainIdentifier": BUNDLE_IDENTIFIER,
        "file": {
            "metadata": {
                "extendedAttributes": {},
                "lastModDate": _device_timestamp(NOW),
                "ownerGid": 501,
                "ownerUid": 501,
                "permissions": 0o755,
                "size": 160,
            },
            "name": REMOTE_SESSION,
            "relativePath": REMOTE_SESSION,
            "resources": {
                "isDirectory": True,
                "isHidden": False,
                "isReadable": True,
                "isSymbolicLink": False,
                "isWritable": True,
            },
        },
        "source": source,
        "sources": [source],
    }


def _session_material(root: Path):
    directory = root / SESSION_DIRECTORY_NAME
    directory.mkdir(mode=0o700)
    certificate = b"fixed test certificate"
    private_key = b"\x04" + b"k" * 96
    certificate_sha256 = hashlib.sha256(certificate).hexdigest()
    private_key_sha256 = hashlib.sha256(private_key).hexdigest()
    session = (
        canonical_json(
            {
                "certificate_sha256": certificate_sha256,
                "created_at": _timestamp(NOW - timedelta(seconds=1)),
                "document": "cfm-ios-transport-peer-session-v1",
                "expires_at": _timestamp(NOW + timedelta(minutes=10)),
                "private_key_sha256": private_key_sha256,
                "schema_version": 1,
                "session_id": SESSION_ID,
            }
        )
        + b"\n"
    )
    for name, data in (
        (CERTIFICATE_FILE_NAME, certificate),
        (PRIVATE_KEY_FILE_NAME, private_key),
        (SESSION_FILE_NAME, session),
    ):
        path = directory / name
        path.write_bytes(data)
        path.chmod(0o600)
    return validate_session_material(
        directory,
        expected_session_id=SESSION_ID,
        now=NOW,
    )


def _packet_lan_material(root: Path):
    tokens = (
        "s0123456789abcdef012",
        "t0123456789abcdef012",
        "e0123456789abcdef012",
    )
    session_bytes = create_packet_lan_session(
        tokens=tokens,
        now=NOW - timedelta(seconds=1),
    )
    session = validate_packet_lan_session(session_bytes, now=NOW)
    directory = root / PACKET_LAN_DIRECTORY_NAME
    directory.mkdir(mode=0o700)
    session_path = directory / "session.json"
    session_path.write_bytes(session_bytes)
    session_path.chmod(0o600)
    material = validate_packet_lan_session_material(
        directory,
        expected_session_id=session["session_id"],
        now=NOW,
    )
    return material, session_bytes, session


def _packet_lan_ready(
    session: dict[str, object], process_id: int = 4330
) -> bytes:
    return (
        canonical_json(
            {
                "schema_version": PACKET_LAN_SCHEMA_VERSION,
                "document": PACKET_LAN_READY_DOCUMENT,
                "evidence_role": PACKET_LAN_EVIDENCE_ROLE,
                "claim_eligible": False,
                "session_id": session["session_id"],
                "bundle_identifier": BUNDLE_IDENTIFIER,
                "process_id": process_id,
                "started_at": _timestamp(NOW - timedelta(microseconds=500_000)),
                "expires_at": session["expires_at"],
                "network": {"interface_name": "en0", "ipv4": "192.168.1.20"},
                "listener": {
                    "port": PACKET_LAN_LISTENER_PORT,
                    "transport": PACKET_LAN_TRANSPORT,
                },
                "session_file_removed": True,
            }
        )
        + b"\n"
    )


def _packet_lan_session_copy_result(
    session_directory: Path,
) -> dict[str, object]:
    source = f"{session_directory.as_uri()}/"
    return {
        "destination": f"file://{REMOTE_PACKET_LAN_SESSION}",
        "deviceIdentifier": DEVICE,
        "domain": "appDataContainer",
        "domainIdentifier": BUNDLE_IDENTIFIER,
        "file": {
            "metadata": {
                "extendedAttributes": {},
                "lastModDate": _device_timestamp(NOW),
                "ownerGid": 501,
                "ownerUid": 501,
                "permissions": 0o755,
                "size": 128,
            },
            "name": REMOTE_PACKET_LAN_SESSION,
            "relativePath": REMOTE_PACKET_LAN_SESSION,
            "resources": {
                "isDirectory": True,
                "isHidden": False,
                "isReadable": True,
                "isSymbolicLink": False,
                "isWritable": True,
            },
        },
        "source": source,
        "sources": [source],
    }


def _primer(process_id: int = 4310) -> bytes:
    return (
        canonical_json(
            {
                "bundle_identifier": BUNDLE_IDENTIFIER,
                "claim_eligible": False,
                "document": "cfm-ios-transport-peer-primer-result-v1",
                "listener": {
                    "bonjour_domain": "local.",
                    "bonjour_name": "CFM Transport Primer",
                    "bonjour_type": "_cfm-primer._tcp",
                    "port": 44332,
                    "transport": "tcp4",
                },
                "listener_cancelled": True,
                "listener_cancelled_at": _timestamp(NOW),
                "listener_ready": True,
                "listener_ready_at": _timestamp(NOW - timedelta(seconds=1)),
                "mode": "local_network_permission_primer",
                "network": {"interface_name": "en0", "ipv4": "192.168.1.20"},
                "process_id": process_id,
                "schema_version": 1,
                "service_registered": True,
                "service_registered_at": _timestamp(NOW - timedelta(seconds=2)),
                "started_at": _timestamp(NOW - timedelta(seconds=3)),
            }
        )
        + b"\n"
    )


def _ready(process_id: int = 4321) -> bytes:
    return (
        canonical_json(
            {
                "bundle_identifier": BUNDLE_IDENTIFIER,
                "certificate_sha256": CERTIFICATE_SHA256,
                "document": "cfm-ios-transport-peer-ready-v1",
                "expires_at": _timestamp(NOW + timedelta(minutes=10)),
                "listeners": {
                    "quic_echo": {
                        "alpn": "cfm-transport-peer-quic/1",
                        "port": 44335,
                        "transport": "quic-tls13",
                    },
                    "tcp_sink": {"alpn": None, "port": 44333, "transport": "tcp4"},
                    "tls13_echo": {
                        "alpn": "cfm-transport-peer-tls/1",
                        "port": 44334,
                        "transport": "tls13-tcp4",
                    },
                },
                "network": {"interface_name": "en0", "ipv4": "192.168.1.20"},
                "process_id": process_id,
                "schema_version": 1,
                "session_id": SESSION_ID,
                "started_at": _timestamp(NOW - timedelta(seconds=1)),
            }
        )
        + b"\n"
    )


class SigningContractTests(unittest.TestCase):
    def test_profile_binding_accepts_current_apple_multiplatform_wildcard_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            artifact = _artifact(root)
            profile_path = root / "peer.mobileprovision"
            profile_path.write_bytes(b"signed cms profile")
            (artifact.app_path / "embedded.mobileprovision").write_bytes(
                profile_path.read_bytes()
            )
            keychain_path = root / "lab.keychain-db"
            keychain_path.write_bytes(b"keychain")
            certificate = b"certificate DER"
            inputs = IOSPeerSigningInputs(
                profile_path=profile_path,
                profile_sha256=hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                keychain_path=keychain_path,
                signing_identity_sha1="A" * 40,
                signing_identity_label="Apple Development: Lab",
                signing_certificate_sha256=hashlib.sha256(certificate).hexdigest(),
                team_identifier="ABCDEFGHIJ",
            )
            decoded = plistlib.dumps(
                {
                    "CreationDate": (NOW - timedelta(days=1)).replace(tzinfo=None),
                    "DeveloperCertificates": [certificate],
                    "Entitlements": {
                        "application-identifier": "ABCDEFGHIJ.*",
                        "com.apple.developer.team-identifier": "ABCDEFGHIJ",
                        "get-task-allow": True,
                    },
                    "ExpirationDate": (NOW + timedelta(days=1)).replace(tzinfo=None),
                    "Name": "Existing lab profile",
                    "Platform": ["iOS", "xrOS", "visionOS"],
                    "ProvisionedDevices": [PROVISIONING_UDID],
                    "TeamIdentifier": ["ABCDEFGHIJ"],
                    "UUID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                }
            )
            profile = parse_decoded_provisioning_profile(
                decoded, inputs=inputs, device=_device(), now=NOW
            )
            self.assertEqual(profile.uuid, "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
            entitlements = plistlib.loads(minimal_entitlements_plist(profile))
            self.assertEqual(
                entitlements["application-identifier"],
                f"ABCDEFGHIJ.{BUNDLE_IDENTIFIER}",
            )
            self.assertIs(entitlements["get-task-allow"], True)

            pem = (
                b"-----BEGIN CERTIFICATE-----\n"
                + __import__("base64").b64encode(certificate)
                + b"\n-----END CERTIFICATE-----\n"
            )
            validate_keychain_certificate_pem(pem, inputs=inputs)

            xcent = root / "peer.xcent"
            xcent.write_bytes(minimal_entitlements_plist(profile))
            authorization = ManualSigningAuthorization(
                profile.uuid,
                artifact.app_tree_sha256,
                hashlib.sha256(xcent.read_bytes()).hexdigest(),
                True,
            )
            plan = IOSPeerSigningCommandPlan(root, artifact, inputs)
            commands = [
                plan.decode_profile(root / "decoded.plist"),
                plan.export_keychain_certificate(),
                plan.verify_signature(),
                plan.signature_details(),
                plan.signature_entitlements(),
                plan.executable_architectures(),
                plan.executable_build_version(),
                plan.manual_sign(profile, xcent, authorization),
            ]
            flattened = "\n".join(" ".join(command.argv) for command in commands)
            self.assertNotIn(":-", plan.signature_entitlements().argv)
            for forbidden in (
                "allowProvisioningUpdates",
                "profile install",
                "manage pair",
                "CODE_SIGN_STYLE=Automatic",
            ):
                self.assertNotIn(forbidden, flattened)
            details = (
                f"Identifier={BUNDLE_IDENTIFIER}\n"
                "TeamIdentifier=ABCDEFGHIJ\n"
                "Authority=Apple Development: Lab\n"
                "Authority=Apple Worldwide Developer Relations Certification Authority\n"
                "Authority=Apple Root CA\n"
                f"CDHash={'a' * 40}\n"
                "Signature size=4788\n"
            ).encode()
            self.assertEqual(
                validate_codesign_details(details, inputs=inputs), "a" * 40
            )
            self.assertEqual(
                validate_embedded_profile(artifact, inputs=inputs),
                inputs.profile_sha256,
            )
            with self.assertRaises(IOSPeerLabError):
                validate_codesign_details(
                    details.replace(b"Signature size=4788", b"Signature=adhoc"),
                    inputs=inputs,
                )
            profile_path.write_bytes(b"drifted profile")
            with self.assertRaises(IOSPeerLabError):
                validate_embedded_profile(artifact, inputs=inputs)
            profile_path.write_bytes(b"signed cms profile")
            validate_executable_architectures(b"arm64\n")
            validate_executable_build_version(
                b"Load command 9\n cmd LC_BUILD_VERSION\n platform IOS\n minos 17.0\n"
            )
            with self.assertRaises(IOSPeerLabError):
                validate_executable_architectures(b"x86_64 arm64\n")

            bad = plistlib.loads(decoded)
            bad["Entitlements"]["get-task-allow"] = False
            with self.assertRaises(IOSPeerLabError):
                parse_decoded_provisioning_profile(
                    plistlib.dumps(bad), inputs=inputs, device=_device(), now=NOW
                )
            (artifact.app_path / "Frameworks").mkdir()
            with self.assertRaises(IOSPeerLabError):
                inspect_ios_peer_artifact(artifact.app_path)


class DevicectlOwnershipTests(unittest.TestCase):
    def test_copy_source_accepts_only_same_private_directory_alias(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as root_text:
            root = Path(root_text)
            expected = root / PACKET_LAN_DIRECTORY_NAME
            expected.mkdir(mode=0o700)
            alias_path = Path(str(expected).replace("/private/tmp/", "/tmp/", 1))
            alias_url = f"{alias_path.as_uri()}/"
            _validate_local_directory_copy_source(
                alias_url,
                [alias_url],
                expected_directory=expected,
                label="packet LAN copy",
            )

            other = root / "other" / PACKET_LAN_DIRECTORY_NAME
            other.parent.mkdir(mode=0o700)
            other.mkdir(mode=0o700)
            other_url = f"{other.as_uri()}/"
            with self.assertRaisesRegex(IOSPeerLabError, "another directory"):
                _validate_local_directory_copy_source(
                    other_url,
                    [other_url],
                    expected_directory=expected,
                    label="packet LAN copy",
                )
            with self.assertRaisesRegex(IOSPeerLabError, "one URL"):
                _validate_local_directory_copy_source(
                    alias_url,
                    [alias_url, alias_url],
                    expected_directory=expected,
                    label="packet LAN copy",
                )

    def test_device_details_separately_bind_coredevice_and_provisioning_ids(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            plan = IOSPeerCommandPlan(root, _device(), _artifact(root))
            details_spec = plan.device_details(root / "device-details.json")
            result = {
                "capabilities": [],
                "identifier": DEVICE,
                "properties": {
                    "connection": {
                        "authenticationType": "manualPairing",
                        "lastConnectionDate": 1,
                        "pairingState": "paired",
                        "screenViewingURL": {},
                        "state": "connected",
                        "transportType": "localNetwork",
                        "tunnelIPAddressString": "192.168.1.2",
                        "tunnelTransportProtocol": "tcp",
                    },
                    "hardware": {
                        "cpuType": {
                            "subtype": 18_446_744_071_562_067_970,
                            "type": 16_777_228,
                        },
                        "deviceType": "iPhone",
                        "platform": "iOS",
                        "reality": "physical",
                        "supportedCPUTypes": [
                            {
                                "subtype": 18_446_744_071_562_067_970,
                                "type": 16_777_228,
                            }
                        ],
                        "supportedDeviceFamilies": [1],
                        "udid": PROVISIONING_UDID,
                    },
                    "software": {
                        "osBuildVersions": {},
                        "osVersionNumber": {
                            "components": [26, 5, 0, 0, 0],
                            "originalComponentsCount": 2,
                            "stringValue": "26.5",
                        },
                        "supportsCheckedAllocations": False,
                    },
                    "state": {
                        "bootState": "booted",
                        "developerModeStatus": {"enabled": {"mode": 1}},
                        "name": "Lab iPhone",
                        "preparednessState": 7,
                    },
                },
                "propertyDisplayNames": None,
                "visibilityClass": "default",
            }
            admission = parse_device_admission(
                _envelope(details_spec, "devicectl.device.info.details", result),
                spec=details_spec,
                runtime=RUNTIME,
                device=_device(),
            )
            self.assertEqual(admission.core_device_identifier, DEVICE)
            self.assertEqual(admission.provisioning_udid, PROVISIONING_UDID)
            self.assertEqual(admission.control_transport, "localNetwork")
            self.assertEqual(admission.authentication_type, "manualPairing")
            result["properties"]["connection"]["transportType"] = "wired"
            with self.assertRaises(IOSPeerLabError):
                parse_device_admission(
                    _envelope(details_spec, "devicectl.device.info.details", result),
                    spec=details_spec,
                    runtime=RUNTIME,
                    device=_device(),
                )
            result["properties"]["connection"]["transportType"] = "unknown"
            with self.assertRaises(IOSPeerLabError):
                parse_device_admission(
                    _envelope(details_spec, "devicectl.device.info.details", result),
                    spec=details_spec,
                    runtime=RUNTIME,
                    device=_device(),
                )
            result["properties"]["connection"]["transportType"] = "localNetwork"
            result["properties"]["connection"]["authenticationType"] = "none"
            with self.assertRaises(IOSPeerLabError):
                parse_device_admission(
                    _envelope(details_spec, "devicectl.device.info.details", result),
                    spec=details_spec,
                    runtime=RUNTIME,
                    device=_device(),
                )
            result["properties"]["connection"]["authenticationType"] = "manualPairing"
            result["properties"]["hardware"]["udid"] = "00008110-FFFFFFFFFFFFFFFF"
            with self.assertRaises(IOSPeerLabError):
                parse_device_admission(
                    _envelope(details_spec, "devicectl.device.info.details", result),
                    spec=details_spec,
                    runtime=RUNTIME,
                    device=_device(),
                )

            lock_spec = plan.lock_state(root / "lock-state.json")
            digest = parse_lock_state(
                _envelope(
                    lock_spec,
                    "devicectl.device.info.lockState",
                    {
                        "deviceIdentifier": DEVICE,
                        "passcodeRequired": True,
                        "unlockedSinceBoot": True,
                    },
                ),
                spec=lock_spec,
                runtime=RUNTIME,
                device=_device(),
            )
            self.assertEqual(len(digest), 64)

    def test_full_inventory_install_launch_cleanup_chain(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            artifact = _artifact(root)
            plan = IOSPeerCommandPlan(root, _device(), artifact)

            app_before_spec = plan.app_inventory(root / "app-inventory-before.json")
            process_before_spec = plan.process_inventory(
                root / "process-inventory-before.json"
            )
            app_before = parse_app_inventory(
                _envelope(
                    app_before_spec, "devicectl.device.info.apps", _app_result([])
                ),
                spec=app_before_spec,
                runtime=RUNTIME,
                device=_device(),
            )
            process_before = parse_process_inventory(
                _envelope(
                    process_before_spec,
                    "devicectl.device.info.processes",
                    _process_result([]),
                ),
                spec=process_before_spec,
                runtime=RUNTIME,
                device=_device(),
            )
            preflight = build_preflight(
                app_inventory=app_before,
                process_inventory=process_before,
                device=_device(),
                observed_at=NOW,
            )

            install_spec = plan.install(preflight, root / "install.json")
            post_app_spec = plan.app_inventory(root / "app-inventory-installed.json")
            post_app_bytes = _envelope(
                post_app_spec,
                "devicectl.device.info.apps",
                _app_result([_app_item(BUNDLE_IDENTIFIER, REMOTE_APP_URL)]),
            )
            post_app = parse_app_inventory(
                post_app_bytes, spec=post_app_spec, runtime=RUNTIME, device=_device()
            )
            install_bytes = _envelope(
                install_spec,
                "devicectl.device.install.app",
                {
                    "deviceIdentifier": DEVICE,
                    "installedApplications": [
                        {
                            "bundleID": BUNDLE_IDENTIFIER,
                            "databaseSequenceNumber": 7,
                            "databaseUUID": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
                            "installationURL": REMOTE_APP_URL,
                            "launchServicesIdentifier": "unknown",
                            "options": {},
                        }
                    ],
                },
            )
            installation = parse_install_receipt(
                install_bytes,
                spec=install_spec,
                runtime=RUNTIME,
                device=_device(),
                artifact=artifact,
                post_install_inventory=post_app,
                installed_at=NOW,
            )
            primer_launch_spec = plan.launch_primer(
                installation, root / "primer-launch.json"
            )
            self.assertNotIn("--launch-persistent-identifier", primer_launch_spec.argv)
            self.assertNotIn("unknown", primer_launch_spec.argv)
            primer_launch = parse_primer_launch_receipt(
                _envelope(
                    primer_launch_spec,
                    "devicectl.device.process.launch",
                    _launch_result(PRIMER_LAUNCH_ARGUMENT, 4310),
                ),
                spec=primer_launch_spec,
                runtime=RUNTIME,
                device=_device(),
                installation=installation,
            )
            primer_process_spec = plan.process_inventory(
                root / "process-inventory-primer.json"
            )
            primer_processes = parse_process_inventory(
                _envelope(
                    primer_process_spec,
                    "devicectl.device.info.processes",
                    _process_result(
                        [
                            {
                                "executable": f"file://{REMOTE_EXECUTABLE}",
                                "processIdentifier": 4310,
                            },
                            {
                                "executable": "file:///usr/libexec/other",
                                "processIdentifier": 99,
                            },
                        ]
                    ),
                ),
                spec=primer_process_spec,
                runtime=RUNTIME,
                device=_device(),
            )
            primer_ownership = bind_primer_process(
                launch=primer_launch,
                process_inventory=primer_processes,
                primer_receipt=_primer(4310),
                installation=installation,
                device=_device(),
                artifact=artifact,
                now=NOW,
            )
            primer_cleanup = authorize_primer_process_cleanup(
                ownership=primer_ownership,
                fresh_inventory=primer_processes,
                fresh_primer_receipt=_primer(4310),
                device=_device(),
                observed_at=NOW,
            )
            primer_terminate = plan.terminate_primer(
                primer_cleanup, root / "primer-terminate.json"
            )
            self.assertEqual(
                primer_terminate.argv[primer_terminate.argv.index("--pid") + 1],
                "4310",
            )
            primer_termination = parse_primer_terminate_receipt(
                _envelope(
                    primer_terminate,
                    "devicectl.device.process.terminate",
                    _terminate_result(4310),
                ),
                spec=primer_terminate,
                runtime=RUNTIME,
                device=_device(),
                authority=primer_cleanup,
            )
            self.assertEqual(primer_termination.signal_name, "SIGTERM")
            rejected_signal = _terminate_result(4310)
            rejected_signal["signal"] = {"name": "SIGKILL", "value": 9}
            with self.assertRaises(IOSPeerLabError):
                parse_primer_terminate_receipt(
                    _envelope(
                        primer_terminate,
                        "devicectl.device.process.terminate",
                        rejected_signal,
                    ),
                    spec=primer_terminate,
                    runtime=RUNTIME,
                    device=_device(),
                    authority=primer_cleanup,
                )
            post_primer_spec = plan.process_inventory(
                root / "process-inventory-primer-stopped.json"
            )
            post_primer_inventory = parse_process_inventory(
                _envelope(
                    post_primer_spec,
                    "devicectl.device.info.processes",
                    _process_result(
                        [
                            {
                                "executable": "file:///usr/libexec/other",
                                "processIdentifier": 99,
                            }
                        ]
                    ),
                ),
                spec=post_primer_spec,
                runtime=RUNTIME,
                device=_device(),
            )
            with self.assertRaises(IOSPeerLabError):
                bind_stopped_primer(
                    authority=primer_cleanup,
                    termination=primer_termination,
                    post_terminate_inventory=primer_processes,
                    device=_device(),
                    observed_at=NOW,
                )
            stopped = bind_stopped_primer(
                authority=primer_cleanup,
                termination=primer_termination,
                post_terminate_inventory=post_primer_inventory,
                device=_device(),
                observed_at=NOW,
            )
            material = _session_material(root)
            session_copy = plan.copy_session_to_device(
                stopped, material.directory, root / "session-copy.json"
            )
            self.assertEqual(session_copy.role, "ios-peer-session-copy")
            copy_observation = parse_session_copy_receipt(
                _envelope(
                    session_copy,
                    "devicectl.device.copy.to",
                    _session_copy_result(material.directory),
                ),
                spec=session_copy,
                runtime=RUNTIME,
                device=_device(),
                stopped_primer=stopped,
                material=material,
            )
            self.assertEqual(copy_observation.session_id, SESSION_ID)

            launch_spec = plan.launch_transport(
                installation, root / "transport-launch.json"
            )
            launch_bytes = _envelope(
                launch_spec,
                "devicectl.device.process.launch",
                _launch_result(TRANSPORT_RUN_ARGUMENT, 4321),
            )
            launch = parse_transport_launch_receipt(
                launch_bytes,
                spec=launch_spec,
                runtime=RUNTIME,
                device=_device(),
                installation=installation,
            )
            process_spec = plan.process_inventory(
                root / "process-inventory-launched.json"
            )
            process_bytes = _envelope(
                process_spec,
                "devicectl.device.info.processes",
                _process_result(
                    [
                        {
                            "executable": f"file://{REMOTE_EXECUTABLE}",
                            "processIdentifier": 4321,
                        },
                        {
                            "executable": "file:///usr/libexec/other",
                            "processIdentifier": 99,
                        },
                    ]
                ),
            )
            processes = parse_process_inventory(
                process_bytes, spec=process_spec, runtime=RUNTIME, device=_device()
            )
            ownership = bind_transport_process(
                launch=launch,
                process_inventory=processes,
                ready_receipt=_ready(),
                installation=installation,
                device=_device(),
                artifact=artifact,
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                now=NOW,
            )
            authority = authorize_exceptional_process_cleanup(
                ownership=ownership,
                fresh_inventory=processes,
                fresh_ready_receipt=_ready(),
                expected_certificate_sha256=CERTIFICATE_SHA256,
                observed_at=NOW,
            )
            terminate = plan.terminate(authority, root / "terminate.json")
            self.assertIn("4321", terminate.argv)
            transport_termination = parse_transport_terminate_receipt(
                _envelope(
                    terminate,
                    "devicectl.device.process.terminate",
                    _terminate_result(4321),
                ),
                spec=terminate,
                runtime=RUNTIME,
                device=_device(),
                authority=authority,
            )
            self.assertEqual(transport_termination.process_id, 4321)

            uninstall_spec = plan.uninstall(installation, root / "uninstall.json")
            uninstall = parse_uninstall_receipt(
                _envelope(
                    uninstall_spec,
                    "devicectl.device.uninstall.app",
                    {
                        "deviceIdentifier": DEVICE,
                        "uninstalledApplications": [{"bundleID": BUNDLE_IDENTIFIER}],
                    },
                ),
                spec=uninstall_spec,
                runtime=RUNTIME,
                device=_device(),
                installation=installation,
            )
            self.assertEqual(uninstall.bundle_identifier, BUNDLE_IDENTIFIER)
            verify_post_uninstall_absence(
                app_inventory=app_before,
                process_inventory=process_before,
                device=_device(),
                ownership=ownership,
            )

    def test_packet_lan_copy_launch_ownership_and_cleanup_chain(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            artifact = _artifact(root)
            plan = IOSPeerCommandPlan(root, _device(), artifact)
            installation = IOSPeerInstallationOwnership(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_tree_sha256=artifact.app_tree_sha256,
                install_receipt_sha256="1" * 64,
                app_inventory_receipt_sha256="2" * 64,
                launch_services_identifier=LAUNCH_IDENTIFIER,
                installed_at=_timestamp(NOW),
            )
            primer_process = IOSPeerPrimerProcessOwnership(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_tree_sha256=artifact.app_tree_sha256,
                process_id=4310,
                launch_services_identifier=LAUNCH_IDENTIFIER,
                executable_path=REMOTE_EXECUTABLE,
                launch_receipt_sha256="3" * 64,
                process_inventory_receipt_sha256="4" * 64,
                primer_receipt_sha256="5" * 64,
            )
            stopped = PrimerStoppedOwnership(
                process=primer_process,
                terminate_receipt_sha256="6" * 64,
                post_terminate_process_inventory_receipt_sha256="7" * 64,
                stopped_at=_timestamp(NOW),
                process_absent=True,
            )
            material, session_bytes, session = _packet_lan_material(root)

            extra = material.directory / "unexpected"
            extra.write_bytes(b"unsafe")
            extra.chmod(0o600)
            with self.assertRaises(IOSPeerLabError):
                validate_packet_lan_session_material(
                    material.directory,
                    expected_session_id=material.session_id,
                    now=NOW,
                )
            extra.unlink()

            copy_spec = plan.copy_packet_lan_session_to_device(
                stopped,
                material.directory,
                root / "packet-lan-session-copy.json",
            )
            copy_observation = parse_packet_lan_session_copy_receipt(
                _envelope(
                    copy_spec,
                    "devicectl.device.copy.to",
                    _packet_lan_session_copy_result(material.directory),
                ),
                spec=copy_spec,
                runtime=RUNTIME,
                device=_device(),
                stopped_primer=stopped,
                material=material,
            )
            self.assertEqual(copy_observation.session_sha256, material.session_sha256)

            launch_spec = plan.launch_packet_lan(
                installation,
                root / "packet-lan-launch.json",
            )
            launch_bytes = _envelope(
                launch_spec,
                "devicectl.device.process.launch",
                _launch_result(PACKET_LAN_LAUNCH_ARGUMENT, 4330),
            )
            launch = parse_packet_lan_launch_receipt(
                launch_bytes,
                spec=launch_spec,
                runtime=RUNTIME,
                device=_device(),
                installation=installation,
            )
            with self.assertRaises(IOSPeerLabError):
                parse_transport_launch_receipt(
                    launch_bytes,
                    spec=launch_spec,
                    runtime=RUNTIME,
                    device=_device(),
                    installation=installation,
                )

            process_spec = plan.process_inventory(
                root / "process-inventory-packet-lan.json"
            )
            processes = parse_process_inventory(
                _envelope(
                    process_spec,
                    "devicectl.device.info.processes",
                    _process_result(
                        [
                            {
                                "executable": f"file://{REMOTE_EXECUTABLE}",
                                "processIdentifier": 4330,
                            },
                            {
                                "executable": "file:///usr/libexec/other",
                                "processIdentifier": 99,
                            },
                        ]
                    ),
                ),
                spec=process_spec,
                runtime=RUNTIME,
                device=_device(),
            )
            ready_bytes = _packet_lan_ready(session)
            ownership = bind_packet_lan_process(
                launch=launch,
                process_inventory=processes,
                session_document=session_bytes,
                ready_receipt=ready_bytes,
                material=material,
                installation=installation,
                device=_device(),
                artifact=artifact,
                now=NOW,
            )
            self.assertEqual(ownership.process_id, 4330)
            self.assertEqual(ownership.session_id, material.session_id)

            with self.assertRaises(IOSPeerLabError):
                bind_packet_lan_process(
                    launch=launch,
                    process_inventory=processes,
                    session_document=session_bytes + b" ",
                    ready_receipt=ready_bytes,
                    material=material,
                    installation=installation,
                    device=_device(),
                    artifact=artifact,
                    now=NOW,
                )
            with self.assertRaises(IOSPeerLabError):
                bind_packet_lan_process(
                    launch=launch,
                    process_inventory=processes,
                    session_document=session_bytes,
                    ready_receipt=_packet_lan_ready(session, process_id=4331),
                    material=material,
                    installation=installation,
                    device=_device(),
                    artifact=artifact,
                    now=NOW,
                )

            authority = authorize_packet_lan_process_cleanup(
                ownership=ownership,
                fresh_inventory=processes,
                fresh_ready_receipt=ready_bytes,
                session_document=session_bytes,
                material=material,
                observed_at=NOW,
            )
            duplicate_process = ProcessInventory(
                receipt_sha256="8" * 64,
                device_identifier=DEVICE,
                processes=(
                    DeviceProcess(4330, REMOTE_EXECUTABLE),
                    DeviceProcess(4331, REMOTE_EXECUTABLE),
                ),
            )
            with self.assertRaises(IOSPeerLabError):
                authorize_packet_lan_process_cleanup(
                    ownership=ownership,
                    fresh_inventory=duplicate_process,
                    fresh_ready_receipt=ready_bytes,
                    session_document=session_bytes,
                    material=material,
                    observed_at=NOW,
                )

            terminate_spec = plan.terminate(
                authority,
                root / "terminate-packet-lan.json",
            )
            termination = parse_packet_lan_terminate_receipt(
                _envelope(
                    terminate_spec,
                    "devicectl.device.process.terminate",
                    _terminate_result(4330),
                ),
                spec=terminate_spec,
                runtime=RUNTIME,
                device=_device(),
                authority=authority,
            )
            self.assertEqual(termination.process_id, 4330)

    def test_launch_parsers_reject_mode_swaps_and_argument_drift(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            artifact = _artifact(root)
            plan = IOSPeerCommandPlan(root, _device(), artifact)
            installation = IOSPeerInstallationOwnership(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_tree_sha256=artifact.app_tree_sha256,
                install_receipt_sha256="1" * 64,
                app_inventory_receipt_sha256="2" * 64,
                launch_services_identifier=LAUNCH_IDENTIFIER,
                installed_at=_timestamp(NOW),
            )
            primer_spec = plan.launch_primer(installation, root / "primer-launch.json")
            primer_bytes = _envelope(
                primer_spec,
                "devicectl.device.process.launch",
                _launch_result(PRIMER_LAUNCH_ARGUMENT, 4310),
            )
            observation = parse_primer_launch_receipt(
                primer_bytes,
                spec=primer_spec,
                runtime=RUNTIME,
                device=_device(),
                installation=installation,
            )
            self.assertEqual(observation.process_id, 4310)
            with self.assertRaises(IOSPeerLabError):
                parse_transport_launch_receipt(
                    primer_bytes,
                    spec=primer_spec,
                    runtime=RUNTIME,
                    device=_device(),
                    installation=installation,
                )

            drifted_result = _launch_result(PRIMER_LAUNCH_ARGUMENT, 4310)
            drifted_result["launchOptions"]["arguments"] = []  # type: ignore[index]
            with self.assertRaises(IOSPeerLabError):
                parse_primer_launch_receipt(
                    _envelope(
                        primer_spec,
                        "devicectl.device.process.launch",
                        drifted_result,
                    ),
                    spec=primer_spec,
                    runtime=RUNTIME,
                    device=_device(),
                    installation=installation,
                )

    def test_primer_retry_requires_first_generation_full_inventory_absence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            artifact = _artifact(root)
            installation = IOSPeerInstallationOwnership(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_tree_sha256=artifact.app_tree_sha256,
                install_receipt_sha256="1" * 64,
                app_inventory_receipt_sha256="2" * 64,
                launch_services_identifier=LAUNCH_IDENTIFIER,
                installed_at=_timestamp(NOW),
            )
            launch = PrimerLaunchObservation(
                receipt_sha256="3" * 64,
                device_identifier=DEVICE,
                process_id=4310,
                executable_path=REMOTE_EXECUTABLE,
            )
            authority = authorize_single_primer_retry(
                first_launch=launch,
                fresh_inventory=ProcessInventory("4" * 64, DEVICE, ()),
                installation=installation,
                device=_device(),
                artifact=artifact,
                observed_at=NOW,
            )
            self.assertEqual(authority.retry_number, 1)

            still_running = ProcessInventory(
                "5" * 64,
                DEVICE,
                (DeviceProcess(4310, REMOTE_EXECUTABLE),),
            )
            with self.assertRaises(IOSPeerLabError):
                authorize_single_primer_retry(
                    first_launch=launch,
                    fresh_inventory=still_running,
                    installation=installation,
                    device=_device(),
                    artifact=artifact,
                    observed_at=NOW,
                )

    def test_parser_rejects_unknown_fields_filters_and_preexisting_app(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            plan = IOSPeerCommandPlan(root, _device(), _artifact(root))
            app_spec = plan.app_inventory(root / "app-inventory.json")
            result = _app_result([])
            result["fallback"] = True
            with self.assertRaises(IOSPeerLabError):
                parse_app_inventory(
                    _envelope(app_spec, "devicectl.device.info.apps", result),
                    spec=app_spec,
                    runtime=RUNTIME,
                    device=_device(),
                )

            process_spec = plan.process_inventory(root / "process-inventory.json")
            filtered = CommandSpec(
                process_spec.role,
                process_spec.argv + ("--search", BUNDLE_IDENTIFIER),
                process_spec.cwd,
                process_spec.timeout_seconds,
                stdout_limit=process_spec.stdout_limit,
                stderr_limit=process_spec.stderr_limit,
            )
            with self.assertRaises(IOSPeerLabError):
                parse_process_inventory(
                    b"{}", spec=filtered, runtime=RUNTIME, device=_device()
                )

            app = AppInventory(
                "a" * 64,
                DEVICE,
                (
                    AppInventoryEntry(
                        BUNDLE_IDENTIFIER, APP_EXECUTABLE, None, True, True
                    ),
                ),
            )
            processes = ProcessInventory("b" * 64, DEVICE, ())
            with self.assertRaises(IOSPeerContractError):
                build_preflight(
                    app_inventory=app,
                    process_inventory=processes,
                    device=_device(),
                    observed_at=NOW,
                )


class TransportPairVerifierTests(unittest.TestCase):
    @staticmethod
    def _payload_digest(service: str) -> str:
        return transport_payload_receipt_sha256(service, SESSION_ID)

    def _peer_result(self) -> dict[str, object]:
        def secure(service: str, transport: str, alpn: str) -> dict[str, object]:
            return {
                "accepted": 0,
                "alpn": alpn,
                "bytes_received": 32,
                "bytes_sent": 34,
                "cipher_suite": 0x1301,
                "control_bytes_received": 1,
                "control_bytes_submitted": 1,
                "delivery_acknowledgement_final_context_observed": True,
                "delivery_confirmation_completion": "processed",
                "early_data_accepted": False,
                "evidence_disposition": "pair_required",
                "payload_sha256": self._payload_digest(service),
                "peer_terminal_observed": False,
                "tls_version": 0x0304,
                "transport": transport,
            }

        return {
            "bundle_identifier": BUNDLE_IDENTIFIER,
            "certificate_sha256": CERTIFICATE_SHA256,
            "completed_at": _timestamp(NOW),
            "connections": {
                "quic_echo": secure(
                    "quic_echo", "quic-tls13", "cfm-transport-peer-quic/1"
                ),
                "tcp_sink": {
                    "accepted": 1,
                    "alpn": None,
                    "bytes_received": 32,
                    "bytes_sent": 0,
                    "cipher_suite": None,
                    "control_bytes_received": 0,
                    "control_bytes_submitted": 0,
                    "delivery_confirmation_completion": None,
                    "delivery_acknowledgement_final_context_observed": False,
                    "early_data_accepted": None,
                    "evidence_disposition": "accepted",
                    "payload_sha256": self._payload_digest("tcp_sink"),
                    "peer_terminal_observed": True,
                    "tls_version": None,
                    "transport": "tcp4",
                },
                "tls13_echo": secure(
                    "tls13_echo", "tls13-tcp4", "cfm-transport-peer-tls/1"
                ),
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

    def _mac_result(self) -> dict[str, object]:
        def secure(service: str, transport: str, alpn: str) -> dict[str, object]:
            return {
                "alpn": alpn,
                "certificate_sha256": CERTIFICATE_SHA256,
                "cipher_suite": 0x1301,
                "client_bytes_received": 34,
                "client_bytes_sent": 34,
                "client_completed": True,
                "client_control_bytes_received": 1,
                "client_control_bytes_sent": 1,
                "delivery_acknowledgement_hex": "a5",
                "delivery_confirmation_hex": "5a",
                "delivery_confirmation_stream_complete": True,
                "early_data_accepted": False,
                "payload_bytes": 32,
                "payload_sha256": self._payload_digest(service),
                "tls_version": 0x0304,
                "transport": transport,
            }

        return {
            "attempt_count": 7,
            "certificate_sha256": CERTIFICATE_SHA256,
            "claim_eligible": False,
            "completed_at": _timestamp(NOW),
            "document": "cfm-ios-transport-peer-mac-probe-result-v3",
            "mode": "lab_smoke_only",
            "negative_checks": {
                "alpn_mismatch_did_not_reach_ready": {
                    "client_bytes_sent": 0,
                    "did_not_reach_ready": True,
                },
                "tls12_did_not_reach_ready": {
                    "client_bytes_sent": 0,
                    "did_not_reach_ready": True,
                },
                "wrong_leaf_pin_rejected": {
                    "client_bytes_sent": 0,
                    "did_not_reach_ready": True,
                    "leaf_matched_session_certificate": True,
                    "verify_callback_invoked": True,
                    "verify_returned_false": True,
                },
                "zero_length_frame_connection_ended": {
                    "alpn": "cfm-transport-peer-tls/1",
                    "cipher_suite": 0x1301,
                    "client_bytes_sent": 2,
                    "client_completed": True,
                    "connection_ended": True,
                    "early_data_accepted": False,
                    "invalid_zero_length_frame_sent": True,
                    "tls_version": 0x0304,
                },
            },
            "peer_ipv4": "192.168.1.20",
            "positive_checks": {
                "quic_echo": secure(
                    "quic_echo", "quic-tls13", "cfm-transport-peer-quic/1"
                ),
                "tcp_sink": {
                    "client_bytes_received": 0,
                    "client_bytes_sent": 32,
                    "client_completed": True,
                    "payload_bytes": 32,
                    "payload_sha256": self._payload_digest("tcp_sink"),
                    "transport": "tcp4",
                },
                "tls13_echo": secure(
                    "tls13_echo", "tls13-tcp4", "cfm-transport-peer-tls/1"
                ),
            },
            "process_id": 4321,
            "schema_version": 3,
            "session_id": SESSION_ID,
            "started_at": _timestamp(NOW - timedelta(seconds=1)),
        }

    def test_joint_verifier_requires_both_exact_receipts(self) -> None:
        mac = self._mac_result()
        peer = self._peer_result()
        verified = verify_transport_pair(
            mac_result=canonical_json(mac) + b"\n",
            peer_result=canonical_json(peer) + b"\n",
            expected_session_id=SESSION_ID,
            expected_certificate_sha256=CERTIFICATE_SHA256,
            expected_process_id=4321,
            now=NOW + timedelta(seconds=1),
        )
        self.assertEqual(verified.process_id, 4321)

        mac["positive_checks"]["quic_echo"]["client_control_bytes_received"] = 0
        with self.assertRaises(IOSPeerLabError):
            verify_transport_pair(
                mac_result=canonical_json(mac) + b"\n",
                peer_result=canonical_json(peer) + b"\n",
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
                now=NOW + timedelta(seconds=1),
            )

    def test_joint_verifier_rejects_python_boolean_integer_aliases(self) -> None:
        peer_result = canonical_json(self._peer_result()) + b"\n"

        mutations = (
            ("negative_checks", "tls12_did_not_reach_ready", "did_not_reach_ready", 1),
            (
                "negative_checks",
                "tls12_did_not_reach_ready",
                "client_bytes_sent",
                False,
            ),
            ("positive_checks", "tcp_sink", "client_bytes_received", False),
            ("positive_checks", "tls13_echo", "client_control_bytes_sent", True),
            ("positive_checks", "tls13_echo", "client_control_bytes_received", True),
            ("positive_checks", "quic_echo", "client_control_bytes_sent", True),
            ("positive_checks", "quic_echo", "client_control_bytes_received", True),
        )
        for section, check, field, value in mutations:
            mac = self._mac_result()
            mac[section][check][field] = value
            with self.assertRaises(IOSPeerLabError):
                verify_transport_pair(
                    mac_result=canonical_json(mac) + b"\n",
                    peer_result=peer_result,
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    expected_process_id=4321,
                    now=NOW + timedelta(seconds=1),
                )

    def test_joint_verifier_resolves_only_exact_pair_required_evidence(self) -> None:
        mac = self._mac_result()
        peer = self._peer_result()

        verified = verify_transport_pair(
            mac_result=canonical_json(mac) + b"\n",
            peer_result=canonical_json(peer) + b"\n",
            expected_session_id=SESSION_ID,
            expected_certificate_sha256=CERTIFICATE_SHA256,
            expected_process_id=4321,
            now=NOW + timedelta(seconds=1),
        )
        self.assertEqual(verified.process_id, 4321)

        for include_field, value in ((True, False), (False, True)):
            invalid_stream_completion = self._mac_result()
            secure = invalid_stream_completion["positive_checks"]["tls13_echo"]
            if include_field:
                secure["delivery_confirmation_stream_complete"] = value
            else:
                del secure["delivery_confirmation_stream_complete"]
            with self.assertRaises(IOSPeerLabError):
                verify_transport_pair(
                    mac_result=canonical_json(invalid_stream_completion) + b"\n",
                    peer_result=canonical_json(peer) + b"\n",
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    expected_process_id=4321,
                    now=NOW + timedelta(seconds=1),
                )

        closed_peer = self._peer_result()
        closed_peer["status"] = "closed"
        for service in ("tls13_echo", "quic_echo"):
            secure = closed_peer["connections"][service]
            secure["accepted"] = 1
            secure["evidence_disposition"] = "accepted"
            secure["delivery_confirmation_completion"] = "processed"
        with self.assertRaises(IOSPeerLabError):
            verify_transport_pair(
                mac_result=canonical_json(mac) + b"\n",
                peer_result=canonical_json(closed_peer) + b"\n",
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
                now=NOW + timedelta(seconds=1),
            )

        nonfinal_acknowledgement_peer = self._peer_result()
        nonfinal_acknowledgement_peer.update(
            {
                "status": "failed",
                "failure_phase": "delivery_evidence",
                "failed_service": "tls13_echo",
                "failure_reason": "acknowledgement_not_final",
                "phase_reached": "echo_completed",
            }
        )
        validate_result_receipt(
            canonical_json(nonfinal_acknowledgement_peer) + b"\n",
            expected_session_id=SESSION_ID,
            expected_certificate_sha256=CERTIFICATE_SHA256,
            expected_process_id=4321,
        )
        with self.assertRaises(IOSPeerLabError):
            verify_transport_pair(
                mac_result=canonical_json(mac) + b"\n",
                peer_result=canonical_json(nonfinal_acknowledgement_peer) + b"\n",
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
                now=NOW + timedelta(seconds=1),
            )

        failed_confirmation = self._peer_result()
        failed_confirmation["connections"]["quic_echo"][
            "delivery_confirmation_completion"
        ] = "failed"
        with self.assertRaises(IOSPeerLabError):
            verify_transport_pair(
                mac_result=canonical_json(mac) + b"\n",
                peer_result=canonical_json(failed_confirmation) + b"\n",
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
                now=NOW + timedelta(seconds=1),
            )

        unobserved_confirmation = self._peer_result()
        unobserved_confirmation["connections"]["quic_echo"][
            "delivery_confirmation_completion"
        ] = "unobserved"
        with self.assertRaises(IOSPeerLabError):
            verify_transport_pair(
                mac_result=canonical_json(mac) + b"\n",
                peer_result=canonical_json(unobserved_confirmation) + b"\n",
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
                now=NOW + timedelta(seconds=1),
            )

        for field, value in (
            ("delivery_acknowledgement_hex", "00"),
            ("delivery_confirmation_hex", "00"),
        ):
            invalid_mac = self._mac_result()
            invalid_mac["positive_checks"]["quic_echo"][field] = value
            with self.assertRaises(IOSPeerLabError):
                verify_transport_pair(
                    mac_result=canonical_json(invalid_mac) + b"\n",
                    peer_result=canonical_json(peer) + b"\n",
                    expected_session_id=SESSION_ID,
                    expected_certificate_sha256=CERTIFICATE_SHA256,
                    expected_process_id=4321,
                    now=NOW + timedelta(seconds=1),
                )

        failed_peer = self._peer_result()
        failed_peer["status"] = "failed"
        failed_peer["failure_phase"] = "delivery_evidence"
        failed_peer["failed_service"] = "quic_echo"
        failed_peer["failure_reason"] = "connection_deadline_expired"
        failed_peer["phase_reached"] = "delivery_confirmation_submitted"
        with self.assertRaises(IOSPeerLabError):
            verify_transport_pair(
                mac_result=canonical_json(mac) + b"\n",
                peer_result=canonical_json(failed_peer) + b"\n",
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
                now=NOW + timedelta(seconds=1),
            )

        legacy_mac = self._mac_result()
        legacy_mac["schema_version"] = 2
        legacy_mac["document"] = "cfm-ios-transport-peer-mac-probe-result-v2"
        for service in ("tls13_echo", "quic_echo"):
            del legacy_mac["positive_checks"][service][
                "delivery_confirmation_stream_complete"
            ]
        with self.assertRaises(IOSPeerLabError):
            verify_transport_pair(
                mac_result=canonical_json(legacy_mac) + b"\n",
                peer_result=canonical_json(peer) + b"\n",
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
                now=NOW + timedelta(seconds=1),
            )

        legacy_peer = self._peer_result()
        legacy_peer["schema_version"] = 4
        legacy_peer["document"] = "cfm-ios-transport-peer-result-v4"
        with self.assertRaises(IOSPeerLabError):
            verify_transport_pair(
                mac_result=canonical_json(self._mac_result()) + b"\n",
                peer_result=canonical_json(legacy_peer) + b"\n",
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
                now=NOW + timedelta(seconds=1),
            )

        mac = self._mac_result()
        peer["connections"]["tls13_echo"].update(
            {
                "accepted": 0,
                "alpn": None,
                "bytes_received": 0,
                "bytes_sent": 0,
                "cipher_suite": None,
                "control_bytes_received": 0,
                "control_bytes_submitted": 0,
                "delivery_acknowledgement_final_context_observed": False,
                "delivery_confirmation_completion": None,
                "early_data_accepted": None,
                "evidence_disposition": "unobserved",
                "payload_sha256": None,
                "peer_terminal_observed": False,
                "tls_version": None,
                "transport": None,
            }
        )
        with self.assertRaises(IOSPeerLabError):
            verify_transport_pair(
                mac_result=canonical_json(mac) + b"\n",
                peer_result=canonical_json(peer) + b"\n",
                expected_session_id=SESSION_ID,
                expected_certificate_sha256=CERTIFICATE_SHA256,
                expected_process_id=4321,
                now=NOW + timedelta(seconds=1),
            )


class JournalAndGuardTests(unittest.TestCase):
    def _ownership(
        self,
    ) -> tuple[
        IOSPeerInstallationOwnership,
        IOSPeerPrimerProcessOwnership,
        IOSPeerPrimerProcessCleanupAuthority,
        PrimerStoppedOwnership,
        IOSPeerProcessOwnership,
    ]:
        installation = IOSPeerInstallationOwnership(
            device_identifier_sha256=device_identifier_sha256(DEVICE),
            app_tree_sha256=APP_TREE_SHA256,
            install_receipt_sha256="4" * 64,
            app_inventory_receipt_sha256="5" * 64,
            launch_services_identifier=LAUNCH_IDENTIFIER,
            installed_at=_timestamp(NOW),
        )
        primer = IOSPeerPrimerProcessOwnership(
            device_identifier_sha256=device_identifier_sha256(DEVICE),
            app_tree_sha256=APP_TREE_SHA256,
            process_id=4310,
            launch_services_identifier=LAUNCH_IDENTIFIER,
            executable_path=REMOTE_EXECUTABLE,
            launch_receipt_sha256="6" * 64,
            process_inventory_receipt_sha256="7" * 64,
            primer_receipt_sha256="8" * 64,
        )
        primer_cleanup = IOSPeerPrimerProcessCleanupAuthority(
            process=primer,
            revalidated_process_inventory_receipt_sha256="9" * 64,
            revalidated_primer_receipt_sha256="8" * 64,
            observed_at=_timestamp(NOW),
        )
        stopped = PrimerStoppedOwnership(
            process=primer,
            terminate_receipt_sha256="a" * 64,
            post_terminate_process_inventory_receipt_sha256="b" * 64,
            stopped_at=_timestamp(NOW),
            process_absent=True,
        )
        process = IOSPeerProcessOwnership(
            device_identifier_sha256=device_identifier_sha256(DEVICE),
            app_tree_sha256=APP_TREE_SHA256,
            session_id=SESSION_ID,
            process_id=4321,
            launch_services_identifier=LAUNCH_IDENTIFIER,
            executable_path=REMOTE_EXECUTABLE,
            launch_receipt_sha256="c" * 64,
            process_inventory_receipt_sha256="d" * 64,
            ready_receipt_sha256="e" * 64,
        )
        return installation, primer, primer_cleanup, stopped, process

    @staticmethod
    def _primer_termination() -> ProcessTerminationObservation:
        return ProcessTerminationObservation(
            receipt_sha256="a" * 64,
            device_identifier=DEVICE,
            process_id=4310,
            executable_path=REMOTE_EXECUTABLE,
            signal_name="SIGTERM",
            signal_value=15,
            device_timestamp=_device_timestamp(NOW),
        )

    @staticmethod
    def _session_copy_observation() -> SessionCopyObservation:
        return SessionCopyObservation(
            receipt_sha256="f" * 64,
            device_identifier=DEVICE,
            source_directory=Path("/private/tmp/CFMTransportPeer"),
            destination_path=REMOTE_SESSION,
            session_id=SESSION_ID,
            certificate_sha256=CERTIFICATE_SHA256,
            last_modified_at=_device_timestamp(NOW),
        )

    def test_journal_intents_are_durable_and_replay_strictly(self) -> None:
        with tempfile.TemporaryDirectory() as parent_text:
            parent = Path(parent_text).resolve()
            root = parent / "transaction"
            root.mkdir(mode=0o700)
            preflight = IOSPeerPreflight(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_inventory_receipt_sha256="a" * 64,
                process_inventory_receipt_sha256="b" * 64,
                observed_at=_timestamp(NOW),
                app_absent=True,
                process_absent=True,
            )
            inputs = IOSPeerTransactionInputs(
                "11111111-2222-3333-4444-555555555555",
                _device(),
                _device_admission(),
                IOSPeerArtifact(
                    parent / f"{APP_EXECUTABLE}.app", "c" * 64, APP_TREE_SHA256
                ),
                SESSION_ID,
                preflight,
                "d" * 64,
            )
            installation, primer, primer_cleanup, stopped, process = self._ownership()
            with IOSPeerTransactionJournal.create(
                root, inputs, recorded_at=NOW
            ) as journal:
                with self.assertRaises(IOSPeerLabError):
                    journal.record_primer_launch_intent(recorded_at=NOW)
                journal.record_install_intent(recorded_at=NOW)
                journal.record_installed(installation, recorded_at=NOW)
                journal.record_primer_launch_intent(recorded_at=NOW)
                journal.record_primer_launched(primer, recorded_at=NOW)
                journal.record_primer_terminate_intent(primer_cleanup, recorded_at=NOW)
                journal.record_primer_terminated(
                    self._primer_termination(), recorded_at=NOW
                )
                journal.record_primer_stopped(stopped, recorded_at=NOW)
                journal.record_session_copy_intent(stopped, recorded_at=NOW)
                journal.record_session_copied(
                    self._session_copy_observation(), recorded_at=NOW
                )
                journal.record_transport_launch_intent(recorded_at=NOW)
                journal.record_transport_launched(process, recorded_at=NOW)
                journal.record_result_received("9" * 64, recorded_at=NOW)
                journal.record_uninstall_intent(installation, recorded_at=NOW)
                journal.record_uninstalled(
                    UninstallObservation("e" * 64, DEVICE, BUNDLE_IDENTIFIER),
                    recorded_at=NOW,
                )
                journal.record_absence_verified(
                    app_inventory_sha256="f" * 64,
                    process_inventory_sha256="0" * 64,
                    legacy_cfw_after_sha256="d" * 64,
                    recorded_at=NOW,
                )
                journal.complete(recorded_at=NOW)
                self.assertEqual(
                    journal.snapshot.state, IOSPeerTransactionState.COMPLETE
                )
                with self.assertRaises(IOSPeerLabError) as raised:
                    IOSPeerTransactionJournal.open(root)
                self.assertEqual(raised.exception.code, "ios_lab_transaction_locked")
            with IOSPeerTransactionJournal.open(root) as reopened:
                self.assertEqual(
                    reopened.snapshot.state, IOSPeerTransactionState.COMPLETE
                )
                self.assertEqual(reopened.snapshot.sequence, 17)

            (root / "journal" / ".00000018.json.pending").write_bytes(b"partial")
            with self.assertRaises(IOSPeerLabError):
                IOSPeerTransactionJournal.open(root)

    def test_failed_launch_intent_can_enter_owned_uninstall(self) -> None:
        with tempfile.TemporaryDirectory() as parent_text:
            parent = Path(parent_text).resolve()
            root = parent / "failed-launch-transaction"
            root.mkdir(mode=0o700)
            preflight = IOSPeerPreflight(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_inventory_receipt_sha256="a" * 64,
                process_inventory_receipt_sha256="b" * 64,
                observed_at=_timestamp(NOW),
                app_absent=True,
                process_absent=True,
            )
            inputs = IOSPeerTransactionInputs(
                "11111111-2222-3333-4444-555555555555",
                _device(),
                _device_admission(),
                IOSPeerArtifact(
                    parent / f"{APP_EXECUTABLE}.app", "c" * 64, APP_TREE_SHA256
                ),
                SESSION_ID,
                preflight,
                "d" * 64,
            )
            installation, _, _, _, _ = self._ownership()
            with IOSPeerTransactionJournal.create(
                root, inputs, recorded_at=NOW
            ) as journal:
                journal.record_install_intent(recorded_at=NOW)
                journal.record_installed(installation, recorded_at=NOW)
                journal.record_primer_launch_intent(recorded_at=NOW)
                with self.assertRaises(IOSPeerLabError):
                    journal.record_uninstall_intent(
                        replace(
                            installation,
                            device_identifier_sha256="f" * 64,
                        ),
                        recorded_at=NOW,
                    )
                journal.record_uninstall_intent(installation, recorded_at=NOW)
                self.assertEqual(
                    journal.snapshot.state, IOSPeerTransactionState.UNINSTALL_INTENT
                )

    def test_primer_retry_is_typed_and_cannot_be_authorized_twice(self) -> None:
        with tempfile.TemporaryDirectory() as parent_text:
            parent = Path(parent_text).resolve()
            root = parent / "retry-transaction"
            root.mkdir(mode=0o700)
            preflight = IOSPeerPreflight(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_inventory_receipt_sha256="a" * 64,
                process_inventory_receipt_sha256="b" * 64,
                observed_at=_timestamp(NOW),
                app_absent=True,
                process_absent=True,
            )
            inputs = IOSPeerTransactionInputs(
                "22222222-3333-4444-5555-666666666666",
                _device(),
                _device_admission(),
                IOSPeerArtifact(
                    parent / f"{APP_EXECUTABLE}.app", "c" * 64, APP_TREE_SHA256
                ),
                SESSION_ID,
                preflight,
                "d" * 64,
            )
            installation, primer, _, _, _ = self._ownership()
            retry = PrimerRetryAuthorization(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_tree_sha256=APP_TREE_SHA256,
                launch_services_identifier=LAUNCH_IDENTIFIER,
                first_launch_receipt_sha256="0" * 64,
                first_process_inventory_receipt_sha256="7" * 64,
                first_process_id=4310,
                executable_path=REMOTE_EXECUTABLE,
                observed_at=_timestamp(NOW),
            )
            with IOSPeerTransactionJournal.create(
                root, inputs, recorded_at=NOW
            ) as journal:
                journal.record_install_intent(recorded_at=NOW)
                journal.record_installed(installation, recorded_at=NOW)
                journal.record_primer_launch_intent(recorded_at=NOW)
                journal.record_primer_retry_authorized(retry, recorded_at=NOW)
                journal.record_primer_retry_launch_intent(retry, recorded_at=NOW)
                with self.assertRaises(IOSPeerLabError) as raised:
                    journal.record_primer_retry_authorized(retry, recorded_at=NOW)
                self.assertEqual(raised.exception.code, "ios_lab_transition_invalid")
                with self.assertRaises(IOSPeerLabError):
                    journal.record_primer_launched(
                        replace(primer, launch_receipt_sha256="0" * 64),
                        recorded_at=NOW,
                    )
                journal.record_primer_launched(primer, recorded_at=NOW)
                self.assertEqual(
                    journal.snapshot.state, IOSPeerTransactionState.PRIMER_LAUNCHED
                )
                journal.record_uninstall_intent(installation, recorded_at=NOW)

    def test_v2_journal_header_is_rejected_without_migration_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as parent_text:
            parent = Path(parent_text).resolve()
            root = parent / "old-schema-transaction"
            root.mkdir(mode=0o700)
            preflight = IOSPeerPreflight(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_inventory_receipt_sha256="a" * 64,
                process_inventory_receipt_sha256="b" * 64,
                observed_at=_timestamp(NOW),
                app_absent=True,
                process_absent=True,
            )
            inputs = IOSPeerTransactionInputs(
                "33333333-4444-4555-8666-777777777777",
                _device(),
                _device_admission(),
                IOSPeerArtifact(
                    parent / f"{APP_EXECUTABLE}.app", "c" * 64, APP_TREE_SHA256
                ),
                SESSION_ID,
                preflight,
                "d" * 64,
            )
            with IOSPeerTransactionJournal.create(root, inputs, recorded_at=NOW):
                pass
            first_event = root / "journal" / "00000001.json"
            value = json.loads(first_event.read_bytes())
            self.assertEqual(value["schema_version"], 3)
            self.assertEqual(value["document"], "cfm-ios-transport-peer-lab-journal-v3")
            value["schema_version"] = 2
            value["document"] = "cfm-ios-transport-peer-lab-journal-v2"
            first_event.write_bytes(canonical_json(value) + b"\n")
            with self.assertRaises(IOSPeerLabError) as raised:
                IOSPeerTransactionJournal.open(root)
            self.assertEqual(raised.exception.code, "ios_lab_journal_invalid")

    def test_ambiguous_install_has_uninstall_only_authority_and_stays_failed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as parent_text:
            parent = Path(parent_text).resolve()
            app_path = parent / f"{APP_EXECUTABLE}.app"
            app_path.mkdir()
            artifact = IOSPeerArtifact(app_path, "c" * 64, APP_TREE_SHA256)
            root = parent / "cleanup-transaction"
            root.mkdir(mode=0o700)
            preflight = IOSPeerPreflight(
                device_identifier_sha256=device_identifier_sha256(DEVICE),
                app_inventory_receipt_sha256="a" * 64,
                process_inventory_receipt_sha256="b" * 64,
                observed_at=_timestamp(NOW),
                app_absent=True,
                process_absent=True,
            )
            inputs = IOSPeerTransactionInputs(
                "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".lower(),
                _device(),
                _device_admission(),
                artifact,
                SESSION_ID,
                preflight,
                "d" * 64,
            )
            with IOSPeerTransactionJournal.create(
                root, inputs, recorded_at=NOW
            ) as journal:
                journal.record_install_intent(recorded_at=NOW)
                inventory = AppInventory(
                    "e" * 64,
                    DEVICE,
                    (
                        AppInventoryEntry(
                            BUNDLE_IDENTIFIER,
                            APP_EXECUTABLE,
                            REMOTE_APP_URL,
                            True,
                            True,
                        ),
                    ),
                )
                cleanup = authorize_cleanup_only_installation(
                    snapshot=journal.snapshot,
                    post_intent_inventory=inventory,
                    device=_device(),
                    artifact=artifact,
                    observed_at=NOW,
                )
                plan = IOSPeerCommandPlan(parent, _device(), artifact)
                uninstall = plan.uninstall(cleanup, parent / "uninstall-cleanup.json")
                self.assertEqual(uninstall.argv[-1], BUNDLE_IDENTIFIER)
                with self.assertRaises(IOSPeerContractError):
                    plan.launch_primer(
                        cleanup,  # type: ignore[arg-type]
                        parent / "primer-launch-cleanup.json",
                    )
                with self.assertRaises(IOSPeerContractError):
                    plan.launch_transport(
                        cleanup,  # type: ignore[arg-type]
                        parent / "transport-launch-cleanup.json",
                    )
                journal.record_cleanup_only_uninstall_intent(cleanup, recorded_at=NOW)
                journal.record_uninstalled(
                    UninstallObservation("f" * 64, DEVICE, BUNDLE_IDENTIFIER),
                    recorded_at=NOW,
                )
                journal.record_absence_verified(
                    app_inventory_sha256="0" * 64,
                    process_inventory_sha256="1" * 64,
                    legacy_cfw_after_sha256="d" * 64,
                    recorded_at=NOW,
                )
                journal.complete(recorded_at=NOW)
                self.assertIsNone(journal.snapshot.evidence.result_receipt_sha256)
                self.assertEqual(
                    journal.snapshot.evidence.cleanup_only_install_intent_sha256,
                    cleanup.install_intent_event_sha256,
                )

    def test_cfw_guard_is_read_only_and_route_rejects_utun(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            gui = root / "CFW"
            core = root / "cfw-core"
            gui.write_bytes(b"gui")
            core.write_bytes(b"core")
            proxy = LegacyProxyConfiguration(True, "127.0.0.1", 7890, False)
            expected = LegacyCFWExpectedState(
                gui,
                hashlib.sha256(b"gui").hexdigest(),
                core,
                hashlib.sha256(b"core").hexdigest(),
                os.geteuid(),
                0,
                "Wi-Fi",
                proxy,
                proxy,
                proxy,
            )
            plan = LegacyCFWGuardPlan(root, expected)
            commands = [
                plan.process_inventory(),
                plan.tcp_7890_owner(),
                plan.udp_7890_owner(),
                plan.http_proxy(),
                plan.https_proxy(),
                plan.socks_proxy(),
                plan.route_to_peer("192.168.1.20"),
            ]
            flattened = "\n".join(" ".join(command.argv) for command in commands)
            self.assertNotIn("kill", flattened)
            self.assertNotIn("networksetup -set", flattened)

            process_output = (
                f" 101 {os.geteuid()} Thu Aug 20 04:05:06 2026 {gui}\n"
                f" 202 0 Thu Aug 20 04:05:07 2026 {core}\n"
            ).encode()
            tcp = (
                b"tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 131072 131072 "
                b"cfw-core:202 00180 00000006\n"
            )
            udp = (
                b"udp4 0 0 127.0.0.1.7890 *.* 0 0 786896 9216 "
                b"cfw-core:202 00180 00000020\n"
            )
            proxy_output = (
                b"Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"
                b"Authenticated Proxy Enabled: 0\n"
            )
            before = build_legacy_cfw_guard_snapshot(
                process_output=process_output,
                tcp_owner_output=tcp,
                udp_owner_output=udp,
                http_proxy_output=proxy_output,
                https_proxy_output=proxy_output,
                socks_proxy_output=proxy_output,
                expected=expected,
            )
            after = build_legacy_cfw_guard_snapshot(
                process_output=process_output,
                tcp_owner_output=tcp,
                udp_owner_output=udp,
                http_proxy_output=proxy_output,
                https_proxy_output=proxy_output,
                socks_proxy_output=proxy_output,
                expected=expected,
            )
            self.assertEqual(
                verify_legacy_cfw_unchanged(before, after), before.binding_sha256
            )
            route = parse_route_to_peer(
                b"route to: 192.168.1.20\ndestination: 192.168.1.20\ninterface: en0\n",
                expected_ipv4="192.168.1.20",
            )
            self.assertEqual(route.interface, "en0")
            with self.assertRaises(IOSPeerLabError):
                parse_route_to_peer(
                    b"route to: 192.168.1.20\ndestination: 192.168.1.20\ninterface: utun3\n",
                    expected_ipv4="192.168.1.20",
                )

    def test_receipt_copy_requires_private_stable_single_link_file(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text).resolve()
            receipt = root / "ready.json"
            receipt.write_bytes(b"{}\n")
            receipt.chmod(0o600)
            verified = validate_copied_receipt(receipt, expected_name="ready.json")
            self.assertEqual(verified.sha256, hashlib.sha256(b"{}\n").hexdigest())
            primer_receipt = root / PRIMER_RESULT_FILE_NAME
            primer_receipt.write_bytes(_primer())
            primer_receipt.chmod(0o600)
            self.assertEqual(
                validate_copied_receipt(
                    primer_receipt, expected_name=PRIMER_RESULT_FILE_NAME
                ).data,
                _primer(),
            )
            hardlink = root / "second-link"
            os.link(receipt, hardlink)
            with self.assertRaises(IOSPeerLabError):
                validate_copied_receipt(receipt, expected_name="ready.json")


if __name__ == "__main__":
    unittest.main()
