from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from scripts.physical_capture import android_lan_peer
from scripts.physical_capture.android_lan_peer import (
    AndroidLanNetworkExpectation,
    AndroidLanPeerAdmissionError,
    AndroidLanPeerLease,
    admit_android_lan_peer,
    discover_android_lan_peer_identity,
    validate_android_lan_peer_identity,
    validate_android_lan_peer_identity_shape,
)
from scripts.physical_capture.execution import CommandResult, command_sha256


SERIAL = b"R58M1234ABC"
FINGERPRINT = b"google/panther/panther:16/BP2A.260701.001/12345678:user/release-keys"
BOOT_ID = b"12345678-1234-4abc-8def-1234567890ab"
PID = 4312
SOCKET_INODE = 98765


def _stat_line(*, start_time: int = 123456, parent_pid: int = 77) -> bytes:
    fields = ["S", str(parent_pid), *("0" for _ in range(17)), str(start_time)]
    fields.extend("0" for _ in range(12))
    return f"{PID} ({android_lan_peer.PROCESS_NAME}) {' '.join(fields)}\n".encode()


def _status(*, uid: int = 2000, gid: int = 2000) -> bytes:
    return (
        f"Name:\t{android_lan_peer.PROCESS_NAME}\n"
        "State:\tS (sleeping)\n"
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n"
        "Threads:\t6\n"
        "NoNewPrivs:\t0\n"
        "Seccomp:\t2\n"
    ).encode()


def _tcp(*, inode: int = SOCKET_INODE, uid: int = 2000) -> bytes:
    return (
        "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when "
        "retrnsmt   uid  timeout inode\n"
        f"   0: 00000000:{android_lan_peer.LISTENER_PORT_HEX} 00000000:0000 "
        f"0A 00000000:00000000 00:00000000 00000000 {uid} 0 {inode}\n"
    ).encode()


class _FakeStarted:
    def __init__(self, runner: _FakeRunner) -> None:
        self.runner = runner
        self.cancelled = False

    def cancel(self) -> None:
        self.runner.cancel_calls += 1
        if self.runner.cancel_failures > 0:
            self.runner.cancel_failures -= 1
            raise RuntimeError("synthetic cancellation failure")
        self.cancelled = True
        self.runner.running = False


class _FakeRunner:
    def __init__(self, artifact: bytes) -> None:
        self.artifact = artifact
        self.running = False
        self.remote_directory = False
        self.remote_binary = False
        self.remote_directory_symlink = False
        self.remote_binary_symlink = False
        self.calls: list[object] = []
        self.started: _FakeStarted | None = None
        self.outputs: dict[str, bytes] = {}
        self.exit_codes: dict[str, int] = {}
        self.queues: dict[str, list[bytes]] = {}
        self.pulled_bytes = artifact
        self.pulled_bytes_by_role: dict[str, bytes] = {}
        self.cancel_calls = 0
        self.cancel_failures = 0
        self.command_counter = 0
        self.started_at_by_role: dict[str, str] = {}
        self.completed_at_by_role: dict[str, str] = {}
        self.duration_ms_by_role: dict[str, int] = {}
        self.mkdir_race_winner = False
        self.errors: dict[str, BaseException] = {}
        self.start_error: BaseException | None = None
        self.server_sockets: dict[str, socket.socket] = {}

    @staticmethod
    def _base_role(role: str) -> str:
        for suffix in (
            "-post-deploy",
            "-post-start",
            "-before-capture",
            "-after-capture",
            "-cleanup-before-delete",
            "-cleanup-after-delete",
        ):
            if role.endswith(suffix):
                return role[: -len(suffix)]
        return role

    def _output(self, role: str) -> bytes:
        queue = self.queues.get(role)
        if queue:
            return queue.pop(0)
        if role in self.outputs:
            return self.outputs[role]
        base_role = self._base_role(role)
        if base_role in self.outputs:
            return self.outputs[base_role]
        values = {
            "android-adb-version": (
                "Android Debug Bridge version 1.0.41\n"
                f"Version {android_lan_peer.ADB_VERSION}\n"
                f"Installed as {android_lan_peer.ADB}\n"
                "Running on Darwin 27.0.0 (arm64)\n"
            ).encode(),
            "android-device-inventory": (
                b"List of devices attached\n"
                + SERIAL
                + b"\tdevice usb:1-1 product:panther model:Pixel_7 device:panther "
                + b"transport_id:1\n"
            ),
            "android-device-serial": SERIAL + b"\n",
            "android-build-fingerprint": FINGERPRINT + b"\n",
            "android-boot-id": BOOT_ID + b"\n",
            "android-verified-boot": b"green\n",
            "android-vbmeta-state": b"locked\n",
            "android-flash-lock": b"1\n",
            "android-primary-abi": b"arm64-v8a\n",
            "android-network-addresses": (
                b"23: wlan0    inet 192.168.43.1/24 brd 192.168.43.255 "
                b"scope global wlan0\n"
            ),
            "android-peer-directory-stat": b"103:7001:2:41c0:2000:2000:4096\n",
            "android-peer-directory-stat-cleanup": (
                b"103:7001:2:41c0:2000:2000:4096\n"
            ),
            "android-peer-binary-stat": (
                f"103:7002:1:8140:2000:2000:{android_lan_peer.ARTIFACT_SIZE}\n".encode()
            ),
            "android-peer-binary-stat-cleanup": (
                f"103:7002:1:8140:2000:2000:{android_lan_peer.ARTIFACT_SIZE}\n".encode()
            ),
            "android-peer-process-stat-before": _stat_line(),
            "android-peer-process-stat-after": _stat_line(),
            "android-peer-process-exe": android_lan_peer.REMOTE_ARTIFACT.encode() + b"\n",
            "android-peer-process-status": _status(),
            "android-peer-process-cmdline": (
                android_lan_peer.REMOTE_ARTIFACT.encode() + b"\0"
            ),
            "android-peer-process-descriptors": (
                b"total 0\n"
                + f"lrwx------ 1 shell shell 64 2026-08-02 3 -> socket:[{SOCKET_INODE}]\n".encode()
            ),
            "android-peer-process-tcp": _tcp(),
        }
        return values.get(base_role, b"")

    def run_command(self, spec: object) -> CommandResult:
        self.calls.append(spec)
        role = spec.role
        if role in self.errors:
            raise self.errors[role]
        base_role = self._base_role(role)
        socket_argument = next(
            (
                value.removeprefix("localfilesystem:")
                for value in spec.argv
                if value.startswith("localfilesystem:")
            ),
            None,
        )
        if role == "android-adb-server-start":
            if socket_argument is None:
                raise AssertionError("server socket missing from start command")
            server_path = Path(socket_argument)
            server_path.parent.mkdir(parents=True, exist_ok=True)
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(server_path))
            self.server_sockets[socket_argument] = server
            output = b""
            stderr = (
                f"* daemon not running; starting now at localfilesystem:{server_path}\n"
                "* daemon started successfully\n"
            ).encode("ascii")
            exit_code = 0
        elif role == "android-adb-server-status":
            if socket_argument is None:
                raise AssertionError("server socket missing from status command")
            server_root = Path(socket_argument).parent
            output = (
                "usb_backend: LIBUSB\n"
                "mdns_backend: MDNS_DISABLED\n"
                'version: "37.0.0"\n'
                'build: "14910828"\n'
                f'executable_absolute_path: "{spec.argv[0]}"\n'
                f'log_absolute_path: "{server_root / "adb.log"}"\n'
                'os: "Darwin 27.0.0 (arm64)"\n'
                'trace_level: ""\n'
                "burst_mode: false\n"
                "mdns_enabled: false\n"
                f'keystore_path: "{server_root / "home" / ".android" / "adbkey"}"\n'
                f'known_hosts_path: "{server_root / "home" / ".android" / "adb_known_hosts.pb"}"\n'
            ).encode("ascii")
            stderr = b""
            exit_code = 0
        elif role == "android-adb-server-kill":
            if socket_argument is not None:
                server = self.server_sockets.pop(socket_argument, None)
                if server is not None:
                    server.close()
                Path(socket_argument).unlink(missing_ok=True)
            output = b""
            stderr = b""
            exit_code = 0
        elif role == "android-adb-version":
            output = (
                "Android Debug Bridge version 1.0.41\n"
                f"Version {android_lan_peer.ADB_VERSION}\n"
                f"Installed as {spec.argv[0]}\n"
                "Running on Darwin 27.0.0 (arm64)\n"
            ).encode()
            stderr = b""
            exit_code = 0
        elif role in {"android-peer-pid", "android-peer-pid-before-deploy"}:
            if self.running:
                output = f"{PID}\n".encode()
                exit_code = 0
            else:
                output = b""
                exit_code = 1
        elif role == "android-peer-original-pid-absence":
            output = b""
            exit_code = 0 if self.running else 1
        elif role == "android-peer-directory-create" and self.mkdir_race_winner:
            self.remote_directory = True
            output = b""
            exit_code = 1
        elif role.startswith("android-peer-directory-exists-"):
            output = b""
            exit_code = 0 if self.remote_directory else 1
        elif role.startswith("android-peer-directory-symlink-"):
            output = b""
            exit_code = 0 if self.remote_directory_symlink else 1
        elif role.startswith("android-peer-binary-exists-"):
            output = b""
            exit_code = 0 if self.remote_binary else 1
        elif role.startswith("android-peer-binary-symlink-"):
            output = b""
            exit_code = 0 if self.remote_binary_symlink else 1
        elif role == "android-peer-directory-cleanup" and self.remote_binary:
            output = b""
            exit_code = 1
        else:
            output = self._output(role)
            exit_code = self.exit_codes.get(role, 0)
        if role == "android-peer-directory-create" and exit_code == 0:
            self.remote_directory = True
        elif role == "android-peer-push" and exit_code == 0:
            self.remote_binary = True
        elif role == "android-peer-binary-cleanup" and exit_code == 0:
            self.remote_binary = False
            self.remote_binary_symlink = False
        elif role in {
            "android-peer-directory-cleanup",
            "android-peer-directory-cleanup-symlink",
        } and exit_code == 0:
            if not self.remote_binary:
                self.remote_directory = False
                self.remote_directory_symlink = False
        if (
            role == "android-peer-pull-verify"
            or base_role == "android-peer-process-exe-pull"
        ) and exit_code == 0:
            destination = Path(spec.argv[-1])
            destination.write_bytes(
                self.pulled_bytes_by_role.get(role, self.pulled_bytes)
            )
        started = datetime(2026, 8, 2, 5, 0, tzinfo=timezone.utc) + timedelta(
            milliseconds=self.command_counter * 2
        )
        completed = started + timedelta(milliseconds=1)
        self.command_counter += 1
        return CommandResult(
            role=role,
            argv_sha256=command_sha256(spec.argv),
            started_at=self.started_at_by_role.get(
                role,
                started.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            ),
            completed_at=self.completed_at_by_role.get(
                role,
                completed.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            ),
            duration_ms=self.duration_ms_by_role.get(role, 1),
            exit_code=exit_code,
            stdout=output,
            stderr=stderr if "stderr" in locals() else b"",
        )

    def start_command(self, spec: object) -> _FakeStarted:
        self.calls.append(spec)
        if spec.role != "android-peer-process":
            raise AssertionError(f"unexpected started role: {spec.role}")
        if self.start_error is not None:
            raise self.start_error
        self.running = True
        self.started = _FakeStarted(self)
        return self.started


class AndroidLanPeerAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name)
        (self.repository / "target").mkdir()
        adb = self.repository / "sdk/platform-tools/adb"
        adb.parent.mkdir(parents=True)
        self.adb_bytes = b"fixed-adb-test-binary"
        adb.write_bytes(self.adb_bytes)
        adb.chmod(0o755)
        artifact = self.repository / "target/packet-lan-peer-linux-arm64"
        self.artifact_bytes = b"fixed-packet-lan-peer-test-artifact"
        artifact.write_bytes(self.artifact_bytes)
        artifact.chmod(0o555)

        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        for name, value in (
            ("REPOSITORY_ROOT", self.repository),
            ("ADB", adb),
            ("ADB_SHA256", hashlib.sha256(self.adb_bytes).hexdigest()),
            ("LOCAL_ARTIFACT", artifact),
            ("ARTIFACT_SHA256", hashlib.sha256(self.artifact_bytes).hexdigest()),
            ("ARTIFACT_SIZE", len(self.artifact_bytes)),
        ):
            self.patches.enter_context(patch.object(android_lan_peer, name, value))
        self.network = AndroidLanNetworkExpectation("wlan0", "192.168.43.1")

    def _expected_identity(self) -> dict[str, object]:
        return android_lan_peer._identity_document(
            serial=SERIAL,
            fingerprint=FINGERPRINT,
            boot_id=BOOT_ID,
            expectation=self.network,
        )

    def _admit(
        self,
        runner: _FakeRunner,
        *,
        expected_identity: object | None = None,
    ) -> AndroidLanPeerLease:
        return admit_android_lan_peer(
            runner=runner,
            network=self.network,
            expected_identity=(
                self._expected_identity()
                if expected_identity is None
                else expected_identity
            ),
        )

    def _complete_capture(self, lease: AndroidLanPeerLease) -> dict[str, object]:
        lease.revalidate_before_capture()
        lease.revalidate_after_capture()
        return lease.close_with_receipt()

    def test_production_pins_are_exact(self) -> None:
        source = Path(android_lan_peer.__file__).read_text(encoding="utf-8")
        self.assertIn("37.0.0-14910828", source)
        self.assertIn(
            "5759ea07285e5a5b66d84f489c118a3fa3998e69cd37725e5a3dc7cbe0597278",
            source,
        )
        self.assertIn(
            "268699e59caff2ea3ddf73e2a22b556364724a6bae985d012f1df7e2b089085c",
            source,
        )
        self.assertIn("ARTIFACT_SIZE: Final = 2_359_422", source)

    def test_full_admission_returns_redacted_typed_identity_and_process_receipts(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        calls_before_getter = len(runner.calls)
        document = lease.as_document()
        self.assertEqual(len(runner.calls), calls_before_getter)
        before_receipt = lease.revalidate_before_capture()
        after_receipt = lease.revalidate_after_capture()
        document = lease.as_document()
        identity = validate_android_lan_peer_identity(document["identity"])

        self.assertEqual(document["document"], android_lan_peer.ADMISSION_DOCUMENT)
        self.assertEqual(identity["serial_sha256"], hashlib.sha256(
            android_lan_peer.SERIAL_DOMAIN + SERIAL
        ).hexdigest())
        self.assertEqual(identity["build_fingerprint_sha256"], hashlib.sha256(
            android_lan_peer.FINGERPRINT_DOMAIN + FINGERPRINT
        ).hexdigest())
        self.assertEqual(identity["boot_id_sha256"], hashlib.sha256(
            android_lan_peer.BOOT_ID_DOMAIN + BOOT_ID
        ).hexdigest())
        self.assertEqual(document["process_receipt"]["pid"], PID)
        self.assertEqual(document["process_receipt"]["socket_inode"], SOCKET_INODE)
        self.assertEqual(document["process_receipt"]["tcp_state"], "LISTEN")
        self.assertEqual(
            before_receipt["document"],
            "cfw-android-lan-peer-before-capture-revalidation-v1",
        )
        self.assertEqual(after_receipt["stage"], "after-capture")
        self.assertEqual(document["before_capture_receipt"], before_receipt)
        self.assertEqual(document["after_capture_receipt"], after_receipt)
        executable_proof = document["process_receipt"]["observations"][
            "executable_host_byte_verification"
        ]
        self.assertEqual(executable_proof["sha256"], android_lan_peer.ARTIFACT_SHA256)
        self.assertEqual(
            set(executable_proof["command"]),
            {
                "role",
                "argv_sha256",
                "started_at",
                "completed_at",
                "duration_ms",
                "exit_code",
            },
        )
        rendered = json.dumps(document, sort_keys=True)
        for secret in (SERIAL, FINGERPRINT, BOOT_ID):
            self.assertNotIn(secret.decode(), rendered)

        calls = runner.calls
        self.assertGreater(len(calls), 20)
        private_environment = dict(calls[0].environment)
        self.assertTrue(private_environment["HOME"].startswith(str(self.repository / "target")))
        self.assertTrue(
            private_environment["ANDROID_USER_HOME"].startswith(
                private_environment["HOME"]
            )
        )
        self.assertTrue(
            private_environment["ANDROID_ADB_LOG_PATH"].startswith(
                private_environment["HOME"].rsplit("/", 1)[0]
            )
        )
        for spec in calls:
            self.assertEqual(dict(spec.environment), private_environment)
            self.assertTrue(Path(spec.argv[0]).is_file())
            self.assertEqual(Path(spec.argv[0]).read_bytes(), self.adb_bytes)
            self.assertEqual(spec.argv[1], "-L")
            self.assertTrue(spec.argv[2].startswith("localfilesystem:"))
            if spec.role in {
                "android-adb-server-start",
                "android-adb-server-status",
                "android-adb-server-kill",
            }:
                continue
            if spec.role == "android-adb-version":
                self.assertEqual(spec.argv[3:], ("version",))
            elif spec.role == "android-device-inventory":
                self.assertEqual(
                    spec.argv[3:],
                    ("-d", "devices", "-l"),
                )
            else:
                self.assertEqual(spec.argv[3:5], ("-t", "1"))
            self.assertNotIn("shell", spec.argv)
            self.assertNotIn("sh", spec.argv)
            self.assertNotIn("/system/bin/sh", spec.argv)
        push = next(spec for spec in calls if spec.role == "android-peer-push")
        pull = next(spec for spec in calls if spec.role == "android-peer-pull-verify")
        process_pull = next(
            spec for spec in calls if spec.role == "android-peer-process-exe-pull"
        )
        self.assertEqual(push.argv[5:8], ("push", "-q", "-Z"))
        self.assertEqual(pull.argv[5:8], ("pull", "-q", "-Z"))
        self.assertEqual(process_pull.argv[-2], f"/proc/{PID}/exe")
        self.assertFalse((self.repository / "target/physical-capture-private").exists())

        shutdown = lease.close_with_receipt()
        self.assertEqual(shutdown["document"], "cfw-android-lan-peer-cleanup-v1")
        self.assertTrue(shutdown["process_absent"])
        self.assertTrue(shutdown["deployment_absent"])
        self.assertEqual(shutdown["outcome"], "capture-complete")
        self.assertEqual(shutdown["removed_directory_binding"]["inode"], 7001)
        self.assertEqual(shutdown["removed_binary_binding"]["inode"], 7002)
        with self.assertRaises(AndroidLanPeerAdmissionError) as duplicate_close:
            lease.close()
        self.assertEqual(
            duplicate_close.exception.code, "android_peer_lease_state_invalid"
        )
        self.assertIsNotNone(runner.started)
        self.assertTrue(runner.started.cancelled)
        with self.assertRaisesRegex(AndroidLanPeerAdmissionError, "closed"):
            lease.as_document()

    def test_device_inventory_requires_exactly_one_authorized_usb_device(self) -> None:
        cases = (
            b"List of devices attached\n\n\n",
            (
                b"List of devices attached\n"
                + SERIAL
                + b"\tdevice product:p model:m device:d transport_id:1\n"
                + b"SECOND\tdevice product:p model:m device:d transport_id:2\n"
            ),
            (
                b"List of devices attached\n"
                + SERIAL
                + b"\toffline product:p model:m device:d transport_id:1\n"
            ),
            (
                b"List of devices attached\r\n"
                + SERIAL
                + b"\tdevice product:p model:m device:d transport_id:1\r\n"
            ),
        )
        for inventory in cases:
            with self.subTest(inventory=inventory):
                runner = _FakeRunner(self.artifact_bytes)
                runner.outputs["android-device-inventory"] = inventory
                with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                    self._admit(runner)
                self.assertEqual(
                    raised.exception.code, "android_peer_device_inventory_invalid"
                )
                self.assertFalse(
                    any(spec.role == "android-peer-push" for spec in runner.calls)
                )

    def test_real_adb_inventory_spacing_and_trailing_blank_line_are_accepted(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        runner.outputs["android-device-inventory"] = (
            b"List of devices attached\n"
            + SERIAL
            + b"            device usb:0-1 product:m3qsqw model:SM_S948U "
            + b"device:m3q transport_id:1\n\n"
        )
        lease = self._admit(runner)
        lease.abort()

    def test_sensitive_identity_lines_reject_crlf_extra_line_and_serial_drift(self) -> None:
        cases = (
            ("android-build-fingerprint", FINGERPRINT + b"\r\n"),
            ("android-boot-id", BOOT_ID + b"\nextra\n"),
            ("android-device-serial", b"DIFFERENT\n"),
        )
        for role, output in cases:
            with self.subTest(role=role):
                runner = _FakeRunner(self.artifact_bytes)
                runner.outputs[role] = output
                with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                    self._admit(runner)
                self.assertIn(
                    raised.exception.code,
                    {"android_peer_output_invalid", "android_peer_identity_output_invalid"},
                )

    def test_identity_validator_rejects_type_hash_and_field_drift(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        identity = lease.as_document()["identity"]
        lease.abort()
        mutations = []
        wrong_type = dict(identity)
        wrong_type["listener_port"] = str(android_lan_peer.LISTENER_PORT)
        mutations.append(wrong_type)
        wrong_hash = dict(identity)
        wrong_hash["serial_sha256"] = "A" * 64
        mutations.append(wrong_hash)
        extra = dict(identity)
        extra["serial"] = SERIAL.decode()
        mutations.append(extra)
        deployment = dict(identity)
        deployment["deployment"] = dict(identity["deployment"], binary_mode="0755")
        mutations.append(deployment)
        for mutation in mutations:
            with self.subTest(fields=set(mutation)):
                with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                    validate_android_lan_peer_identity(mutation)
                self.assertEqual(raised.exception.code, "android_peer_identity_invalid")

    def test_identity_shape_can_describe_stale_artifact_but_never_admit_it(self) -> None:
        identity = self._expected_identity()
        stale = dict(identity)
        stale["deployment"] = dict(
            identity["deployment"],
            binary_sha256="0" * 64,
            binary_size=identity["deployment"]["binary_size"] + 1,
        )

        parsed = validate_android_lan_peer_identity_shape(stale)
        self.assertEqual(parsed, stale)
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            validate_android_lan_peer_identity(stale)
        self.assertEqual(raised.exception.code, "android_peer_identity_invalid")

        malformed = dict(stale)
        malformed["deployment"] = dict(stale["deployment"], binary_sha256="not-a-hash")
        with self.assertRaises(AndroidLanPeerAdmissionError):
            validate_android_lan_peer_identity_shape(malformed)

    def test_pull_verification_rejects_changed_bytes_and_removes_private_copy(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        runner.pulled_bytes = b"x" * len(self.artifact_bytes)
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            self._admit(runner)
        self.assertEqual(raised.exception.code, "android_peer_pulled_artifact_invalid")
        self.assertFalse((self.repository / "target/physical-capture-private").exists())

    def test_local_artifact_hash_drift_blocks_before_adb(self) -> None:
        android_lan_peer.LOCAL_ARTIFACT.chmod(0o755)
        android_lan_peer.LOCAL_ARTIFACT.write_bytes(b"changed-artifact")
        android_lan_peer.LOCAL_ARTIFACT.chmod(0o555)
        runner = _FakeRunner(self.artifact_bytes)
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            self._admit(runner)
        self.assertIn(
            raised.exception.code,
            {"android_peer_host_file_unsafe", "android_peer_host_file_drift"},
        )
        self.assertEqual(runner.calls, [])

    def test_pid_parser_rejects_ambiguous_or_noncanonical_values(self) -> None:
        for value in (b"1 2\n", b"4312\r\n", b"04312\n", b"4312\nextra\n"):
            with self.subTest(value=value):
                with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                    android_lan_peer._parse_pid(value)
                self.assertIn(
                    raised.exception.code,
                    {"android_peer_output_invalid", "android_peer_pid_invalid"},
                )

    def test_process_exe_status_stat_cmdline_and_socket_drift_fail_closed(self) -> None:
        cases: tuple[tuple[str, bytes], ...] = (
            (
                "android-peer-process-exe",
                b"/data/local/tmp/unreviewed-peer\n",
            ),
            ("android-peer-process-status", _status(uid=0)),
            (
                "android-peer-process-cmdline",
                android_lan_peer.REMOTE_ARTIFACT.encode() + b"\0--flag\0",
            ),
            ("android-peer-process-tcp", _tcp(inode=SOCKET_INODE + 1)),
        )
        for role, output in cases:
            with self.subTest(role=role):
                runner = _FakeRunner(self.artifact_bytes)
                runner.outputs[role] = output
                with self.assertRaises(AndroidLanPeerAdmissionError):
                    self._admit(runner)
                self.assertFalse(runner.running)

        runner = _FakeRunner(self.artifact_bytes)
        runner.outputs["android-peer-process-stat-after"] = _stat_line(
            start_time=123457
        )
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            self._admit(runner)
        self.assertEqual(raised.exception.code, "android_peer_process_drift")
        self.assertFalse(runner.running)

    def test_network_expectation_is_typed_canonical_and_must_be_observed_once(self) -> None:
        for interface, address in (
            ("wlan0;id", "192.168.43.1"),
            ("wlan0", "8.8.8.8"),
            ("wlan0", "192.168.043.001"),
        ):
            with self.subTest(interface=interface, address=address):
                with self.assertRaises(AndroidLanPeerAdmissionError):
                    AndroidLanNetworkExpectation(interface, address)
        runner = _FakeRunner(self.artifact_bytes)
        runner.outputs["android-network-addresses"] = (
            b"23: wlan1    inet 192.168.43.1/24 scope global wlan1\n"
        )
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            self._admit(runner)
        self.assertEqual(
            raised.exception.code, "android_peer_network_observation_invalid"
        )

    def test_transport_selector_is_positive_canonical_and_all_later_commands_use_it(self) -> None:
        for transport in ("0", "01", "2147483648"):
            with self.subTest(transport=transport):
                runner = _FakeRunner(self.artifact_bytes)
                runner.outputs["android-device-inventory"] = (
                    b"List of devices attached\n"
                    + SERIAL
                    + b"\tdevice usb:1-1 product:p model:m device:d transport_id:"
                    + transport.encode()
                    + b"\n"
                )
                with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                    self._admit(runner)
                self.assertEqual(
                    raised.exception.code, "android_peer_device_inventory_invalid"
                )

        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        try:
            lease.as_document()
            selected = [
                spec
                for spec in runner.calls
                if spec.role
                not in {
                    "android-adb-server-start",
                    "android-adb-server-status",
                    "android-adb-server-kill",
                    "android-adb-version",
                    "android-device-inventory",
                }
            ]
            self.assertTrue(selected)
            self.assertTrue(all(spec.argv[3:5] == ("-t", "1") for spec in selected))
            self.assertEqual(
                sum("-d" in spec.argv for spec in runner.calls),
                1,
            )
        finally:
            self._complete_capture(lease)

    def test_transaction_identity_drift_cleans_owned_paths_and_releases_lock(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        runner.outputs["android-build-fingerprint-post-deploy"] = (
            b"google/panther/panther:16/DIFFERENT:user/release-keys\n"
        )
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            self._admit(runner)
        self.assertEqual(raised.exception.code, "android_peer_identity_drift")
        self.assertFalse(runner.running)
        self.assertFalse(runner.remote_binary)
        self.assertFalse(runner.remote_directory)

        retry = _FakeRunner(self.artifact_bytes)
        lease = self._admit(retry)
        lease.abort()

    def test_process_executable_host_bytes_are_bound_for_admission_and_capture(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        runner.pulled_bytes_by_role["android-peer-process-exe-pull"] = (
            b"x" * len(self.artifact_bytes)
        )
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            self._admit(runner)
        self.assertEqual(raised.exception.code, "android_peer_pulled_artifact_invalid")
        self.assertFalse(runner.remote_binary)
        self.assertFalse(runner.remote_directory)

        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        runner.pulled_bytes_by_role[
            "android-peer-process-exe-pull-before-capture"
        ] = (
            b"x" * len(self.artifact_bytes)
        )
        try:
            with self.assertRaises(AndroidLanPeerAdmissionError) as capture:
                lease.revalidate_before_capture()
            self.assertEqual(
                capture.exception.code, "android_peer_pulled_artifact_invalid"
            )
        finally:
            lease.abort()

    def test_explicit_capture_transition_revalidates_live_process_and_listener(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        runner.outputs[
            "android-peer-process-stat-before-before-capture"
        ] = _stat_line(
            start_time=123457
        )
        runner.outputs[
            "android-peer-process-stat-after-before-capture"
        ] = _stat_line(
            start_time=123457
        )
        try:
            with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                lease.revalidate_before_capture()
            self.assertEqual(raised.exception.code, "android_peer_process_drift")
        finally:
            lease.abort()

    def test_preexisting_deployment_is_rejected_without_removal(self) -> None:
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                runner = _FakeRunner(self.artifact_bytes)
                runner.remote_directory = not symlink
                runner.remote_directory_symlink = symlink
                with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                    self._admit(runner)
                self.assertEqual(
                    raised.exception.code, "android_peer_preexisting_deployment"
                )
                self.assertEqual(runner.remote_directory, not symlink)
                self.assertEqual(runner.remote_directory_symlink, symlink)
                self.assertFalse(
                    any(
                        spec.role
                        in {
                            "android-peer-binary-cleanup",
                            "android-peer-directory-cleanup",
                        }
                        for spec in runner.calls
                    )
                )

    def test_close_is_retryable_and_never_closes_before_exact_absence(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        lease.revalidate_before_capture()
        lease.revalidate_after_capture()
        runner.cancel_failures = 1
        with patch.object(android_lan_peer, "PROCESS_STOP_SECONDS", 0.0):
            with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                lease.close()
        self.assertEqual(raised.exception.code, "android_peer_cleanup_unproven")
        self.assertTrue(runner.running)
        self.assertTrue(runner.remote_binary)
        self.assertTrue(runner.remote_directory)
        self.assertGreaterEqual(
            sum(spec.role == "android-peer-pid" for spec in runner.calls), 1
        )

        shutdown = lease.close()
        self.assertFalse(runner.running)
        self.assertEqual(runner.cancel_calls, 2)
        self.assertEqual(shutdown["capture_state"], "capture-validated")
        with self.assertRaises(AndroidLanPeerAdmissionError):
            lease.as_document()

    def test_process_lock_rejects_concurrent_admission_until_close(self) -> None:
        first_runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(first_runner)
        second_runner = _FakeRunner(self.artifact_bytes)
        try:
            with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                self._admit(second_runner)
            self.assertEqual(raised.exception.code, "android_peer_admission_busy")
            self.assertEqual(second_runner.calls, [])
        finally:
            lease.abort()

        retry = self._admit(second_runner)
        retry.abort()

    def test_discovery_is_read_only_and_expected_identity_blocks_before_deploy(self) -> None:
        discovery_runner = _FakeRunner(self.artifact_bytes)
        discovery = discover_android_lan_peer_identity(
            runner=discovery_runner,
            network=self.network,
        )
        self.assertEqual(discovery["document"], android_lan_peer.DISCOVERY_DOCUMENT)
        self.assertEqual(discovery["identity"], self._expected_identity())
        self.assertFalse(
            any(
                spec.role
                in {
                    "android-peer-directory-create",
                    "android-peer-push",
                    "android-peer-process",
                }
                for spec in discovery_runner.calls
            )
        )

        wrong = self._expected_identity()
        wrong["serial_sha256"] = "0" * 64
        runner = _FakeRunner(self.artifact_bytes)
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            self._admit(runner, expected_identity=wrong)
        self.assertEqual(
            raised.exception.code, "android_peer_expected_identity_mismatch"
        )
        self.assertFalse(
            any(
                spec.role in {"android-peer-directory-create", "android-peer-push"}
                for spec in runner.calls
            )
        )

        malformed = self._expected_identity()
        malformed["serial"] = SERIAL.decode()
        untouched = _FakeRunner(self.artifact_bytes)
        with self.assertRaises(AndroidLanPeerAdmissionError) as invalid:
            self._admit(untouched, expected_identity=malformed)
        self.assertEqual(invalid.exception.code, "android_peer_identity_invalid")
        self.assertEqual(untouched.calls, [])

    def test_capture_state_machine_is_one_shot_and_ordered(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        getter_calls = len(runner.calls)
        lease.as_document()
        lease.as_document()
        self.assertEqual(len(runner.calls), getter_calls)

        with self.assertRaises(AndroidLanPeerAdmissionError) as early_after:
            lease.revalidate_after_capture()
        self.assertEqual(
            early_after.exception.code, "android_peer_lease_state_invalid"
        )
        with self.assertRaises(AndroidLanPeerAdmissionError) as early_close:
            lease.close()
        self.assertEqual(
            early_close.exception.code, "android_peer_lease_state_invalid"
        )

        lease.revalidate_before_capture()
        with self.assertRaises(AndroidLanPeerAdmissionError) as repeated_before:
            lease.revalidate_before_capture()
        self.assertEqual(
            repeated_before.exception.code, "android_peer_lease_state_invalid"
        )
        lease.revalidate_after_capture()
        with self.assertRaises(AndroidLanPeerAdmissionError) as repeated_after:
            lease.revalidate_after_capture()
        self.assertEqual(
            repeated_after.exception.code, "android_peer_lease_state_invalid"
        )
        receipt = lease.close()
        self.assertEqual(receipt["capture_state"], "capture-validated")
        self.assertIn("process_absence_window", receipt)
        self.assertIn("deployment_absence_window", receipt)
        self.assertEqual(
            receipt["pre_delete_identity_revalidation"]["stage"],
            "cleanup-before-delete",
        )
        self.assertEqual(
            receipt["post_delete_identity_revalidation"]["stage"],
            "cleanup-after-delete",
        )

    def test_failed_capture_revalidation_permanently_poisons_the_lease(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        runner.outputs[
            "android-peer-process-stat-before-before-capture"
        ] = _stat_line(start_time=123457)
        runner.outputs[
            "android-peer-process-stat-after-before-capture"
        ] = _stat_line(start_time=123457)
        with self.assertRaises(AndroidLanPeerAdmissionError) as failed_before:
            lease.revalidate_before_capture()
        self.assertEqual(failed_before.exception.code, "android_peer_process_drift")
        runner.outputs.pop("android-peer-process-stat-before-before-capture")
        runner.outputs.pop("android-peer-process-stat-after-before-capture")
        for operation in (
            lease.as_document,
            lease.revalidate_before_capture,
            lease.revalidate_after_capture,
            lease.close,
        ):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(AndroidLanPeerAdmissionError) as poisoned:
                    operation()
                self.assertEqual(
                    poisoned.exception.code, "android_peer_lease_state_invalid"
                )
        aborted = lease.abort()
        self.assertEqual(aborted["capture_state"], "poisoned")
        self.assertEqual(aborted["lease_failure"]["phase"], "before-capture")
        self.assertEqual(
            aborted["lease_failure"]["code"], "android_peer_process_drift"
        )
        self.assertNotIn(SERIAL.decode(), json.dumps(aborted, sort_keys=True))

        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        lease.revalidate_before_capture()
        runner.outputs[
            "android-peer-process-stat-before-after-capture"
        ] = _stat_line(start_time=123457)
        runner.outputs[
            "android-peer-process-stat-after-after-capture"
        ] = _stat_line(start_time=123457)
        with self.assertRaises(AndroidLanPeerAdmissionError):
            lease.revalidate_after_capture()
        runner.outputs.pop("android-peer-process-stat-before-after-capture")
        runner.outputs.pop("android-peer-process-stat-after-after-capture")
        with self.assertRaises(AndroidLanPeerAdmissionError) as retry:
            lease.revalidate_after_capture()
        self.assertEqual(retry.exception.code, "android_peer_lease_state_invalid")
        self.assertEqual(lease.abort()["lease_failure"]["phase"], "after-capture")

    def test_capture_control_flow_exceptions_are_rethrown_after_poisoning(self) -> None:
        for control in (KeyboardInterrupt(), SystemExit(9)):
            with self.subTest(control=type(control).__name__):
                runner = _FakeRunner(self.artifact_bytes)
                lease = self._admit(runner)
                role = "android-device-serial-before-capture"
                runner.errors[role] = control
                with self.assertRaises(type(control)) as raised:
                    lease.revalidate_before_capture()
                self.assertIs(raised.exception, control)
                runner.errors.pop(role)
                with self.assertRaises(AndroidLanPeerAdmissionError) as getter:
                    lease.as_document()
                self.assertEqual(
                    getter.exception.code, "android_peer_lease_state_invalid"
                )
                receipt = lease.abort()
                self.assertEqual(receipt["capture_state"], "poisoned")
                self.assertEqual(
                    receipt["lease_failure"]["error_type"], type(control).__name__
                )

    def test_admission_and_cleanup_control_flow_always_run_transaction_cleanup(self) -> None:
        admission_cases = (
            ("android-peer-directory-mode", KeyboardInterrupt()),
            ("android-peer-binary-mode", SystemExit(7)),
            ("android-peer-process", KeyboardInterrupt()),
        )
        for role, control in admission_cases:
            with self.subTest(admission=role, control=type(control).__name__):
                runner = _FakeRunner(self.artifact_bytes)
                if role == "android-peer-process":
                    runner.start_error = control
                else:
                    runner.errors[role] = control
                with self.assertRaises(type(control)) as raised:
                    self._admit(runner)
                self.assertIs(raised.exception, control)
                self.assertFalse(runner.remote_binary)
                self.assertFalse(runner.remote_directory)
                retry = _FakeRunner(self.artifact_bytes)
                self._admit(retry).abort()

        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        control = KeyboardInterrupt()
        runner.errors["android-peer-binary-stat-cleanup"] = control
        with self.assertRaises(KeyboardInterrupt) as cleanup_control:
            lease.abort()
        self.assertIs(cleanup_control.exception, control)
        self.assertTrue(
            any(
                spec.role == "android-device-serial-cleanup-after-delete"
                for spec in runner.calls
            )
        )
        runner.errors.pop("android-peer-binary-stat-cleanup")
        receipt = lease.abort()
        self.assertEqual(
            [attempt["status"] for attempt in receipt["attempts"]],
            ["failed", "complete"],
        )
        self.assertEqual(
            receipt["attempts"][0]["errors"][0]["error_type"],
            "KeyboardInterrupt",
        )

        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        control = SystemExit(11)
        role = "android-device-serial-cleanup-before-delete"
        runner.errors[role] = control
        with self.assertRaises(SystemExit) as cleanup_exit:
            lease.abort()
        self.assertIs(cleanup_exit.exception, control)
        self.assertTrue(runner.remote_binary)
        self.assertTrue(runner.remote_directory)
        self.assertTrue(
            any(spec.role == "android-peer-pid" for spec in runner.calls)
        )
        self.assertTrue(
            any(
                spec.role == "android-device-serial-cleanup-after-delete"
                for spec in runner.calls
            )
        )
        runner.errors.pop(role)
        receipt = lease.abort()
        self.assertEqual(len(receipt["attempts"]), 2)
        self.assertEqual(
            receipt["attempts"][0]["errors"][0]["error_type"], "SystemExit"
        )

    def test_context_exit_preserves_primary_when_abort_cleanup_fails(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        primary = AndroidLanPeerAdmissionError("business_failure", "synthetic")
        runner.cancel_failures = 1
        with patch.object(android_lan_peer, "PROCESS_STOP_SECONDS", 0.0):
            with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                with lease:
                    raise primary
        self.assertIs(raised.exception, primary)
        self.assertEqual(primary.code, "business_failure")
        self.assertEqual(primary.cleanup_code, "android_peer_cleanup_unproven")
        lease.abort()

        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        value_error = ValueError("business bytes must survive")
        runner.cancel_failures = 1
        with patch.object(android_lan_peer, "PROCESS_STOP_SECONDS", 0.0):
            with self.assertRaises(ValueError) as non_domain:
                with lease:
                    raise value_error
        self.assertIs(non_domain.exception, value_error)
        self.assertTrue(
            any(
                "android_peer_cleanup_unproven" in note
                for note in getattr(value_error, "__notes__", ())
            )
        )
        lease.abort()

        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        runner.cancel_failures = 1
        with patch.object(android_lan_peer, "PROCESS_STOP_SECONDS", 0.0):
            with self.assertRaises(AndroidLanPeerAdmissionError) as cleanup_only:
                with lease:
                    pass
        self.assertEqual(
            cleanup_only.exception.code, "android_peer_cleanup_unproven"
        )
        lease.abort()

    def test_cleanup_refuses_inode_drift_then_succeeds_after_exact_restore(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        runner.outputs["android-peer-binary-stat-cleanup"] = (
            f"103:7999:1:8140:2000:2000:{android_lan_peer.ARTIFACT_SIZE}\n".encode()
        )
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            lease.abort()
        self.assertEqual(raised.exception.code, "android_peer_cleanup_unproven")
        self.assertTrue(runner.remote_binary)
        self.assertTrue(runner.remote_directory)

        runner.outputs["android-peer-binary-stat-cleanup"] = (
            f"103:7002:1:8140:2000:2000:{android_lan_peer.ARTIFACT_SIZE}\n".encode()
        )
        receipt = lease.abort()
        self.assertEqual(receipt["outcome"], "aborted")
        self.assertEqual(
            [attempt["status"] for attempt in receipt["attempts"]],
            ["failed", "complete"],
        )
        self.assertEqual(receipt["removed_binary_binding"]["inode"], 7002)
        self.assertEqual(receipt["removed_directory_binding"]["inode"], 7001)
        self.assertTrue(receipt["attempts"][0]["errors"])
        self.assertTrue(
            any(
                command["role"] == "android-peer-binary-stat-cleanup"
                for command in receipt["attempts"][0]["commands"]
            )
        )
        self.assertFalse(runner.remote_binary)
        self.assertFalse(runner.remote_directory)

    def test_cleanup_revalidates_device_before_any_remote_deletion(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        runner.outputs["android-boot-id-cleanup-before-delete"] = (
            b"87654321-4321-4abc-8def-1234567890ab\n"
        )
        with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
            lease.abort()
        self.assertEqual(raised.exception.code, "android_peer_cleanup_unproven")
        self.assertTrue(runner.remote_binary)
        self.assertTrue(runner.remote_directory)
        self.assertFalse(
            any(
                spec.role in {"android-peer-binary-cleanup", "android-peer-directory-cleanup"}
                for spec in runner.calls
            )
        )

        runner.outputs.pop("android-boot-id-cleanup-before-delete")
        receipt = lease.abort()
        self.assertEqual(len(receipt["attempts"]), 2)
        self.assertEqual(receipt["attempts"][0]["status"], "failed")
        self.assertEqual(receipt["attempts"][1]["status"], "complete")
        self.assertEqual(receipt["removed_binary_binding"]["inode"], 7002)
        self.assertEqual(receipt["removed_directory_binding"]["inode"], 7001)
        aggregate_roles = [
            command["role"] for command in receipt["window"]["commands"]
        ]
        for role in (
            "android-device-serial-cleanup-before-delete",
            "android-peer-pid",
            "android-peer-binary-cleanup",
            "android-device-serial-cleanup-after-delete",
        ):
            self.assertIn(role, aggregate_roles)
        attempt_commands = [
            command
            for attempt in receipt["attempts"]
            for command in attempt["commands"]
        ]
        self.assertEqual(receipt["window"]["commands"], attempt_commands)
        self.assertNotIn(None, receipt.values())

        runner = _FakeRunner(self.artifact_bytes)
        lease = self._admit(runner)
        runner.outputs["android-boot-id-cleanup-after-delete"] = (
            b"87654321-4321-4abc-8def-1234567890ab\n"
        )
        with self.assertRaises(AndroidLanPeerAdmissionError) as post_delete:
            lease.abort()
        self.assertEqual(
            post_delete.exception.code, "android_peer_cleanup_unproven"
        )
        self.assertFalse(runner.remote_binary)
        self.assertFalse(runner.remote_directory)
        runner.outputs.pop("android-boot-id-cleanup-after-delete")
        post_receipt = lease.abort()
        self.assertEqual(
            [attempt["status"] for attempt in post_receipt["attempts"]],
            ["failed", "complete"],
        )
        self.assertEqual(post_receipt["removed_binary_binding"]["inode"], 7002)
        self.assertTrue(post_receipt["deployment_absence_window"]["commands"])

    def test_atomic_mkdir_loser_never_claims_or_deletes_winner_directory(self) -> None:
        runner = _FakeRunner(self.artifact_bytes)
        runner.mkdir_race_winner = True
        selector = android_lan_peer._DeviceSelector(
            serial=SERIAL,
            transport_id=1,
            server_socket=str(self.repository / "adb.sock"),
        )
        ownership = android_lan_peer._DeploymentOwnership()
        with self.assertRaises(AndroidLanPeerAdmissionError):
            android_lan_peer._deploy(
                runner,
                selector,
                self.artifact_bytes,
                ownership,
            )
        self.assertTrue(ownership.directory_create_attempted)
        self.assertFalse(ownership.directory_created)
        self.assertTrue(runner.remote_directory)
        with self.assertRaises(AndroidLanPeerAdmissionError):
            android_lan_peer._cleanup_deployment(runner, selector, ownership)
        self.assertTrue(runner.remote_directory)
        self.assertFalse(
            any(spec.role == "android-peer-directory-cleanup" for spec in runner.calls)
        )

    def test_command_results_require_canonical_ordered_bounded_time(self) -> None:
        mutations = (
            ("started_at_by_role", "2026-08-02T05:00:00Z"),
            ("completed_at_by_role", "2026-08-02T04:59:59.000000Z"),
            ("duration_ms_by_role", 15_001),
        )
        for attribute, value in mutations:
            with self.subTest(attribute=attribute):
                runner = _FakeRunner(self.artifact_bytes)
                getattr(runner, attribute)["android-adb-version"] = value
                with self.assertRaises(AndroidLanPeerAdmissionError) as raised:
                    self._admit(runner)
                self.assertEqual(
                    raised.exception.code, "android_peer_command_result_drift"
                )

        runner = _FakeRunner(self.artifact_bytes)
        runner.started_at_by_role["android-device-inventory"] = (
            "2026-08-02T05:00:00.000500Z"
        )
        runner.completed_at_by_role["android-device-inventory"] = (
            "2026-08-02T05:00:00.001500Z"
        )
        with self.assertRaises(AndroidLanPeerAdmissionError) as overlap:
            self._admit(runner)
        self.assertEqual(overlap.exception.code, "android_peer_command_result_drift")


if __name__ == "__main__":
    unittest.main()
