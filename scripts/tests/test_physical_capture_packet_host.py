from __future__ import annotations

import array
import os
from pathlib import Path
import signal
import socket
import stat
import tempfile
import threading
import unittest
from unittest.mock import call, patch

from scripts.physical_capture import packet_host
from scripts.physical_capture.packet_host import (
    PacketCaptureDisposition,
    PacketHostError,
    _child_cloexec_boundary,
    _receive_frame,
    _send_frame,
    run_fixed_host_transaction,
)


class PacketHostTransportTests(unittest.TestCase):
    def test_frames_are_canonical_bounded_and_reject_ancillary_fds(self) -> None:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        value = {
            "schema_version": 5,
            "document": "test-frame",
            "sequence": 1,
        }
        sender = threading.Thread(target=_send_frame, args=(left, value))
        sender.start()
        self.assertEqual(_receive_frame(right), value)
        sender.join()

        with tempfile.TemporaryFile() as handle:
            descriptors = array.array("i", [handle.fileno()])
            left.sendmsg(
                [b"\x00\x00\x00\x02{}"],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)],
            )
            with self.assertRaises(PacketHostError) as raised:
                _receive_frame(right)
            self.assertEqual(raised.exception.code, "ancillary_descriptor_rejected")

    def test_cloexec_boundary_restores_but_never_leaves_sentinel_inheritable(self) -> None:
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        os.set_inheritable(write_fd, True)
        with _child_cloexec_boundary():
            self.assertFalse(os.get_inheritable(write_fd))
        self.assertTrue(os.get_inheritable(write_fd))

    def test_noncanonical_and_oversized_frames_fail_closed(self) -> None:
        for body, code in (
            (b'{ "document":"x"}', "frame_invalid"),
            (b"x" * (16 * 1024 + 1), "frame_bound_exceeded"),
        ):
            with self.subTest(code=code):
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    left.sendall(len(body).to_bytes(4, "big"))
                    if len(body) <= 16 * 1024:
                        left.sendall(body)
                    with self.assertRaises(PacketHostError) as raised:
                        _receive_frame(right)
                    self.assertEqual(raised.exception.code, code)
                finally:
                    left.close()
                    right.close()

    def test_spawned_host_runs_closed_transaction_without_inheriting_unrelated_fd(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / "host_helper.py"
            marker = root / "sentinel-leaked"
            read_fd, write_fd = os.pipe()
            try:
                os.set_inheritable(write_fd, True)
                identity = os.fstat(write_fd)
                helper.write_text(
                    """
import json, os, socket, struct, sys

def send(sock, value):
    body = json.dumps(value, sort_keys=True, separators=(\",\", \":\")).encode()
    sock.sendall(struct.pack(\"!I\", len(body)) + body)

def receive(sock):
    length = struct.unpack(\"!I\", sock.recv(4))[0]
    body = b\"\"
    while len(body) < length:
        body += sock.recv(length - len(body))
    return json.loads(body)

fd, device, inode, marker = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
try:
    observed = os.fstat(fd)
    if observed.st_dev == device and observed.st_ino == inode:
        open(marker, \"xb\").close()
except OSError:
    pass
channel = socket.socket(fileno=3)
send(channel, {
    \"collector_pid\": os.getppid(),
    \"collector_uid\": os.geteuid(),
    \"document\": \"cfw-packet-host-hello-v5\",
    \"host_pid\": os.getpid(),
    \"host_uid\": os.geteuid(),
    \"schema_version\": 5,
})
hello = receive(channel)
request = receive(channel)
baseline = {
    \"config_digest\": \"a\" * 64,
    \"desired_mode\": \"tunnel\",
    \"generation\": 7,
    \"ipv6_enabled\": True,
    \"owner\": \"packet_tunnel_system_extension\",
    \"phase\": \"tunnel_active\",
    \"ready\": True,
}
test = dict(baseline, config_digest=\"b\" * 64, generation=8)
restore = dict(baseline, generation=9)
send(channel, {
    \"baseline\": baseline,
    \"baseline_observation_sequence\": 10,
    \"case_id\": request[\"case_id\"],
    \"document\": \"cfw-packet-host-baseline-observed-v5\",
    \"schema_version\": 5,
    \"sequence\": 2,
    \"session_id\": hello[\"session_id\"],
})
capture_started = receive(channel)
test_submitted = {}
capture_completed = {}
if capture_started[\"document\"] == \"cfw-packet-collector-capture-started-v5\":
    send(channel, {
        \"case_id\": request[\"case_id\"],
        \"document\": \"cfw-packet-host-test-observed-v5\",
        \"schema_version\": 5,
        \"sequence\": 4,
        \"session_id\": hello[\"session_id\"],
        \"test\": test,
        \"test_observation_sequence\": 11,
    })
    test_submitted = receive(channel)
    send(channel, {
        \"baseline\": baseline,
        \"baseline_observation_sequence\": 10,
        \"case_id\": request[\"case_id\"],
        \"document\": \"cfw-packet-host-baseline-restored-v5\",
        \"restore\": restore,
        \"restore_observation_sequence\": 12,
        \"schema_version\": 5,
        \"sequence\": 6,
        \"session_id\": hello[\"session_id\"],
        \"test\": test,
        \"test_observation_sequence\": 11,
    })
    capture_completed = receive(channel)
if (
    capture_started[\"document\"] == \"cfw-packet-collector-capture-started-v5\"
    and test_submitted[\"document\"] == \"cfw-packet-collector-test-submitted-v5\"
    and capture_completed[\"document\"] == \"cfw-packet-collector-capture-completed-v5\"
):
    send(channel, {
        \"baseline\": baseline,
        \"baseline_observation_sequence\": 10,
        \"candidate_observation_sequence\": 11,
        \"case_id\": request[\"case_id\"],
        \"document\": \"cfw-packet-host-completed-v5\",
        \"restore\": restore,
        \"restore_observation_sequence\": 12,
        \"schema_version\": 5,
        \"sequence\": 8,
        \"session_id\": hello[\"session_id\"],
        \"test\": test,
        \"test_observation_sequence\": 11,
    })
else:
    send(channel, {
        \"case_id\": request[\"case_id\"],
        \"code\": \"capture_cancelled\",
        \"document\": \"cfw-packet-host-failed-v5\",
        \"schema_version\": 5,
        \"sequence\": 8,
        \"session_id\": hello[\"session_id\"],
    })
""",
                    encoding="utf-8",
                )
                executable = Path("/usr/bin/env")
                self.assertTrue(stat.S_ISREG(executable.stat().st_mode))
                with patch.object(packet_host, "HOST_EXECUTABLE", executable), patch.object(
                    packet_host,
                    "HOST_ARGV",
                    (
                        str(executable),
                        "/usr/bin/python3",
                        "-I",
                        "-S",
                        "-B",
                        str(helper),
                        str(write_fd),
                        str(identity.st_dev),
                        str(identity.st_ino),
                        str(marker),
                    ),
                ):
                    receipt = run_fixed_host_transaction(
                        case_id="dns-a-primary",
                        begin_capture=lambda ready: (
                            PacketCaptureDisposition.COMPLETE
                            if ready.case_id == "dns-a-primary"
                            else PacketCaptureDisposition.CANCELLED
                        ),
                        exercise_test=lambda ready: (
                            PacketCaptureDisposition.COMPLETE
                            if ready.test.generation == 8
                            else PacketCaptureDisposition.CANCELLED
                        ),
                        finish_capture=lambda ready: (
                            PacketCaptureDisposition.COMPLETE
                            if ready.restore.generation == 9
                            else PacketCaptureDisposition.CANCELLED
                        ),
                    )
                self.assertEqual(receipt.baseline.generation, 7)
                self.assertEqual(receipt.test.generation, 8)
                self.assertEqual(receipt.restore.generation, 9)
                self.assertEqual(receipt.candidate_observation_sequence, 11)
                self.assertFalse(marker.exists())
                self.assertTrue(os.get_inheritable(write_fd))
            finally:
                os.close(read_fd)
                os.close(write_fd)

    def test_unknown_case_is_rejected_before_host_launch(self) -> None:
        with patch.object(packet_host, "_validate_host_executable") as validate:
            with self.assertRaises(PacketHostError) as raised:
                run_fixed_host_transaction(
                    case_id="dns-caller-endpoint",
                    begin_capture=lambda _ready: PacketCaptureDisposition.COMPLETE,
                    exercise_test=lambda _ready: PacketCaptureDisposition.COMPLETE,
                    finish_capture=lambda _ready: PacketCaptureDisposition.COMPLETE,
                )
        self.assertEqual(raised.exception.code, "case_invalid")
        validate.assert_not_called()

    def test_cleanup_failure_is_attached_without_replacing_primary_error(self) -> None:
        invalid_hello = {
            "collector_pid": os.getpid(),
            "collector_uid": os.geteuid(),
            "document": "cfw-packet-host-hello-v5",
            "extra": True,
            "host_pid": 4244,
            "host_uid": os.geteuid(),
            "schema_version": 5,
        }
        cleanup_error = PacketHostError(
            "host_cleanup_unproven",
            "Packet Host process-group cleanup is unproven",
        )
        with patch.object(packet_host, "_validate_host_executable"), patch.object(
            packet_host, "_spawn_fixed_host", return_value=4244
        ), patch.object(
            packet_host, "_receive_frame", return_value=invalid_hello
        ), patch.object(
            packet_host, "_terminate_process_group", side_effect=cleanup_error
        ) as terminate:
            with self.assertRaises(PacketHostError) as raised:
                run_fixed_host_transaction(
                    case_id="tcp-ipv4",
                    begin_capture=lambda _ready: PacketCaptureDisposition.COMPLETE,
                    exercise_test=lambda _ready: PacketCaptureDisposition.COMPLETE,
                    finish_capture=lambda _ready: PacketCaptureDisposition.COMPLETE,
                )

        self.assertEqual(raised.exception.code, "host_hello_invalid")
        self.assertEqual(
            raised.exception.args,
            ("Packet Host hello has an invalid field set",),
        )
        self.assertEqual(raised.exception.cleanup_code, "host_cleanup_unproven")
        self.assertEqual(
            raised.exception.cleanup_context,
            "Packet Host process-group cleanup is unproven",
        )
        self.assertEqual(
            raised.exception.__notes__,
            [
                "Packet Host process-group cleanup also failed "
                "[host_cleanup_unproven]: "
                "Packet Host process-group cleanup is unproven"
            ],
        )
        self.assertIsNot(raised.exception.__cause__, cleanup_error)
        terminate.assert_called_once_with(4244)

    def test_zombie_leader_permission_race_is_reaped_before_group_retry(
        self,
    ) -> None:
        permission_error = PermissionError(1, "operation not permitted")
        with patch.object(
            packet_host.os,
            "waitpid",
            side_effect=[(0, 0), (4244, 0)],
        ) as waitpid, patch.object(
            packet_host.os,
            "killpg",
            side_effect=[permission_error, ProcessLookupError()],
        ) as killpg:
            packet_host._terminate_process_group(4244)

        self.assertEqual(
            waitpid.call_args_list,
            [
                call(4244, os.WNOHANG),
                call(4244, os.WNOHANG),
            ],
        )
        self.assertEqual(
            killpg.call_args_list,
            [
                call(4244, signal.SIGTERM),
                call(4244, signal.SIGTERM),
            ],
        )

    def test_permission_failure_after_reap_remains_fail_closed(self) -> None:
        with patch.object(
            packet_host.os, "waitpid", return_value=(4244, 0)
        ), patch.object(
            packet_host.os,
            "killpg",
            side_effect=PermissionError(1, "operation not permitted"),
        ), patch.object(
            packet_host.time,
            "monotonic",
            side_effect=[0.0, 3.0, 4.0, 5.0, 7.0],
        ):
            with self.assertRaises(PacketHostError) as raised:
                packet_host._terminate_process_group(4244)
        self.assertEqual(raised.exception.code, "host_cleanup_unproven")

    def test_permission_probe_after_reap_means_group_still_exists(self) -> None:
        with patch.object(
            packet_host.os,
            "killpg",
            side_effect=PermissionError(1, "operation not permitted"),
        ):
            self.assertTrue(packet_host._process_group_exists_after_reap(4244))

    def test_forced_cleanup_never_uses_an_unbounded_child_wait(self) -> None:
        with patch.object(
            packet_host.os, "waitpid", return_value=(0, 0)
        ) as waitpid, patch.object(
            packet_host.os, "killpg", return_value=None
        ), patch.object(
            packet_host.time,
            "monotonic",
            side_effect=[0.0, 3.0, 4.0, 7.0],
        ):
            with self.assertRaises(PacketHostError) as raised:
                packet_host._terminate_process_group(4244)
        self.assertEqual(raised.exception.code, "host_cleanup_unproven")
        self.assertTrue(waitpid.call_args_list)
        self.assertTrue(
            all(call_args.args == (4244, os.WNOHANG) for call_args in waitpid.call_args_list)
        )

    def test_unexpected_cleanup_context_preserves_non_domain_primary_error(self) -> None:
        primary_error = ValueError("primary transaction failure")
        cleanup_error = RuntimeError("unbounded internal cleanup detail")

        packet_host._attach_process_group_cleanup_context(
            primary_error, cleanup_error
        )

        self.assertEqual(primary_error.args, ("primary transaction failure",))
        self.assertEqual(
            primary_error.__notes__,
            [
                "Packet Host process-group cleanup also failed "
                "[host_cleanup_unexpected]: RuntimeError"
            ],
        )
        self.assertNotIn("unbounded internal cleanup detail", primary_error.__notes__[0])

    def test_aborted_host_state_still_invokes_exactly_one_terminal_cleanup(self) -> None:
        terminal_messages: list[dict[str, object]] = []
        worker: threading.Thread | None = None

        def spawn(child_fd: int, _parent_fd: int) -> int:
            nonlocal worker

            def host() -> None:
                channel = socket.socket(fileno=os.dup(child_fd))
                try:
                    _send_frame(
                        channel,
                        {
                            "collector_pid": os.getpid(),
                            "collector_uid": os.geteuid(),
                            "document": "cfw-packet-host-hello-v5",
                            "host_pid": 4242,
                            "host_uid": os.geteuid(),
                            "schema_version": 5,
                        },
                    )
                    hello = _receive_frame(channel)
                    request = _receive_frame(channel)
                    baseline = {
                        "config_digest": "a" * 64,
                        "desired_mode": "tunnel",
                        "generation": 7,
                        "ipv6_enabled": True,
                        "owner": "packet_tunnel_system_extension",
                        "phase": "tunnel_active",
                        "ready": True,
                    }
                    _send_frame(
                        channel,
                        {
                            "baseline": baseline,
                            "baseline_observation_sequence": 10,
                            "case_id": request["case_id"],
                            "document": "cfw-packet-host-baseline-observed-v5",
                            "schema_version": 5,
                            "sequence": 2,
                            "session_id": hello["session_id"],
                        },
                    )
                    terminal_messages.append(_receive_frame(channel))
                    _send_frame(
                        channel,
                        {
                            "baseline": baseline,
                            "baseline_observation_sequence": 10,
                            "case_id": request["case_id"],
                            "code": "observation_failed",
                            "document": "cfw-packet-host-capture-aborted-v5",
                            "schema_version": 5,
                            "sequence": 6,
                            "session_id": hello["session_id"],
                        },
                    )
                    terminal_messages.append(_receive_frame(channel))
                    _send_frame(
                        channel,
                        {
                            "case_id": request["case_id"],
                            "code": "observation_failed",
                            "document": "cfw-packet-host-failed-v5",
                            "schema_version": 5,
                            "sequence": 8,
                            "session_id": hello["session_id"],
                        },
                    )
                finally:
                    channel.close()

            worker = threading.Thread(target=host)
            worker.start()
            return 4242

        cleanup_calls = 0

        def finish(terminal: object) -> PacketCaptureDisposition:
            nonlocal cleanup_calls
            self.assertIsInstance(terminal, packet_host.PacketHostAborted)
            cleanup_calls += 1
            return PacketCaptureDisposition.COMPLETE

        with patch.object(packet_host, "_validate_host_executable"), patch.object(
            packet_host, "_spawn_fixed_host", side_effect=spawn
        ), patch.object(packet_host, "_terminate_process_group"):
            with self.assertRaises(PacketHostError) as raised:
                run_fixed_host_transaction(
                    case_id="tcp-ipv4",
                    begin_capture=lambda _ready: PacketCaptureDisposition.COMPLETE,
                    exercise_test=lambda _ready: self.fail("test stage must not run"),
                    finish_capture=finish,
                )
        if worker is not None:
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(raised.exception.code, "observation_failed")
        self.assertEqual(cleanup_calls, 1)
        self.assertEqual(
            [message["document"] for message in terminal_messages],
            [
                "cfw-packet-collector-capture-started-v5",
                "cfw-packet-collector-capture-completed-v5",
            ],
        )

    def test_failed_begin_still_invokes_exactly_one_terminal_cleanup(self) -> None:
        stage_messages: list[dict[str, object]] = []
        worker: threading.Thread | None = None

        def spawn(child_fd: int, _parent_fd: int) -> int:
            nonlocal worker

            def host() -> None:
                channel = socket.socket(fileno=os.dup(child_fd))
                try:
                    _send_frame(
                        channel,
                        {
                            "collector_pid": os.getpid(),
                            "collector_uid": os.geteuid(),
                            "document": "cfw-packet-host-hello-v5",
                            "host_pid": 4243,
                            "host_uid": os.geteuid(),
                            "schema_version": 5,
                        },
                    )
                    hello = _receive_frame(channel)
                    request = _receive_frame(channel)
                    baseline = {
                        "config_digest": "a" * 64,
                        "desired_mode": "tunnel",
                        "generation": 7,
                        "ipv6_enabled": True,
                        "owner": "packet_tunnel_system_extension",
                        "phase": "tunnel_active",
                        "ready": True,
                    }
                    _send_frame(
                        channel,
                        {
                            "baseline": baseline,
                            "baseline_observation_sequence": 10,
                            "case_id": request["case_id"],
                            "document": "cfw-packet-host-baseline-observed-v5",
                            "schema_version": 5,
                            "sequence": 2,
                            "session_id": hello["session_id"],
                        },
                    )
                    stage_messages.append(_receive_frame(channel))
                    _send_frame(
                        channel,
                        {
                            "baseline": baseline,
                            "baseline_observation_sequence": 10,
                            "case_id": request["case_id"],
                            "document": "cfw-packet-host-baseline-restored-v5",
                            "restore": baseline,
                            "restore_observation_sequence": 11,
                            "schema_version": 5,
                            "sequence": 6,
                            "session_id": hello["session_id"],
                            "test": None,
                            "test_observation_sequence": None,
                        },
                    )
                    stage_messages.append(_receive_frame(channel))
                    _send_frame(
                        channel,
                        {
                            "case_id": request["case_id"],
                            "code": "capture_cancelled",
                            "document": "cfw-packet-host-failed-v5",
                            "schema_version": 5,
                            "sequence": 8,
                            "session_id": hello["session_id"],
                        },
                    )
                finally:
                    channel.close()

            worker = threading.Thread(target=host)
            worker.start()
            return 4243

        cleanup_calls = 0

        def finish(terminal: object) -> PacketCaptureDisposition:
            nonlocal cleanup_calls
            self.assertIsInstance(terminal, packet_host.PacketHostRestored)
            cleanup_calls += 1
            return PacketCaptureDisposition.COMPLETE

        with patch.object(packet_host, "_validate_host_executable"), patch.object(
            packet_host, "_spawn_fixed_host", side_effect=spawn
        ), patch.object(packet_host, "_terminate_process_group"):
            with self.assertRaises(PacketHostError) as raised:
                run_fixed_host_transaction(
                    case_id="tcp-ipv4",
                    begin_capture=lambda _ready: PacketCaptureDisposition.CANCELLED,
                    exercise_test=lambda _ready: self.fail("test stage must not run"),
                    finish_capture=finish,
                )
        if worker is not None:
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(raised.exception.code, "capture_cancelled")
        self.assertEqual(cleanup_calls, 1)
        self.assertEqual(
            [message["document"] for message in stage_messages],
            [
                "cfw-packet-collector-capture-start-failed-v5",
                "cfw-packet-collector-capture-completed-v5",
            ],
        )


if __name__ == "__main__":
    unittest.main()
