from __future__ import annotations

import argparse
import socket
import unittest
from unittest.mock import patch

from scripts.physical_capture import packet_sender


def _arguments(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "case": "udp",
        "stage": "target",
        "protocol": "udp",
        "family": "ipv4",
        "local_address": "127.0.0.1",
        "local_port": 0,
        "remote_address": "127.0.0.1",
        "remote_port": 44333,
        "resolver_role": "none",
        "token": "packet-target-0001",
        "quic_version": 0,
        "absence_window_ms": 0,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class PacketSenderTests(unittest.TestCase):
    def test_udp_uses_kernel_ephemeral_port_and_sends_exact_stage(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(2)
            remote_port = receiver.getsockname()[1]
            result = packet_sender.run(_arguments(remote_port=remote_port))
            payload = receiver.recvfrom(256)[0]

        self.assertEqual(payload, b"packet-target-0001")
        self.assertEqual(result["document"], packet_sender.DOCUMENT)
        self.assertEqual(result["stage"], "target")
        self.assertEqual(result["local_address"], "127.0.0.1")
        self.assertGreaterEqual(result["local_port"], 1)
        self.assertEqual(result["remote_port"], remote_port)
        self.assertEqual(result["transport"], "udp")
        self.assertEqual(result["bytes_submitted"], len(b"packet-target-0001"))
        self.assertIsNone(result["dns_result"])

    def test_dns_uses_system_resolver_trigger_without_a_raw_socket_tuple(self) -> None:
        arguments = _arguments(
            case="dns-a-primary",
            protocol="dns",
            local_address=None,
            local_port=None,
            remote_address=None,
            remote_port=None,
            resolver_role="primary",
        )
        records = [
            (
                socket.AF_INET,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
                "",
                ("198.18.2.6", 0),
            )
        ]
        with patch.object(
            packet_sender.socket, "getaddrinfo", return_value=records
        ) as resolver, patch.object(packet_sender.time, "sleep"):
            result = packet_sender.run(arguments)
        self.assertEqual(resolver.call_count, 1)
        self.assertIsNone(result["local_address"])
        self.assertIsNone(result["remote_address"])
        self.assertEqual(result["transport"], "resolver")
        self.assertEqual(result["dns_result"]["trigger"], "getaddrinfo")
        self.assertEqual(result["dns_result"]["resolver_role"], "primary")
        self.assertEqual(result["dns_result"]["requested_type"], "A")
        self.assertEqual(
            result["dns_result"]["query"]["addresses"], ["198.18.2.6"]
        )

    def test_quic_header_binds_fixed_bit_version_and_connection_id(self) -> None:
        token = b"packet-target-0001"
        packet = packet_sender._quic_initial(token, 1)
        self.assertEqual(packet[0] & 0x40, 0x40)
        self.assertEqual(int.from_bytes(packet[1:5], "big"), 1)
        self.assertEqual(packet[5], len(token))
        self.assertEqual(packet[6 : 6 + len(token)], token)

    def test_invalid_matrix_port_version_and_window_fail_closed(self) -> None:
        invalid = (
            _arguments(case="tcp-ipv4"),
            _arguments(
                case="dns-a-primary",
                protocol="dns",
                remote_port=44333,
                resolver_role="primary",
            ),
            _arguments(quic_version=1),
            _arguments(absence_window_ms=packet_sender.MAX_ABSENCE_WINDOW_MS + 1),
            _arguments(
                case="stop-cleanup",
                protocol="tcp",
                absence_window_ms=0,
            ),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                with self.assertRaises(packet_sender.PacketSendError):
                    packet_sender.run(arguments)

    def test_absence_delay_is_exactly_target_stage_only(self) -> None:
        arguments = _arguments(
            case="ipv6-disabled-absence",
            protocol="tcp",
            family="ipv6",
            local_address="2001:db8::1",
            remote_address="2001:db8::2",
            absence_window_ms=3_000,
        )
        with patch.object(packet_sender, "_send_tcp", return_value=("2001:db8::1", 51000, None)) as sender:
            result = packet_sender.run(arguments)
        self.assertEqual(result["stage"], "target")
        self.assertEqual(sender.call_args.kwargs["absence_window_ms"], 3_000)

        arguments.stage = "end"
        with self.assertRaises(packet_sender.PacketSendError):
            packet_sender.run(arguments)


if __name__ == "__main__":
    unittest.main()
