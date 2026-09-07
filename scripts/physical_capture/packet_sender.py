#!/usr/bin/python3
"""Source-reviewed single-stage sender for physical Packet evidence.

The helper has no generic execution surface.  It accepts one exact case/stage
pair, binds the source-selected local socket when the case is not DNS, emits
exactly one evidence token, and prints one canonical receipt.  The production
adapter owns ordering around the signed Host's baseline/test/restore stages.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import time


DOCUMENT = "cfw-packet-send-stage-result-v2"
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
MAX_ABSENCE_WINDOW_MS = 30_000
SOCKET_TIMEOUT_SECONDS = 5.0
STAGES = ("start", "target", "end")
CASE_MATRIX = {
    "tcp-ipv4": ("tcp", "ipv4"),
    "tcp-ipv6": ("tcp", "ipv6"),
    "udp": ("udp", "ipv4"),
    "quic": ("quic", "ipv4"),
    "dns-a-primary": ("dns", "ipv4"),
    "dns-a-secondary": ("dns", "ipv4"),
    "dns-aaaa-primary": ("dns", "ipv6"),
    "dns-aaaa-secondary": ("dns", "ipv6"),
    "lan-bypass": ("tcp", "ipv4"),
    "included-routes": ("tcp", "ipv4"),
    "excluded-routes": ("tcp", "ipv4"),
    "stop-cleanup": ("tcp", "ipv4"),
    "ipv6-disabled-absence": ("tcp", "ipv6"),
}
ABSENCE_CASES = frozenset({"stop-cleanup", "ipv6-disabled-absence"})


class PacketSendError(RuntimeError):
    """The fixed packet stage could not be submitted exactly."""


def _token(value: str, label: str) -> bytes:
    if TOKEN_RE.fullmatch(value) is None:
        raise PacketSendError(f"{label} is not a canonical packet token")
    return value.encode("ascii")


def _family(name: str) -> socket.AddressFamily:
    return socket.AF_INET if name == "ipv4" else socket.AF_INET6


def _address(value: str, family: str, label: str) -> str:
    if not isinstance(value, str):
        raise PacketSendError(f"{label} is not an IP address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise PacketSendError(f"{label} is not an IP address") from error
    expected = 4 if family == "ipv4" else 6
    if parsed.version != expected:
        raise PacketSendError(f"{label} differs from the case address family")
    return str(parsed)


def _resolve_dns(
    *,
    family: str,
    resolver_role: str,
    token: bytes,
    absence_window_ms: int,
) -> dict[str, object]:
    if resolver_role not in {"primary", "secondary"}:
        raise PacketSendError("DNS resolver role is not primary or secondary")
    name = f"{token.decode('ascii')}.evidence.test"
    try:
        records = socket.getaddrinfo(
            name,
            None,
            _family(family),
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP,
            0,
        )
    except socket.gaierror as error:
        raise PacketSendError("product DNS resolution did not complete") from error
    addresses: set[str] = set()
    for record in records:
        if len(record) != 5 or not isinstance(record[4], tuple) or not record[4]:
            raise PacketSendError("getaddrinfo returned a malformed record")
        addresses.add(_address(record[4][0], family, "resolved address"))
    if not addresses or len(addresses) > 16:
        raise PacketSendError("product DNS resolution result count is outside the bound")
    if absence_window_ms:
        time.sleep(absence_window_ms / 1000)
    return {
        "trigger": "getaddrinfo",
        "resolver_role": resolver_role,
        "requested_type": "A" if family == "ipv4" else "AAAA",
        "query": {
            "name": name,
            "token_sha256": hashlib.sha256(token).hexdigest(),
            "addresses": sorted(addresses),
        },
    }


def _quic_initial(token: bytes, version: int) -> bytes:
    if len(token) > 20:
        raise PacketSendError("QUIC evidence token exceeds the CID bound")
    source = hashlib.sha256(b"cfw-packet-quic-scid-v1\0" + token).digest()[:8]
    return b"\xc0" + version.to_bytes(4, "big") + bytes((len(token),)) + token + bytes(
        (len(source),)
    ) + source


def _send_datagram(
    *,
    protocol: str,
    family: str,
    local: tuple[str, int],
    remote: tuple[str, int],
    token: bytes,
    quic_version: int,
    absence_window_ms: int,
) -> tuple[str, int, None]:
    with socket.socket(_family(family), socket.SOCK_DGRAM) as connection:
        connection.settimeout(SOCKET_TIMEOUT_SECONDS)
        connection.bind(local)
        bound = connection.getsockname()
        payload = _quic_initial(token, quic_version) if protocol == "quic" else token
        if connection.sendto(payload, remote) != len(payload):
            raise PacketSendError("datagram submission was incomplete")
        if absence_window_ms:
            time.sleep(absence_window_ms / 1000)
        return str(bound[0]), int(bound[1]), None


def _send_tcp(
    *,
    family: str,
    local: tuple[str, int],
    remote: tuple[str, int],
    token: bytes,
    absence_window_ms: int,
) -> tuple[str, int, None]:
    with socket.socket(_family(family), socket.SOCK_STREAM) as connection:
        connection.settimeout(SOCKET_TIMEOUT_SECONDS)
        connection.bind(local)
        connection.connect(remote)
        bound = connection.getsockname()
        connection.sendall(token)
        if absence_window_ms:
            time.sleep(absence_window_ms / 1000)
        connection.shutdown(socket.SHUT_WR)
        return str(bound[0]), int(bound[1]), None


def _port(value: int, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise PacketSendError(f"{label} is outside the port range")
    return value


def _local_port(value: int) -> int:
    if type(value) is not int or not 0 <= value <= 65535:
        raise PacketSendError("local port is outside the bind range")
    return value


def run(arguments: argparse.Namespace) -> dict[str, object]:
    expected = CASE_MATRIX[arguments.case]
    if (arguments.protocol, arguments.family) != expected:
        raise PacketSendError("case protocol/family differs from the fixed matrix")
    if arguments.stage not in STAGES:
        raise PacketSendError("packet stage is not source-owned")
    if arguments.protocol == "quic" and arguments.quic_version not in {1, 0x6B3343CF}:
        raise PacketSendError("QUIC evidence version is not v1 or v2")
    if arguments.protocol != "quic" and arguments.quic_version != 0:
        raise PacketSendError("non-QUIC evidence declares a QUIC version")
    expected_absence_window = (
        3_000
        if arguments.case in ABSENCE_CASES and arguments.stage == "target"
        else 0
    )
    if (
        not 0 <= arguments.absence_window_ms <= MAX_ABSENCE_WINDOW_MS
        or arguments.absence_window_ms != expected_absence_window
    ):
        raise PacketSendError("absence window differs from the fixed case/stage plan")
    token = _token(arguments.token, f"{arguments.stage} token")
    if arguments.protocol == "dns":
        if any(
            value is not None
            for value in (
                arguments.local_address,
                arguments.local_port,
                arguments.remote_address,
                arguments.remote_port,
            )
        ):
            raise PacketSendError("DNS resolver trigger must not declare a raw socket tuple")
        observed_local: tuple[str | None, int | None, dict[str, object] | None] = (
            None,
            None,
            _resolve_dns(
                family=arguments.family,
                resolver_role=arguments.resolver_role,
                token=token,
                absence_window_ms=arguments.absence_window_ms,
            ),
        )
        remote_address = None
        remote_port = None
        transport = "resolver"
    else:
        if arguments.resolver_role != "none":
            raise PacketSendError("non-DNS packet send declares a resolver role")
        local_address = _address(
            arguments.local_address, arguments.family, "local address"
        )
        remote_address = _address(
            arguments.remote_address, arguments.family, "remote address"
        )
        local_port = _local_port(arguments.local_port)
        remote_port = _port(arguments.remote_port, "remote port")
        local = (local_address, local_port)
        remote = (remote_address, remote_port)
        transport = "tcp" if arguments.protocol == "tcp" else "udp"
        if arguments.protocol == "tcp":
            observed_local = _send_tcp(
                family=arguments.family,
                local=local,
                remote=remote,
                token=token,
                absence_window_ms=arguments.absence_window_ms,
            )
        else:
            observed_local = _send_datagram(
                protocol=arguments.protocol,
                family=arguments.family,
                local=local,
                remote=remote,
                token=token,
                quic_version=arguments.quic_version,
                absence_window_ms=arguments.absence_window_ms,
            )
    return {
        "schema_version": 2,
        "document": DOCUMENT,
        "case_id": arguments.case,
        "stage": arguments.stage,
        "local_address": observed_local[0],
        "local_port": observed_local[1],
        "remote_address": remote_address,
        "remote_port": remote_port,
        "transport": transport,
        "token_sha256": hashlib.sha256(token).hexdigest(),
        "bytes_submitted": len(token),
        "dns_result": observed_local[2],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=tuple(CASE_MATRIX), required=True)
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--protocol", choices=("tcp", "udp", "dns", "quic"), required=True)
    parser.add_argument("--family", choices=("ipv4", "ipv6"), required=True)
    parser.add_argument("--local-address")
    parser.add_argument("--local-port", type=int)
    parser.add_argument("--remote-address")
    parser.add_argument("--remote-port", type=int)
    parser.add_argument(
        "--resolver-role", choices=("none", "primary", "secondary"), required=True
    )
    parser.add_argument("--token", required=True)
    parser.add_argument("--quic-version", type=int, required=True)
    parser.add_argument("--absence-window-ms", type=int, required=True)
    return parser


def main() -> None:
    try:
        result = run(_parser().parse_args())
    except (OSError, PacketSendError, TimeoutError) as error:
        raise SystemExit(f"error: fixed packet send failed: {error}") from error
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
