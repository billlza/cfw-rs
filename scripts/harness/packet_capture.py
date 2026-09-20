"""Bounded, protocol-aware pcap/pcapng validation for packet evidence."""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
import hashlib
import ipaddress
import struct
from typing import Iterable


MAX_CAPTURE_PACKETS = 100_000
MAX_CAPTURE_BLOCKS = 200_000
MAX_SNAPLEN = 262_144
MAX_PACKET_BYTES = 262_144
MAX_REASSEMBLED_FLOW_BYTES = 1 * 1024 * 1024
MAX_IPV6_EXTENSION_HEADERS = 8
MAX_VLAN_TAGS = 2

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
ALLOWED_LINK_TYPES = frozenset(
    {DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LOOP, DLT_LINUX_SLL, DLT_LINUX_SLL2}
)

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
VLAN_ETHERTYPES = frozenset({0x8100, 0x88A8, 0x9100})
DARWIN_AF_INET = 2
DARWIN_AF_INET6 = 30
QUIC_VERSION_1 = 0x00000001
QUIC_VERSION_2 = 0x6B3343CF
SUPPORTED_QUIC_VERSIONS = frozenset({QUIC_VERSION_1, QUIC_VERSION_2})
DNS_TTL = 0
DNS_A_ADDRESS = "192.0.2.1"
DNS_AAAA_ADDRESS = "2001:db8::1"
DNS_RESPONSE_DIGEST_DOMAIN = b"cfw-packet-dns-responses-v1\0"


class PacketCaptureError(ValueError):
    """A capture is malformed or does not prove its declared network behavior."""


@dataclass(frozen=True)
class CaptureInterface:
    interface_id: int
    link_type: int
    snaplen: int
    timestamp_resolution: Fraction
    name: str | None


@dataclass(frozen=True)
class PacketRecord:
    timestamp: Fraction
    payload: bytes
    link_type: int
    interface_id: int


@dataclass(frozen=True)
class ParsedCapture:
    records: tuple[PacketRecord, ...]
    interfaces: tuple[CaptureInterface, ...]


@dataclass(frozen=True)
class CaptureProof:
    observation_ms: int
    started_at: Fraction
    ended_at: Fraction
    start_event_started_at: Fraction
    start_event_ended_at: Fraction
    target_started_at: Fraction | None
    target_ended_at: Fraction | None
    end_event_started_at: Fraction
    end_event_ended_at: Fraction
    total_record_count: int
    packet_count: int
    token_occurrences: int
    link_type: int
    interface_name: str | None
    quic_version: int | None
    dns_response_count: int | None
    dns_answer_type: str | None
    dns_answer_address: str | None
    dns_ttl: int | None
    dns_responses_sha256: str | None


@dataclass(frozen=True)
class StagedCaptureEndpoint:
    """One exact sender-stage flow retained by Packet provenance."""

    stage: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int


@dataclass(frozen=True)
class NetworkPacket:
    timestamp: Fraction
    family: str
    source: str
    destination: str
    protocol: int
    payload: bytes
    link_type: int
    interface_id: int


@dataclass(frozen=True)
class TransportPacket:
    timestamp: Fraction
    family: str
    source: str
    destination: str
    source_port: int
    destination_port: int
    protocol: str
    payload: bytes
    sequence: int | None
    link_type: int
    interface_id: int


@dataclass(frozen=True)
class DnsMessage:
    identifier: int
    is_response: bool
    question_name: str
    question_type: int
    answer_address: str | None


def _parse_options(
    data: bytes,
    endian: str,
    *,
    allow_tsresol: bool,
    allow_name: bool,
) -> tuple[Fraction, str | None]:
    offset = 0
    option_count = 0
    resolution = Fraction(1, 1_000_000)
    name: str | None = None
    seen_resolution = False
    ended = False
    while offset < len(data):
        if len(data) - offset < 4:
            raise PacketCaptureError("pcapng option header is truncated")
        code, length = struct.unpack_from(f"{endian}HH", data, offset)
        offset += 4
        if code == 0:
            if length != 0 or any(data[offset:]):
                raise PacketCaptureError("pcapng end-of-options record is malformed")
            ended = True
            offset = len(data)
            break
        option_count += 1
        if option_count > 256:
            raise PacketCaptureError("pcapng option count exceeds the bound")
        padded = (length + 3) & ~3
        if offset + padded > len(data):
            raise PacketCaptureError("pcapng option payload is truncated")
        payload = data[offset : offset + length]
        if any(data[offset + length : offset + padded]):
            raise PacketCaptureError("pcapng option padding is nonzero")
        if code == 2:
            if not allow_name or name is not None or not payload or len(payload) > 64:
                raise PacketCaptureError("pcapng interface-name option is invalid")
            try:
                name = payload.decode("ascii")
            except UnicodeDecodeError as error:
                raise PacketCaptureError("pcapng interface name is not ASCII") from error
            if not name.isprintable() or name.strip() != name:
                raise PacketCaptureError("pcapng interface name is not canonical")
        elif code == 9:
            if not allow_tsresol or seen_resolution or length != 1:
                raise PacketCaptureError("pcapng timestamp-resolution option is invalid")
            raw = payload[0]
            exponent = raw & 0x7F
            if exponent > 30:
                raise PacketCaptureError("pcapng timestamp resolution is too fine")
            resolution = (
                Fraction(1, 2**exponent)
                if raw & 0x80
                else Fraction(1, 10**exponent)
            )
            seen_resolution = True
        offset += padded
    if data and not ended:
        raise PacketCaptureError("pcapng options do not contain an end marker")
    return resolution, name


def _capture_pcap(data: bytes) -> ParsedCapture:
    if len(data) < 24:
        raise PacketCaptureError("pcap global header is truncated")
    formats: dict[bytes, tuple[str, int]] = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if data[:4] not in formats:
        raise PacketCaptureError("pcap magic is unsupported")
    endian, subsecond_scale = formats[data[:4]]
    version_major, version_minor, timezone, sigfigs, snaplen, network = struct.unpack_from(
        f"{endian}HHiIII", data, 4
    )
    if (version_major, version_minor) != (2, 4):
        raise PacketCaptureError("pcap version is not 2.4")
    if timezone != 0 or sigfigs != 0:
        raise PacketCaptureError("pcap timezone/sigfigs fields must be zero")
    if snaplen < 1 or snaplen > MAX_SNAPLEN:
        raise PacketCaptureError("pcap snaplen is outside the accepted range")
    if network not in ALLOWED_LINK_TYPES:
        raise PacketCaptureError("pcap link type is not accepted")
    interface = CaptureInterface(0, network, snaplen, Fraction(1, subsecond_scale), None)
    records: list[PacketRecord] = []
    offset = 24
    while offset < len(data):
        if len(records) >= MAX_CAPTURE_PACKETS:
            raise PacketCaptureError("pcap packet count exceeds the bound")
        if len(data) - offset < 16:
            raise PacketCaptureError("pcap packet header is truncated")
        seconds, subseconds, included, original = struct.unpack_from(
            f"{endian}IIII", data, offset
        )
        offset += 16
        if subseconds >= subsecond_scale:
            raise PacketCaptureError("pcap packet timestamp fraction is malformed")
        if included < 1 or included > snaplen or included > MAX_PACKET_BYTES:
            raise PacketCaptureError("pcap captured packet length is outside the bound")
        if original < included:
            raise PacketCaptureError("pcap original packet length is below captured length")
        end = offset + included
        if end > len(data):
            raise PacketCaptureError("pcap packet payload is truncated")
        records.append(
            PacketRecord(
                timestamp=Fraction(seconds, 1) + Fraction(subseconds, subsecond_scale),
                payload=data[offset:end],
                link_type=network,
                interface_id=0,
            )
        )
        offset = end
    if offset != len(data) or not records:
        raise PacketCaptureError("pcap contains no complete packet records")
    return ParsedCapture(tuple(records), (interface,))


def _capture_pcapng(data: bytes) -> ParsedCapture:
    if len(data) < 28 or data[:4] != b"\x0a\x0d\x0d\x0a":
        raise PacketCaptureError("pcapng must start with a section header block")
    records: list[PacketRecord] = []
    interfaces: list[CaptureInterface] = []
    offset = 0
    endian: str | None = None
    block_count = 0
    seen_section = False
    while offset < len(data):
        block_count += 1
        if block_count > MAX_CAPTURE_BLOCKS:
            raise PacketCaptureError("pcapng block count exceeds the bound")
        if len(data) - offset < 12:
            raise PacketCaptureError("pcapng block header is truncated")
        raw_type = data[offset : offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            if seen_section:
                raise PacketCaptureError("pcapng multiple sections are not accepted")
            if len(data) - offset < 28:
                raise PacketCaptureError("pcapng section header is truncated")
            byte_order_magic = data[offset + 8 : offset + 12]
            if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PacketCaptureError("pcapng section byte-order magic is invalid")
            seen_section = True
        if endian is None:
            raise PacketCaptureError("pcapng block appears outside a section")
        block_type, block_length = struct.unpack_from(f"{endian}II", data, offset)
        if block_length < 12 or block_length % 4 != 0:
            raise PacketCaptureError("pcapng block length is invalid")
        end = offset + block_length
        if end > len(data):
            raise PacketCaptureError("pcapng block is truncated")
        if struct.unpack_from(f"{endian}I", data, end - 4)[0] != block_length:
            raise PacketCaptureError("pcapng block length trailer differs")
        body = data[offset + 8 : end - 4]
        if block_type == 0x0A0D0D0A:
            if block_length < 28:
                raise PacketCaptureError("pcapng section header length is invalid")
            major, minor = struct.unpack_from(f"{endian}HH", body, 4)
            section_length = struct.unpack_from(f"{endian}q", body, 8)[0]
            if (major, minor) != (1, 0) or section_length != -1:
                raise PacketCaptureError("pcapng section version/length contract is unsupported")
            interfaces = []
            if len(body) > 16:
                _parse_options(
                    body[16:], endian, allow_tsresol=False, allow_name=False
                )
        elif block_type == 1:
            if len(body) < 8:
                raise PacketCaptureError("pcapng interface description is truncated")
            link_type, reserved, snaplen = struct.unpack_from(f"{endian}HHI", body, 0)
            if reserved != 0 or link_type not in ALLOWED_LINK_TYPES:
                raise PacketCaptureError("pcapng interface link metadata is invalid")
            if snaplen < 1 or snaplen > MAX_SNAPLEN:
                raise PacketCaptureError("pcapng interface snaplen is outside the bound")
            resolution, name = _parse_options(
                body[8:], endian, allow_tsresol=True, allow_name=True
            )
            interfaces.append(
                CaptureInterface(len(interfaces), link_type, snaplen, resolution, name)
            )
        elif block_type == 6:
            if len(records) >= MAX_CAPTURE_PACKETS:
                raise PacketCaptureError("pcapng packet count exceeds the bound")
            if len(body) < 20:
                raise PacketCaptureError("pcapng enhanced packet block is truncated")
            interface_id, timestamp_high, timestamp_low, captured, original = struct.unpack_from(
                f"{endian}IIIII", body, 0
            )
            if interface_id >= len(interfaces):
                raise PacketCaptureError("pcapng packet references an unknown interface")
            interface = interfaces[interface_id]
            if captured < 1 or captured > interface.snaplen or captured > MAX_PACKET_BYTES:
                raise PacketCaptureError("pcapng captured packet length is outside the bound")
            if original < captured:
                raise PacketCaptureError("pcapng original packet length is below captured length")
            padded = (captured + 3) & ~3
            if 20 + padded > len(body):
                raise PacketCaptureError("pcapng enhanced packet payload is truncated")
            payload = body[20 : 20 + captured]
            if any(body[20 + captured : 20 + padded]):
                raise PacketCaptureError("pcapng packet padding is nonzero")
            if len(body) > 20 + padded:
                _parse_options(
                    body[20 + padded :], endian, allow_tsresol=False, allow_name=False
                )
            timestamp = (timestamp_high << 32) | timestamp_low
            records.append(
                PacketRecord(
                    timestamp=timestamp * interface.timestamp_resolution,
                    payload=payload,
                    link_type=interface.link_type,
                    interface_id=interface_id,
                )
            )
        elif block_type in {2, 3}:
            raise PacketCaptureError("pcapng packet block lacks an accepted timestamp contract")
        offset = end
    if offset != len(data) or not records:
        raise PacketCaptureError("pcapng contains no enhanced packet records")
    return ParsedCapture(tuple(records), tuple(interfaces))


def parse_packet_capture(data: bytes, kind: str) -> ParsedCapture:
    if kind == "packet-pcap":
        return _capture_pcap(data)
    if kind == "packet-pcapng":
        return _capture_pcapng(data)
    raise PacketCaptureError(f"unsupported capture kind: {kind!r}")


def parse_packet_records(data: bytes, kind: str) -> list[PacketRecord]:
    """Compatibility-free v3 parser entry returning semantically tagged records."""

    return list(parse_packet_capture(data, kind).records)


def _network_payload(record: PacketRecord) -> tuple[str, bytes]:
    frame = record.payload
    if record.link_type == DLT_EN10MB:
        if len(frame) < 14:
            raise PacketCaptureError("Ethernet frame is truncated")
        offset = 14
        ether_type = int.from_bytes(frame[12:14], "big")
        tags = 0
        while ether_type in VLAN_ETHERTYPES:
            tags += 1
            if tags > MAX_VLAN_TAGS or len(frame) < offset + 4:
                raise PacketCaptureError("Ethernet VLAN stack is invalid or excessive")
            ether_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
        payload = frame[offset:]
    elif record.link_type == DLT_RAW:
        if not frame:
            raise PacketCaptureError("raw IP frame is empty")
        version = frame[0] >> 4
        ether_type = ETHERTYPE_IPV4 if version == 4 else ETHERTYPE_IPV6 if version == 6 else 0
        payload = frame
    elif record.link_type in {DLT_NULL, DLT_LOOP}:
        if len(frame) < 4:
            raise PacketCaptureError("loopback frame is truncated")
        family = int.from_bytes(
            frame[:4], "little" if record.link_type == DLT_NULL else "big"
        )
        ether_type = (
            ETHERTYPE_IPV4
            if family == DARWIN_AF_INET
            else ETHERTYPE_IPV6
            if family == DARWIN_AF_INET6
            else 0
        )
        payload = frame[4:]
    elif record.link_type == DLT_LINUX_SLL:
        if len(frame) < 16:
            raise PacketCaptureError("Linux cooked-v1 frame is truncated")
        ether_type = int.from_bytes(frame[14:16], "big")
        payload = frame[16:]
    elif record.link_type == DLT_LINUX_SLL2:
        if len(frame) < 20:
            raise PacketCaptureError("Linux cooked-v2 frame is truncated")
        ether_type = int.from_bytes(frame[0:2], "big")
        payload = frame[20:]
    else:  # pragma: no cover - the capture parser rejects this first
        raise PacketCaptureError("packet uses an unsupported link type")
    if ether_type == ETHERTYPE_IPV4:
        return "ipv4", payload
    if ether_type == ETHERTYPE_IPV6:
        return "ipv6", payload
    raise PacketCaptureError("captured frame does not contain IPv4 or IPv6")


def _decode_network(record: PacketRecord) -> NetworkPacket:
    family, packet = _network_payload(record)
    if family == "ipv4":
        if len(packet) < 20 or packet[0] >> 4 != 4:
            raise PacketCaptureError("IPv4 header is truncated or malformed")
        header_length = (packet[0] & 0x0F) * 4
        total_length = int.from_bytes(packet[2:4], "big")
        fragment = int.from_bytes(packet[6:8], "big")
        if header_length < 20 or total_length < header_length or total_length > len(packet):
            raise PacketCaptureError("IPv4 length contract is invalid")
        if fragment & 0xBFFF:
            raise PacketCaptureError("fragmented IPv4 evidence is not accepted")
        source = str(ipaddress.ip_address(packet[12:16]))
        destination = str(ipaddress.ip_address(packet[16:20]))
        protocol = packet[9]
        payload = packet[header_length:total_length]
    else:
        if len(packet) < 40 or packet[0] >> 4 != 6:
            raise PacketCaptureError("IPv6 header is truncated or malformed")
        payload_length = int.from_bytes(packet[4:6], "big")
        total_length = 40 + payload_length
        if payload_length == 0 or total_length > len(packet):
            raise PacketCaptureError("IPv6 payload length is invalid")
        source = str(ipaddress.ip_address(packet[8:24]))
        destination = str(ipaddress.ip_address(packet[24:40]))
        protocol = packet[6]
        offset = 40
        extensions = 0
        while protocol in {0, 43, 51, 60}:
            extensions += 1
            if extensions > MAX_IPV6_EXTENSION_HEADERS or offset + 2 > total_length:
                raise PacketCaptureError("IPv6 extension-header chain is invalid or excessive")
            next_protocol = packet[offset]
            extension_length = (
                (packet[offset + 1] + 2) * 4
                if protocol == 51
                else (packet[offset + 1] + 1) * 8
            )
            if extension_length < 8 or offset + extension_length > total_length:
                raise PacketCaptureError("IPv6 extension-header length is invalid")
            protocol = next_protocol
            offset += extension_length
        if protocol == 44:
            raise PacketCaptureError("fragmented IPv6 evidence is not accepted")
        if protocol in {50, 59}:
            raise PacketCaptureError("encrypted/no-next-header IPv6 evidence cannot prove transport")
        payload = packet[offset:total_length]
    return NetworkPacket(
        record.timestamp,
        family,
        source,
        destination,
        protocol,
        payload,
        record.link_type,
        record.interface_id,
    )


def _decode_transport(packet: NetworkPacket) -> TransportPacket:
    if packet.protocol == 6:
        if len(packet.payload) < 20:
            raise PacketCaptureError("TCP header is truncated")
        source_port, destination_port, sequence = struct.unpack_from("!HHI", packet.payload, 0)
        header_length = (packet.payload[12] >> 4) * 4
        if header_length < 20 or header_length > len(packet.payload):
            raise PacketCaptureError("TCP data offset is invalid")
        return TransportPacket(
            packet.timestamp,
            packet.family,
            packet.source,
            packet.destination,
            source_port,
            destination_port,
            "tcp",
            packet.payload[header_length:],
            sequence,
            packet.link_type,
            packet.interface_id,
        )
    if packet.protocol == 17:
        if len(packet.payload) < 8:
            raise PacketCaptureError("UDP header is truncated")
        source_port, destination_port, length = struct.unpack_from("!HHH", packet.payload, 0)
        if length < 8 or length > len(packet.payload):
            raise PacketCaptureError("UDP length is invalid")
        return TransportPacket(
            packet.timestamp,
            packet.family,
            packet.source,
            packet.destination,
            source_port,
            destination_port,
            "udp",
            packet.payload[8:length],
            None,
            packet.link_type,
            packet.interface_id,
        )
    raise PacketCaptureError("capture contains a non-TCP/UDP network packet")


def _matches_flow(
    packet: TransportPacket,
    *,
    local_address: str,
    local_port: int,
    remote_address: str,
    remote_port: int,
) -> bool:
    return (
        packet.source == local_address
        and packet.source_port == local_port
        and packet.destination == remote_address
        and packet.destination_port == remote_port
    ) or (
        packet.source == remote_address
        and packet.source_port == remote_port
        and packet.destination == local_address
        and packet.destination_port == local_port
    )


def _token_offsets(data: bytes, token: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0
    while True:
        found = data.find(token, start)
        if found < 0:
            return offsets
        offsets.append(found)
        start = found + 1


def _tcp_token_windows(
    packets: Iterable[TransportPacket], token: bytes
) -> list[tuple[Fraction, Fraction]]:
    flows: dict[tuple[str, str, int, int], list[TransportPacket]] = {}
    for packet in packets:
        key = (packet.source, packet.destination, packet.source_port, packet.destination_port)
        flows.setdefault(key, []).append(packet)
    occurrences: list[tuple[Fraction, Fraction]] = []
    for segments in flows.values():
        nonempty = [segment for segment in segments if segment.payload]
        if not nonempty:
            continue
        ordered = sorted(nonempty, key=lambda item: (item.sequence or 0, item.timestamp))
        base = ordered[0].sequence
        if base is None:
            raise PacketCaptureError("TCP sequence is absent")
        stream = bytearray()
        timestamps: list[Fraction] = []
        cursor = base
        for segment in ordered:
            sequence = segment.sequence
            if sequence is None:  # pragma: no cover - TransportPacket construction invariant
                raise PacketCaptureError("TCP sequence is absent")
            if sequence > cursor:
                raise PacketCaptureError("TCP evidence has a reassembly gap")
            overlap = max(0, cursor - sequence)
            if overlap:
                existing_start = sequence - base
                existing_end = existing_start + min(overlap, len(segment.payload))
                if bytes(stream[existing_start:existing_end]) != segment.payload[: existing_end - existing_start]:
                    raise PacketCaptureError("TCP evidence has conflicting overlap bytes")
            suffix = segment.payload[overlap:]
            if len(stream) + len(suffix) > MAX_REASSEMBLED_FLOW_BYTES:
                raise PacketCaptureError("TCP reassembled flow exceeds the bound")
            stream.extend(suffix)
            timestamps.extend([segment.timestamp] * len(suffix))
            cursor = max(cursor, sequence + len(segment.payload))
        occurrences.extend(
            (timestamps[offset], timestamps[offset + len(token) - 1])
            for offset in _token_offsets(bytes(stream), token)
        )
    return occurrences


def _tcp_token_times(packets: Iterable[TransportPacket], token: bytes) -> list[Fraction]:
    return [started_at for started_at, _ended_at in _tcp_token_windows(packets, token)]


def _dns_name(data: bytes, offset: int, *, depth: int = 0) -> tuple[str, int]:
    if depth > 8:
        raise PacketCaptureError("DNS compression depth exceeds the bound")
    labels: list[str] = []
    next_offset: int | None = None
    seen: set[int] = set()
    while True:
        if offset >= len(data) or offset in seen:
            raise PacketCaptureError("DNS name is truncated or cyclic")
        seen.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            return ".".join(labels), next_offset if next_offset is not None else offset
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise PacketCaptureError("DNS compression pointer is truncated")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, _ = _dns_name(data, pointer, depth=depth + 1)
            labels.extend(suffix.split(".") if suffix else [])
            return ".".join(labels), next_offset if next_offset is not None else offset + 2
        if length > 63 or offset + 1 + length > len(data):
            raise PacketCaptureError("DNS label is malformed")
        try:
            label = data[offset + 1 : offset + 1 + length].decode("ascii")
        except UnicodeDecodeError as error:
            raise PacketCaptureError("DNS label is not ASCII") from error
        if not label or len(labels) >= 32:
            raise PacketCaptureError("DNS name exceeds the accepted bounds")
        labels.append(label.lower())
        offset += 1 + length


def _dns_message(data: bytes, family: str) -> DnsMessage:
    if len(data) < 12:
        raise PacketCaptureError("DNS header is truncated")
    identifier, flags, questions, answers, authority, additional = struct.unpack_from(
        "!HHHHHH", data, 0
    )
    expected_type = 1 if family == "ipv4" else 28
    offset = 12
    question_name, offset = _dns_name(data, offset)
    if offset + 4 > len(data):
        raise PacketCaptureError("DNS question is truncated")
    question_type, question_class = struct.unpack_from("!HH", data, offset)
    offset += 4
    if question_type != expected_type or question_class != 1:
        raise PacketCaptureError(
            "DNS message does not contain the required A/AAAA question"
        )
    if flags == 0x0000 and (questions, answers, authority, additional) == (1, 0, 0, 0):
        if offset != len(data):
            raise PacketCaptureError("DNS query has trailing records or bytes")
        return DnsMessage(identifier, False, question_name, question_type, None)
    if flags != 0x8400 or (questions, answers, authority, additional) != (1, 1, 0, 0):
        raise PacketCaptureError("DNS response is not exact authoritative non-recursive data")
    answer_name, offset = _dns_name(data, offset)
    if offset + 10 > len(data):
        raise PacketCaptureError("DNS answer header is truncated")
    record_type, record_class, ttl, length = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    expected_length = 4 if family == "ipv4" else 16
    if (
        answer_name != question_name
        or record_type != expected_type
        or record_class != 1
        or ttl != DNS_TTL
        or length != expected_length
        or offset + length != len(data)
    ):
        raise PacketCaptureError("DNS answer owner/type/class/TTL/length differs")
    try:
        answer_address = str(ipaddress.ip_address(data[offset : offset + length]))
    except ValueError as error:  # pragma: no cover - exact lengths are guarded above
        raise PacketCaptureError("DNS answer address is invalid") from error
    expected_answer = DNS_A_ADDRESS if family == "ipv4" else DNS_AAAA_ADDRESS
    if answer_address != expected_answer:
        raise PacketCaptureError("DNS answer address differs from the fixed contract")
    return DnsMessage(identifier, True, question_name, question_type, answer_address)


def _dns_response_for_token(
    packets: list[TransportPacket], family: str, token: bytes
) -> tuple[Fraction, Fraction, bytes]:
    expected_name = f"{token.decode('ascii').lower()}.evidence.test"
    queries: list[tuple[TransportPacket, DnsMessage]] = []
    responses: list[tuple[TransportPacket, DnsMessage]] = []
    for packet in packets:
        if packet.family != family or packet.protocol != "udp":
            continue
        message = _dns_message(packet.payload, family)
        if message.question_name != expected_name:
            continue
        if message.is_response:
            if packet.source_port != 53:
                raise PacketCaptureError("DNS response direction/port is invalid")
            responses.append((packet, message))
        else:
            if packet.destination_port != 53:
                raise PacketCaptureError("DNS query direction/port is invalid")
            queries.append((packet, message))
    if len(queries) != 1 or len(responses) != 1:
        raise PacketCaptureError(
            "DNS token must have exactly one query and one authoritative response"
        )
    query_packet, query = queries[0]
    response_packet, response = responses[0]
    if (
        query.identifier != response.identifier
        or query.question_type != response.question_type
        or response.answer_address is None
        or response_packet.timestamp <= query_packet.timestamp
    ):
        raise PacketCaptureError("DNS query/response transaction is not causal and exact")
    return query_packet.timestamp, response_packet.timestamp, response_packet.payload


def _quic_connection_ids(data: bytes) -> tuple[int, bytes, bytes]:
    if len(data) < 7 or not data[0] & 0x40 or not data[0] & 0x80:
        raise PacketCaptureError("QUIC packet lacks a long-header fixed-bit contract")
    version = int.from_bytes(data[1:5], "big")
    if version == 0:
        raise PacketCaptureError("QUIC version-negotiation packets are not proof")
    dcid_length = data[5]
    if not 1 <= dcid_length <= 20 or 6 + dcid_length >= len(data):
        raise PacketCaptureError("QUIC destination connection ID length is invalid")
    dcid = data[6 : 6 + dcid_length]
    scid_length_offset = 6 + dcid_length
    scid_length = data[scid_length_offset]
    scid_start = scid_length_offset + 1
    if not 1 <= scid_length <= 20 or scid_start + scid_length > len(data):
        raise PacketCaptureError("QUIC source connection ID length is invalid")
    return version, dcid, data[scid_start : scid_start + scid_length]


def _events_for_token(
    packets: list[TransportPacket], protocol: str, family: str, token: bytes
) -> list[Fraction]:
    matching = [packet for packet in packets if packet.family == family]
    if protocol == "tcp":
        return _tcp_token_times(
            (packet for packet in matching if packet.protocol == "tcp"), token
        )
    if protocol == "udp":
        return [
            packet.timestamp
            for packet in matching
            if packet.protocol == "udp" and token in packet.payload
        ]
    if protocol == "dns":
        _query_at, response_at, _response = _dns_response_for_token(
            matching, family, token
        )
        return [response_at]
    if protocol == "quic":
        result = []
        for packet in matching:
            if packet.protocol != "udp":
                continue
            _version, dcid, scid = _quic_connection_ids(packet.payload)
            if token in dcid or token in scid:
                result.append(packet.timestamp)
        return result
    raise PacketCaptureError(f"unsupported evidence protocol: {protocol!r}")


def _event_windows_for_token(
    packets: list[TransportPacket], protocol: str, family: str, token: bytes
) -> list[tuple[Fraction, Fraction]]:
    matching = [packet for packet in packets if packet.family == family]
    if protocol == "tcp":
        return _tcp_token_windows(
            (packet for packet in matching if packet.protocol == "tcp"), token
        )
    if protocol == "udp":
        return [
            (packet.timestamp, packet.timestamp)
            for packet in matching
            if packet.protocol == "udp" and token in packet.payload
        ]
    if protocol == "dns":
        query_at, response_at, _response = _dns_response_for_token(
            matching, family, token
        )
        return [(query_at, response_at)]
    if protocol == "quic":
        result: list[tuple[Fraction, Fraction]] = []
        for packet in matching:
            if packet.protocol != "udp":
                continue
            _version, dcid, scid = _quic_connection_ids(packet.payload)
            if token in dcid or token in scid:
                result.append((packet.timestamp, packet.timestamp))
        return result
    raise PacketCaptureError(f"unsupported evidence protocol: {protocol!r}")


def validate_capture_tokens(
    data: bytes,
    kind: str,
    *,
    protocol: str,
    family: str,
    local_address: str,
    local_port: int,
    remote_address: str,
    remote_port: int,
    expected_link_type: int,
    expected_interface_name: str,
    expected_quic_version: int | None,
    token: bytes,
    start_marker: bytes,
    end_marker: bytes,
    expect_token: bool,
    declared_observation_ms: int,
) -> CaptureProof:
    """Prove a token only in the declared protocol/application-data flow."""

    capture = parse_packet_capture(data, kind)
    if not capture.interfaces or any(
        interface.link_type != expected_link_type for interface in capture.interfaces
    ):
        raise PacketCaptureError("capture link type differs from signed provenance")
    named = {interface.name for interface in capture.interfaces if interface.name is not None}
    if named and named != {expected_interface_name}:
        raise PacketCaptureError("pcapng interface name differs from signed provenance")
    try:
        expected_local_ip = ipaddress.ip_address(local_address)
        expected_remote_ip = ipaddress.ip_address(remote_address)
    except ValueError as error:
        raise PacketCaptureError("capture signed endpoint address is invalid") from error
    expected_version = 4 if family == "ipv4" else 6
    if (
        expected_local_ip.version != expected_version
        or expected_remote_ip.version != expected_version
    ):
        raise PacketCaptureError("capture signed endpoint family differs from the case")
    network = [_decode_network(record) for record in capture.records]
    transports = [_decode_transport(packet) for packet in network]
    selected = [
        packet
        for packet in transports
        if packet.family == family
        and _matches_flow(
            packet,
            local_address=local_address,
            local_port=local_port,
            remote_address=remote_address,
            remote_port=remote_port,
        )
    ]
    if not selected:
        raise PacketCaptureError("capture contains no packets for the signed endpoint tuple")
    if protocol == "quic":
        if expected_quic_version not in SUPPORTED_QUIC_VERSIONS:
            raise PacketCaptureError("signed QUIC version is not an accepted v1/v2 version")
        quic_versions = {
            _quic_connection_ids(packet.payload)[0]
            for packet in selected
            if packet.protocol == "udp"
        }
        if quic_versions != {expected_quic_version}:
            raise PacketCaptureError(
                "captured QUIC version differs from signed v1/v2 provenance"
            )
    elif expected_quic_version is not None:
        raise PacketCaptureError("non-QUIC evidence declares a QUIC version")
    start_windows = _event_windows_for_token(
        selected, protocol, family, start_marker
    )
    end_windows = _event_windows_for_token(selected, protocol, family, end_marker)
    if len(start_windows) != 1 or len(end_windows) != 1:
        raise PacketCaptureError("capture window markers must each occur exactly once")
    start_event_started_at, start_event_ended_at = start_windows[0]
    end_event_started_at, end_event_ended_at = end_windows[0]
    started_at = start_event_ended_at
    ended_at = end_event_ended_at
    if ended_at <= started_at:
        raise PacketCaptureError("capture window end marker does not follow its start marker")
    duration_ms = (ended_at - started_at) * 1000
    observation_ms = duration_ms.numerator // duration_ms.denominator
    if observation_ms < 1_000 or observation_ms > 30_000:
        raise PacketCaptureError("capture observation window is outside 1s..30s")
    if declared_observation_ms != observation_ms:
        raise PacketCaptureError("declared observation_ms differs from capture timestamps")
    window = [packet for packet in selected if started_at <= packet.timestamp <= ended_at]
    target_windows = _event_windows_for_token(window, protocol, family, token)
    occurrences = len(target_windows)
    if expect_token and occurrences < 1:
        raise PacketCaptureError("required unique token is absent from decoded application data")
    if not expect_token and occurrences != 0:
        raise PacketCaptureError("forbidden unique token is present in decoded application data")
    dns_response_count: int | None = None
    dns_answer_type: str | None = None
    dns_answer_address: str | None = None
    dns_ttl: int | None = None
    dns_responses_sha256: str | None = None
    target_started_at = (
        min(started_at for started_at, _ended_at in target_windows)
        if target_windows
        else None
    )
    target_ended_at = (
        max(ended_at for _started_at, ended_at in target_windows)
        if target_windows
        else None
    )
    if protocol == "dns":
        if not expect_token:
            raise PacketCaptureError("DNS evidence requires successful resolution proof")
        responses = [
            _dns_response_for_token(selected, family, evidence_token)[2]
            for evidence_token in (start_marker, token, end_marker)
        ]
        digest = hashlib.sha256(DNS_RESPONSE_DIGEST_DOMAIN)
        for response in responses:
            digest.update(len(response).to_bytes(4, "big"))
            digest.update(response)
        dns_response_count = len(responses)
        dns_answer_type = "A" if family == "ipv4" else "AAAA"
        dns_answer_address = DNS_A_ADDRESS if family == "ipv4" else DNS_AAAA_ADDRESS
        dns_ttl = DNS_TTL
        dns_responses_sha256 = digest.hexdigest()
    if protocol == "quic" and any(
        packet.protocol == "tcp"
        and packet.family == family
        and _matches_flow(
            packet,
            local_address=local_address,
            local_port=local_port,
            remote_address=remote_address,
            remote_port=remote_port,
        )
        and started_at <= packet.timestamp <= ended_at
        for packet in transports
    ):
        raise PacketCaptureError("QUIC evidence contains TCP fallback for the same endpoint/window")
    used_interfaces = {packet.interface_id for packet in window}
    if len(used_interfaces) != 1:
        raise PacketCaptureError("evidence window spans multiple capture interfaces")
    interface = capture.interfaces[next(iter(used_interfaces))]
    return CaptureProof(
        observation_ms=observation_ms,
        started_at=started_at,
        ended_at=ended_at,
        start_event_started_at=start_event_started_at,
        start_event_ended_at=start_event_ended_at,
        target_started_at=target_started_at,
        target_ended_at=target_ended_at,
        end_event_started_at=end_event_started_at,
        end_event_ended_at=end_event_ended_at,
        total_record_count=len(capture.records),
        packet_count=len(window),
        token_occurrences=occurrences,
        link_type=interface.link_type,
        interface_name=interface.name,
        quic_version=expected_quic_version,
        dns_response_count=dns_response_count,
        dns_answer_type=dns_answer_type,
        dns_answer_address=dns_answer_address,
        dns_ttl=dns_ttl,
        dns_responses_sha256=dns_responses_sha256,
    )


def validate_staged_capture_tokens(
    data: bytes,
    kind: str,
    *,
    protocol: str,
    family: str,
    endpoints: tuple[StagedCaptureEndpoint, StagedCaptureEndpoint, StagedCaptureEndpoint],
    expected_link_type: int,
    expected_interface_name: str,
    expected_quic_version: int | None,
    token: bytes,
    start_marker: bytes,
    end_marker: bytes,
    expect_token: bool,
    declared_observation_ms: int,
) -> CaptureProof:
    """Validate a marker window whose three source-owned sends have own tuples.

    The capture remains one immutable independent-vantage artifact.  Only the
    sender tuple may change as the signed Host moves through baseline, test and
    restored state; each token is evaluated against its own exact flow.
    """

    if tuple(endpoint.stage for endpoint in endpoints) != ("start", "target", "end"):
        raise PacketCaptureError("staged capture endpoints are not start/target/end")
    capture = parse_packet_capture(data, kind)
    if not capture.interfaces or any(
        interface.link_type != expected_link_type for interface in capture.interfaces
    ):
        raise PacketCaptureError("capture link type differs from signed provenance")
    named = {interface.name for interface in capture.interfaces if interface.name is not None}
    if named and named != {expected_interface_name}:
        raise PacketCaptureError("pcapng interface name differs from signed provenance")
    expected_version = 4 if family == "ipv4" else 6
    normalized: list[StagedCaptureEndpoint] = []
    for endpoint in endpoints:
        try:
            local = ipaddress.ip_address(endpoint.local_address)
            remote = ipaddress.ip_address(endpoint.remote_address)
        except ValueError as error:
            raise PacketCaptureError("staged capture endpoint address is invalid") from error
        if (
            local.version != expected_version
            or remote.version != expected_version
            or not 1 <= endpoint.local_port <= 65535
            or not 1 <= endpoint.remote_port <= 65535
        ):
            raise PacketCaptureError("staged capture endpoint family/port is invalid")
        normalized.append(
            StagedCaptureEndpoint(
                endpoint.stage,
                str(local),
                endpoint.local_port,
                str(remote),
                endpoint.remote_port,
            )
        )
    network = [_decode_network(record) for record in capture.records]
    transports = [_decode_transport(packet) for packet in network]
    stage_packets: dict[str, list[TransportPacket]] = {}
    for endpoint in normalized:
        stage_packets[endpoint.stage] = [
            packet
            for packet in transports
            if packet.family == family
            and _matches_flow(
                packet,
                local_address=endpoint.local_address,
                local_port=endpoint.local_port,
                remote_address=endpoint.remote_address,
                remote_port=endpoint.remote_port,
            )
        ]
    start_windows = _event_windows_for_token(
        stage_packets["start"], protocol, family, start_marker
    )
    end_windows = _event_windows_for_token(
        stage_packets["end"], protocol, family, end_marker
    )
    if len(start_windows) != 1 or len(end_windows) != 1:
        raise PacketCaptureError("capture window markers must each occur exactly once")
    start_event_started_at, start_event_ended_at = start_windows[0]
    end_event_started_at, end_event_ended_at = end_windows[0]
    started_at = start_event_ended_at
    ended_at = end_event_ended_at
    if ended_at <= started_at:
        raise PacketCaptureError("capture window end marker does not follow its start marker")
    duration_ms = (ended_at - started_at) * 1000
    observation_ms = duration_ms.numerator // duration_ms.denominator
    if not 1_000 <= observation_ms <= 30_000:
        raise PacketCaptureError("capture observation window is outside 1s..30s")
    if declared_observation_ms != observation_ms:
        raise PacketCaptureError("declared observation_ms differs from capture timestamps")
    target_window = [
        packet
        for packet in stage_packets["target"]
        if started_at <= packet.timestamp <= ended_at
    ]
    target_windows = _event_windows_for_token(
        target_window, protocol, family, token
    )
    occurrences = len(target_windows)
    if expect_token and occurrences < 1:
        raise PacketCaptureError("required unique token is absent from decoded application data")
    if not expect_token and occurrences != 0:
        raise PacketCaptureError("forbidden unique token is present from the required vantage")
    selected_window = [
        packet
        for packets in stage_packets.values()
        for packet in packets
        if started_at <= packet.timestamp <= ended_at
    ]
    if not selected_window:
        raise PacketCaptureError("staged capture contains no marker-bounded packets")
    expected_transport = "tcp" if protocol == "tcp" else "udp"
    if any(packet.protocol != expected_transport for packet in selected_window):
        raise PacketCaptureError(
            f"{protocol.upper()} evidence contains a transport fallback"
        )
    if protocol == "quic":
        if expected_quic_version not in SUPPORTED_QUIC_VERSIONS:
            raise PacketCaptureError("signed QUIC version is not an accepted v1/v2 version")
        versions = {
            _quic_connection_ids(packet.payload)[0]
            for packet in selected_window
            if packet.protocol == "udp"
        }
        if versions != {expected_quic_version}:
            raise PacketCaptureError("captured QUIC version differs from signed provenance")
    elif expected_quic_version is not None:
        raise PacketCaptureError("non-QUIC evidence declares a QUIC version")
    dns_response_count: int | None = None
    dns_answer_type: str | None = None
    dns_answer_address: str | None = None
    dns_ttl: int | None = None
    dns_responses_sha256: str | None = None
    target_started_at = (
        min(started_at for started_at, _ended_at in target_windows)
        if target_windows
        else None
    )
    target_ended_at = (
        max(ended_at for _started_at, ended_at in target_windows)
        if target_windows
        else None
    )
    if protocol == "dns":
        if not expect_token:
            raise PacketCaptureError("DNS evidence requires successful resolution proof")
        response_values = []
        for stage, evidence_token in (
            ("start", start_marker),
            ("target", token),
            ("end", end_marker),
        ):
            _query_at, _response_at, response = _dns_response_for_token(
                stage_packets[stage], family, evidence_token
            )
            response_values.append(response)
        digest = hashlib.sha256(DNS_RESPONSE_DIGEST_DOMAIN)
        for response in response_values:
            digest.update(len(response).to_bytes(4, "big"))
            digest.update(response)
        dns_response_count = len(response_values)
        dns_answer_type = "A" if family == "ipv4" else "AAAA"
        dns_answer_address = DNS_A_ADDRESS if family == "ipv4" else DNS_AAAA_ADDRESS
        dns_ttl = DNS_TTL
        dns_responses_sha256 = digest.hexdigest()
    used_interfaces = {packet.interface_id for packet in selected_window}
    if len(used_interfaces) != 1:
        raise PacketCaptureError("evidence window spans multiple capture interfaces")
    interface = capture.interfaces[next(iter(used_interfaces))]
    return CaptureProof(
        observation_ms=observation_ms,
        started_at=started_at,
        ended_at=ended_at,
        start_event_started_at=start_event_started_at,
        start_event_ended_at=start_event_ended_at,
        target_started_at=target_started_at,
        target_ended_at=target_ended_at,
        end_event_started_at=end_event_started_at,
        end_event_ended_at=end_event_ended_at,
        total_record_count=len(capture.records),
        packet_count=len(selected_window),
        token_occurrences=occurrences,
        link_type=interface.link_type,
        interface_name=interface.name,
        quic_version=expected_quic_version,
        dns_response_count=dns_response_count,
        dns_answer_type=dns_answer_type,
        dns_answer_address=dns_answer_address,
        dns_ttl=dns_ttl,
        dns_responses_sha256=dns_responses_sha256,
    )


def dns_stage_endpoints(
    data: bytes,
    kind: str,
    *,
    family: str,
    remote_address: str,
    tokens: tuple[bytes, bytes, bytes],
) -> tuple[StagedCaptureEndpoint, StagedCaptureEndpoint, StagedCaptureEndpoint]:
    """Derive exact client tuples from the independent remote DNS pcap."""

    try:
        remote = str(ipaddress.ip_address(remote_address))
    except ValueError as error:
        raise PacketCaptureError("remote DNS endpoint address is invalid") from error
    expected_version = 4 if family == "ipv4" else 6
    if ipaddress.ip_address(remote).version != expected_version:
        raise PacketCaptureError("remote DNS endpoint family differs")
    parsed = parse_packet_capture(data, kind)
    transports = [
        _decode_transport(_decode_network(record)) for record in parsed.records
    ]
    endpoints: list[StagedCaptureEndpoint] = []
    for stage, token in zip(("start", "target", "end"), tokens, strict=True):
        expected_name = f"{token.decode('ascii')}.evidence.test"
        matches: list[TransportPacket] = []
        for packet in transports:
            if (
                packet.family != family
                or packet.protocol != "udp"
                or packet.destination != remote
                or packet.destination_port != 53
            ):
                continue
            try:
                message = _dns_message(packet.payload, family)
            except PacketCaptureError:
                continue
            if not message.is_response and message.question_name == expected_name:
                matches.append(packet)
        if len(matches) != 1:
            raise PacketCaptureError(
                f"remote DNS pcap does not contain one exact {stage} query"
            )
        packet = matches[0]
        endpoints.append(
            StagedCaptureEndpoint(
                stage=stage,
                local_address=packet.source,
                local_port=packet.source_port,
                remote_address=packet.destination,
                remote_port=packet.destination_port,
            )
        )
    return endpoints[0], endpoints[1], endpoints[2]


def staged_marker_window(
    data: bytes,
    kind: str,
    *,
    protocol: str,
    family: str,
    endpoints: tuple[StagedCaptureEndpoint, StagedCaptureEndpoint, StagedCaptureEndpoint],
    start_marker: bytes,
    end_marker: bytes,
) -> tuple[Fraction, Fraction]:
    """Return the exact unique marker timestamps for producer provenance."""

    if tuple(endpoint.stage for endpoint in endpoints) != ("start", "target", "end"):
        raise PacketCaptureError("staged marker endpoints are not ordered")
    capture = parse_packet_capture(data, kind)
    transports = [_decode_transport(_decode_network(record)) for record in capture.records]

    def selected(endpoint: StagedCaptureEndpoint) -> list[TransportPacket]:
        return [
            packet
            for packet in transports
            if packet.family == family
            and _matches_flow(
                packet,
                local_address=endpoint.local_address,
                local_port=endpoint.local_port,
                remote_address=endpoint.remote_address,
                remote_port=endpoint.remote_port,
            )
        ]

    starts = _events_for_token(selected(endpoints[0]), protocol, family, start_marker)
    ends = _events_for_token(selected(endpoints[2]), protocol, family, end_marker)
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
        raise PacketCaptureError("staged capture markers are absent, repeated, or reversed")
    return starts[0], ends[0]


def timestamp_fraction(value: str) -> Fraction:
    """Convert a strict UTC ISO-8601 timestamp to exact Unix-epoch seconds."""

    if not isinstance(value, str) or not value.endswith("Z"):
        raise PacketCaptureError("capture timestamp must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PacketCaptureError("capture timestamp is not ISO-8601") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PacketCaptureError("capture timestamp must use UTC")
    seconds = calendar.timegm(parsed.utctimetuple())
    return Fraction(seconds, 1) + Fraction(parsed.microsecond, 1_000_000)
