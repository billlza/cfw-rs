"""Bounded pcap/pcapng packet-record parsing for unique-token evidence."""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
import struct
from typing import Iterable


MAX_CAPTURE_PACKETS = 100_000
MAX_CAPTURE_BLOCKS = 200_000
MAX_SNAPLEN = 262_144
MAX_PACKET_BYTES = 262_144
ALLOWED_LINK_TYPES = frozenset({0, 1, 101, 108, 113, 276})


class PacketCaptureError(ValueError):
    """A capture is structurally malformed or does not prove its token window."""


@dataclass(frozen=True)
class PacketRecord:
    timestamp: Fraction
    payload: bytes


@dataclass(frozen=True)
class CaptureProof:
    observation_ms: int
    started_at: Fraction
    ended_at: Fraction
    packet_count: int
    token_occurrences: int


def _records_pcap(data: bytes) -> list[PacketRecord]:
    if len(data) < 24:
        raise PacketCaptureError("pcap global header is truncated")
    magic = data[:4]
    formats: dict[bytes, tuple[str, int]] = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        raise PacketCaptureError("pcap magic is unsupported")
    endian, subsecond_scale = formats[magic]
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
            )
        )
        offset = end
    if offset != len(data) or not records:
        raise PacketCaptureError("pcap contains no complete packet records")
    return records


def _parse_options(data: bytes, endian: str, *, allow_tsresol: bool) -> Fraction:
    offset = 0
    option_count = 0
    resolution = Fraction(1, 1_000_000)
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
        if code == 9:
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
    return resolution


def _records_pcapng(data: bytes) -> list[PacketRecord]:
    if len(data) < 28 or data[:4] != b"\x0a\x0d\x0d\x0a":
        raise PacketCaptureError("pcapng must start with a section header block")
    records: list[PacketRecord] = []
    interfaces: list[tuple[int, Fraction]] = []
    offset = 0
    endian: str | None = None
    block_count = 0
    while offset < len(data):
        block_count += 1
        if block_count > MAX_CAPTURE_BLOCKS:
            raise PacketCaptureError("pcapng block count exceeds the bound")
        if len(data) - offset < 12:
            raise PacketCaptureError("pcapng block header is truncated")
        raw_type = data[offset : offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            if len(data) - offset < 28:
                raise PacketCaptureError("pcapng section header is truncated")
            byte_order_magic = data[offset + 8 : offset + 12]
            if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PacketCaptureError("pcapng section byte-order magic is invalid")
        if endian is None:
            raise PacketCaptureError("pcapng block appears outside a section")
        block_type, block_length = struct.unpack_from(f"{endian}II", data, offset)
        if block_length < 12 or block_length % 4 != 0:
            raise PacketCaptureError("pcapng block length is invalid")
        end = offset + block_length
        if end > len(data):
            raise PacketCaptureError("pcapng block is truncated")
        trailing_length = struct.unpack_from(f"{endian}I", data, end - 4)[0]
        if trailing_length != block_length:
            raise PacketCaptureError("pcapng block length trailer differs")
        body = data[offset + 8 : end - 4]

        if block_type == 0x0A0D0D0A:
            if block_length < 28:
                raise PacketCaptureError("pcapng section header length is invalid")
            major, minor = struct.unpack_from(f"{endian}HH", body, 4)
            if (major, minor) != (1, 0):
                raise PacketCaptureError("pcapng section version is not 1.0")
            interfaces = []
            if len(body) > 16:
                _parse_options(body[16:], endian, allow_tsresol=False)
        elif block_type == 1:
            if len(body) < 8:
                raise PacketCaptureError("pcapng interface description is truncated")
            link_type, reserved, snaplen = struct.unpack_from(f"{endian}HHI", body, 0)
            if reserved != 0 or link_type not in ALLOWED_LINK_TYPES:
                raise PacketCaptureError("pcapng interface link metadata is invalid")
            if snaplen < 1 or snaplen > MAX_SNAPLEN:
                raise PacketCaptureError("pcapng interface snaplen is outside the bound")
            resolution = _parse_options(body[8:], endian, allow_tsresol=True)
            interfaces.append((snaplen, resolution))
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
            snaplen, resolution = interfaces[interface_id]
            if captured < 1 or captured > snaplen or captured > MAX_PACKET_BYTES:
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
                _parse_options(body[20 + padded :], endian, allow_tsresol=False)
            timestamp = (timestamp_high << 32) | timestamp_low
            records.append(PacketRecord(timestamp=timestamp * resolution, payload=payload))
        elif block_type in {2, 3}:
            # Obsolete/simple packet blocks do not carry the timestamp required
            # for a bounded absence window.
            raise PacketCaptureError("pcapng packet block lacks an accepted timestamp contract")
        offset = end
    if offset != len(data) or not records:
        raise PacketCaptureError("pcapng contains no enhanced packet records")
    return records


def parse_packet_records(data: bytes, kind: str) -> list[PacketRecord]:
    """Return only captured packet-record payloads and their capture timestamps."""

    if kind == "packet-pcap":
        return _records_pcap(data)
    if kind == "packet-pcapng":
        return _records_pcapng(data)
    raise PacketCaptureError(f"unsupported capture kind: {kind!r}")


def _token_timestamps(records: Iterable[PacketRecord], token: bytes) -> list[Fraction]:
    return [record.timestamp for record in records if token in record.payload]


def validate_capture_tokens(
    data: bytes,
    kind: str,
    *,
    token: bytes,
    start_marker: bytes,
    end_marker: bytes,
    expect_token: bool,
    declared_observation_ms: int,
) -> CaptureProof:
    """Recompute token presence/absence inside a marker-bounded packet window."""

    records = parse_packet_records(data, kind)
    starts = _token_timestamps(records, start_marker)
    ends = _token_timestamps(records, end_marker)
    if not starts or not ends:
        raise PacketCaptureError("capture window boundary marker is absent from packet payloads")
    started_at = min(starts)
    ended_at = max(ends)
    if ended_at <= started_at:
        raise PacketCaptureError("capture window end marker does not follow its start marker")
    duration_ms = (ended_at - started_at) * 1000
    observation_ms = duration_ms.numerator // duration_ms.denominator
    if observation_ms < 1_000 or observation_ms > 600_000:
        raise PacketCaptureError("capture observation window is outside 1s..10min")
    if declared_observation_ms != observation_ms:
        raise PacketCaptureError("declared observation_ms differs from capture timestamps")
    window = [record for record in records if started_at <= record.timestamp <= ended_at]
    if len(window) < 2:
        raise PacketCaptureError("capture window contains fewer than two packet records")
    occurrences = sum(1 for record in window if token in record.payload)
    if expect_token and occurrences < 1:
        raise PacketCaptureError("required unique token is absent from the capture window")
    if not expect_token and occurrences != 0:
        raise PacketCaptureError("forbidden unique token is present in the capture window")
    return CaptureProof(
        observation_ms=observation_ms,
        started_at=started_at,
        ended_at=ended_at,
        packet_count=len(window),
        token_occurrences=occurrences,
    )


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
