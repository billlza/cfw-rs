from __future__ import annotations

import base64
import calendar
from contextlib import contextmanager, nullcontext
import copy
import dataclasses
import hashlib
import io
import ipaddress
import itertools
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from types import MappingProxyType, SimpleNamespace
from typing import Any, Iterator
import unittest
from unittest.mock import MagicMock, call, patch

from scripts import ga_runtime_acceptance as ga_runtime
from scripts.ga_runtime_acceptance import (
    ACCEPTANCE_RELATIVE,
    CHECKS,
    CHECK_DOCUMENT,
    COLLECTION_RELATIVE,
    COLLECTION_DOCUMENT,
    COLLECTION_EVENT_DOCUMENT,
    COLLECTION_INTENT_SCHEMA_VERSION,
    COLLECTION_SUCCESS_STEPS,
    COMMAND_DOCUMENT,
    DOCUMENT,
    DMG_BYTE_PROOF_TIMEOUT_SECONDS,
    ENVIRONMENT_RELATIVE,
    FROM_BUILD,
    GARuntimeAcceptanceError,
    GACollectionRecoveryRequired,
    HIGH_RISK_PROBES,
    INSTALL_JOURNAL_RELATIVE,
    OFF_PROOF_COMMAND,
    PCAP_FILES,
    PROCESS_OBSERVATION_COMMAND,
    ProductionCollectorRuntime,
    PRODUCT_VERSION,
    RAW_FILE_NAMES,
    RAW_ROOT_RELATIVE,
    SCHEMA_VERSION,
    SECRET_POLICY,
    TO_BUILD,
    TRAFFIC_CHECKS,
    TRAFFIC_POLICY,
    _confirm_snapshot,
    _arguments,
    _derive_capture_token,
    _fixed_paths,
    collect_ga_runtime_acceptance,
    recover_ga_runtime_collection,
    seal_ga_runtime_acceptance,
    self_check,
    validate_ga_runtime_acceptance,
)
from scripts.ga_acceptance_environment import (
    DOCUMENT as GA_ENVIRONMENT_DOCUMENT,
    SCHEMA_VERSION as GA_ENVIRONMENT_SCHEMA_VERSION,
    environment_sha256,
)
from scripts.harness.packet_capture import (
    DnsResolverLeg,
    PacketCaptureError,
    RetransmissionPolicy,
)
from scripts.harness.packet_evidence import (
    TUNNEL_CAPTURE_LOCAL_ADDRESSES,
    packet_capture_filter_argv,
)
from scripts.physical_capture.packet_host import (
    PacketCaptureDisposition,
    PacketHostError,
    PacketHostReceipt,
    PacketHostSnapshot,
)
from scripts.publication import common, durable_file
from scripts.publication.common import PublicationError, canonical_json, sha256_bytes
from scripts.publication.durable_file import DurabilityOutcomeUnknown
from scripts import dormant_app_install
from scripts.dormant_app_install import ACTIVE_PREDECESSOR
from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY
from scripts.tests import test_ga_acceptance_journal_export as journal_fixture
from scripts.tests.release_identity_fixture import NEXT_GA_BUILD
from scripts.tests.physical_evidence_fixture import pcap_bytes


DIGESTS = {
    "dmg_gatekeeper_sha256": "1" * 64,
    "dmg_set_seal_sha256": "2" * 64,
    "dmg_sha256": "3" * 64,
    "install_journal_sha256": "4" * 64,
    "service_journal_tree_sha256": "5" * 64,
}
RAW_MACHINE_UUID = "01234567-89AB-CDEF-0123-456789ABCDEF"
RAW_BOOT_UUID = "89ABCDEF-0123-4567-89AB-CDEF01234567"
GA_ENVIRONMENT = {
    "architecture": "arm64",
    "boot_environment_sha256": hashlib.sha256(RAW_BOOT_UUID.encode("ascii")).hexdigest(),
    "document": GA_ENVIRONMENT_DOCUMENT,
    "hardware_model": "Mac16,1",
    "machine_sha256": hashlib.sha256(RAW_MACHINE_UUID.encode("ascii")).hexdigest(),
    "macos_build_version": "26A5388g",
    "macos_product_version": "27.0",
    "physical_nonvirtualized": True,
    "schema_version": GA_ENVIRONMENT_SCHEMA_VERSION,
}
GA_ENVIRONMENT_SHA256 = environment_sha256(GA_ENVIRONMENT)
APP_TREE = "6" * 64
SESSION_ID = "12345678-1234-4234-8234-123456789abc"
CHALLENGE = base64.urlsafe_b64encode(b"C" * 32).decode("ascii").rstrip("=")
REPOSITORY = Path(__file__).resolve().parent.parent.parent
# The collection intent's record of the checkout and Python that collected:
# this test checkout and the interpreter running the tests.
COLLECTOR = {
    "operator_root": str(REPOSITORY),
    "python": {"executable": sys.executable, "version": platform.python_version()},
}
# Another checkout and Python than the ones verifying, as after an operator
# update or a release Python pin bump between collection and sealing.
OTHER_COLLECTOR = {
    "operator_root": "/Volumes/Release/collected-operator",
    "python": {
        "executable": (
            "/opt/homebrew/Cellar/python@3.14/3.14.0/Frameworks/"
            "Python.framework/Versions/3.14/bin/python3.14"
        ),
        "version": "3.14.0",
    },
}
STEP_EVENTS = [
    (phase, step)
    for step in COLLECTION_SUCCESS_STEPS
    for phase in ("started", "completed")
]
RAW_PUBLISHED_EVENT = ("raw_published", "collection")
ABORTED_EVENT = ("aborted_before_mutation", "collection")
RECOVERY_REQUIRED_EVENT = ("recovery_required", "collection")
# recover's marker for an attempt it archives without runtime work, and the
# one it records after the full runtime cleanup.
ARCHIVED_BEFORE_MUTATION_EVENT = ("recovered", "collection")
RUNTIME_CLEANUP_EVENT = ("recovered", "runtime-cleanup")
FULL_RECOVERY_EVENTS = [
    (phase, step)
    for step in (
        "runtime-recovery-host-process-observation",
        "runtime-recovery-off-proof",
        "runtime-recovery-process-observation",
    )
    for phase in ("started", "completed")
] + [RUNTIME_CLEANUP_EVENT]
SEAL_RETRY_COMMAND = "scripts/run_ga_runtime_acceptance.sh resume-seal"
RECOVERY_COMMAND = "scripts/run_ga_runtime_acceptance.sh recover"
PRE_MUTATION_ABORT_GUIDANCE = (
    "GA runtime collection stopped before it launched the Host; run "
    f"{RECOVERY_COMMAND} to archive this attempt, then collect again"
)
# Only the product's own quit controls run its graceful shutdown, so the
# collector asks the operator for one and sends the Host no quit request. The
# app's own Settings Force Quit is graceful; the macOS Force Quit window is not.
OPERATOR_QUIT_INSTRUCTION = (
    f"GA runtime collection is waiting for you to quit the installed {TO_BUILD} Clash "
    "for Mac with Quit Clash for Mac (⌘Q) in its app menu or Quit in its menu "
    "bar menu; do not quit it from the Dock, AppleScript or Activity Monitor, "
    "or with the macOS Force Quit window (Option-Command-Esc)"
)
OPERATOR_QUIT_REQUEST = {
    "instruction": OPERATOR_QUIT_INSTRUCTION,
    "kind": "operator_quit_instruction",
}
RECOVERY_OFF_PROOF_GUIDANCE = (
    "the installed Host may have exited without its graceful shutdown and left "
    "its runtime on: open Clash for Mac so its startup reconciliation stops the "
    "orphaned runtime, confirm its dashboard shows TUN Mode and System Proxy "
    "off (it may show Off or a stopped failure state; do not retry them), quit "
    "it with Quit Clash for Mac (⌘Q) in its app menu, then rerun "
    f"{RECOVERY_COMMAND}; if the Off proof still fails after that, stop and "
    "investigate instead of repeating these steps"
)
RECOVERY_OPERATOR_QUIT_GUIDANCE = (
    "recovery did not observe the installed Host exit: if it is still running, "
    "quit it with Quit Clash for Mac (⌘Q) in its app menu, then rerun "
    f"{RECOVERY_COMMAND}; if it does not exit after ⌘Q, stop and investigate "
    "instead of quitting it any other way"
)
# collect's pre-flight refusals: its baseline is the network without Clash for
# Mac, which neither a running Host nor a connected VPN leaves.
HOST_PREFLIGHT_REFUSAL = (
    "GA runtime collection needs every Clash for Mac Host quit before it starts; "
    "quit it with Quit Clash for Mac (⌘Q) in its app menu"
)
VPN_PREFLIGHT_REFUSAL = (
    "GA runtime collection needs every Clash for Mac VPN disconnected before it "
    f"starts; turn TUN Mode off in the installed {TO_BUILD} dashboard, then quit "
    "it with Quit Clash for Mac (⌘Q) in its app menu"
)


def loopback_proxy_refusal(found: list[str]) -> str:
    """collect's pre-flight refusal of each enabled loopback system proxy.

    An orphaned Clash for Mac System Proxy or another local proxy tool would
    otherwise fail the collection only at its end, once the product restores
    the system proxy.
    """

    return (
        "GA runtime collection needs no HTTP, HTTPS or SOCKS system proxy on a "
        f"loopback host before it starts ({'; '.join(found)}); open the installed "
        f"{TO_BUILD} Clash for Mac, turn System Proxy off in its dashboard and "
        "approve the macOS prompt, then quit it with Quit Clash for Mac (⌘Q) in "
        "its app menu, or quit the other proxy tool"
    )
# Only a refusal before any collection state says to rerun collect; a later
# one is an aborted attempt, which recover archives first.
PREFLIGHT_RETRY_GUIDANCE = (
    "GA runtime collection recorded nothing for this attempt; rerun collect once "
    "that is done"
)
PREFLIGHT_VPN_ID = "97543966-32A2-4199-B43A-2F18E9C69F84"
# The retired shutdown request. Its quit AppleEvent bypasses the product's
# graceful shutdown and leaves the Packet Tunnel connected.
LEGACY_APPLE_EVENT_QUIT = (
    "/usr/bin/osascript",
    "-e",
    'tell application id "com.bill.clashformac" to quit',
)

# The product DNS legs on the Packet Tunnel utun: the system resolver at a
# tunnel client address queries the tunnel DNS peer of the same family, and
# libbox relays the evidence resolver's authoritative answer with the client's
# RD bit echoed. macOS orders the IPv6 peer first, so getaddrinfo's A query was
# observed on the IPv6 leg; any stage may use either leg.
TUNNEL_CLIENT = "198.18.64.1"
TUNNEL_DNS_PEER = "198.18.64.2"
TUNNEL_CLIENT_IPV6 = "2001:2:0:64::1"
TUNNEL_DNS_PEER_IPV6 = "2001:2:0:64::2"
IPV4_DNS_LEG = (TUNNEL_CLIENT, TUNNEL_DNS_PEER)
IPV6_DNS_LEG = (TUNNEL_CLIENT_IPV6, TUNNEL_DNS_PEER_IPV6)
DNS_LEGS = {"ipv4": IPV4_DNS_LEG, "ipv6": IPV6_DNS_LEG}
# tcpdump on the release Mac's utun: "link-type RAW (Raw IP)".
UTUN_LINK_TYPE = 101
# tcpdump -w writes the snapshot length it captures with into the pcap
# header. Without -s (or with -s 0) it captured the release Mac's Packet
# Tunnel utun at "snapshot length 524288 bytes", above packet_capture's
# MAX_SNAPLEN; the GA capture argv fixes it at 262144.
UTUN_DEFAULT_SNAPLEN = 524288
UTUN_CAPTURE_SNAPLEN = 262144
UTUN_EPOCH = calendar.timegm((2026, 7, 27, 12, 0, 0))
# Seconds after UTUN_EPOCH of each stage's query and response. Each pair sits
# inside that stage's sender receipt in RuntimeFixture._traffic.
DNS_TRANSACTION_TIMES = {
    "start": (0.00, 0.31),
    "target": (1.00, 1.29),
    "end": (5.00, 5.27),
}
DNS_OBSERVATION_MS = 4960
DNS_CLIENT_PORTS = {"start": 53001, "target": 53002, "end": 53003}
DNS_QUERY_IDS = {"start": 0x5A01, "target": 0x5A02, "end": 0x5A03}
DNS_STAGES = ("start", "target", "end")
OBSERVED_DNS_FAMILIES = {stage: "ipv6" for stage in DNS_STAGES}
UtunPacket = tuple[float, str, int, str, int, bytes]


def _dns_name_bytes(name: str) -> bytes:
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    return labels + b"\0"


def _tunnel_dns_query(
    identifier: int, name: str, *, flags: int = 0x0100, question_type: int = 1
) -> bytes:
    return (
        struct.pack("!HHHHHH", identifier, flags, 1, 0, 0, 0)
        + _dns_name_bytes(name)
        + struct.pack("!HH", question_type, 1)
    )


def _tunnel_dns_response(
    query: bytes,
    *,
    flags: int | None = None,
    answer: str | None = None,
    ttl: int = 0,
) -> bytes:
    """Answer one query as libbox re-packs it: RD echoed, owner uncompressed."""

    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    question = query[12:]
    question_type = struct.unpack_from("!H", question, len(question) - 4)[0]
    if answer is None:
        answer = "192.0.2.1" if question_type == 1 else "2001:db8::1"
    rdata = ipaddress.ip_address(answer).packed
    header_flags = (0x8400 | (query_flags & 0x0100)) if flags is None else flags
    return (
        struct.pack("!HHHHHH", identifier, header_flags, 1, 1, 0, 0)
        + question
        + question[:-4]
        + struct.pack("!HHIH", question_type, 1, ttl, len(rdata))
        + rdata
    )


def _tunnel_dns_packets(
    tokens: dict[str, str],
    *,
    families: dict[str, str] | None = None,
    client: str | None = None,
    resolver: str | None = None,
    target_query_flags: int = 0x0100,
    target_response: dict[str, Any] | None = None,
) -> list[UtunPacket]:
    """Return each stage's query and answer on that stage's tunnel leg.

    families picks each stage's leg (the observed IPv6 leg by default); client
    or resolver replaces that address on every stage's leg.
    """

    stage_families = OBSERVED_DNS_FAMILIES if families is None else families
    packets: list[UtunPacket] = []
    for stage in DNS_STAGES:
        leg_client, leg_resolver = DNS_LEGS[stage_families[stage]]
        stage_client = leg_client if client is None else client
        stage_resolver = leg_resolver if resolver is None else resolver
        query_at, response_at = DNS_TRANSACTION_TIMES[stage]
        port = DNS_CLIENT_PORTS[stage]
        query = _tunnel_dns_query(
            DNS_QUERY_IDS[stage],
            f"{tokens[stage]}.evidence.test",
            flags=target_query_flags if stage == "target" else 0x0100,
        )
        response = _tunnel_dns_response(
            query, **((target_response or {}) if stage == "target" else {})
        )
        packets.append((query_at, stage_client, port, stage_resolver, 53, query))
        packets.append((response_at, stage_resolver, 53, stage_client, port, response))
    return packets


def _tunnel_dns_transaction(
    token: str,
    family: str,
    *,
    at: float,
    port: int,
    identifier: int,
    question_type: int = 1,
) -> list[UtunPacket]:
    """Return one query for a token on a tunnel leg and its answer 0.1 s later."""

    client, resolver = DNS_LEGS[family]
    query = _tunnel_dns_query(
        identifier, f"{token}.evidence.test", question_type=question_type
    )
    return [
        (at, client, port, resolver, 53, query),
        (at + 0.1, resolver, 53, client, port, _tunnel_dns_response(query)),
    ]


def _utun_udp_pcap(
    packets: list[UtunPacket],
    *,
    link_type: int = UTUN_LINK_TYPE,
    ipv6_hop_by_hop: bool = False,
) -> bytes:
    """Write UDP datagrams as tcpdump does on a utun.

    RAW (101) frames start at the IP header; NULL (0) frames carry the host's
    little-endian AF_INET (2) or AF_INET6 (30) first. Each datagram's family
    follows its addresses. ipv6_hop_by_hop puts an 8-byte Hop-by-Hop Options
    header (PadN only) between each IPv6 header and its UDP header.
    """

    if link_type not in {0, 101}:
        raise ValueError("utun fixture link type is RAW or NULL")
    output = bytearray(
        struct.pack(
            "<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, UTUN_CAPTURE_SNAPLEN, link_type
        )
    )
    ordered = sorted(packets, key=lambda packet: packet[0])
    for index, packet in enumerate(ordered):
        seconds, source, source_port, destination, destination_port, payload = packet
        source_ip = ipaddress.ip_address(source)
        destination_ip = ipaddress.ip_address(destination)
        if source_ip.version != destination_ip.version:
            raise ValueError("utun fixture datagram mixes address families")
        udp = struct.pack(
            "!HHHH", source_port, destination_port, 8 + len(payload), 0
        ) + payload
        if source_ip.version == 4:
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(udp),
                index + 1,
                0x4000,
                64,
                17,
                0,
                source_ip.packed,
                destination_ip.packed,
            ) + udp
            address_family = 2
        else:
            # Next header 17, length 0 (8 bytes), one 4-byte PadN option.
            extension = bytes((17, 0, 1, 4, 0, 0, 0, 0)) if ipv6_hop_by_hop else b""
            ip = struct.pack(
                "!IHBB16s16s",
                6 << 28,
                len(extension) + len(udp),
                0 if ipv6_hop_by_hop else 17,
                64,
                source_ip.packed,
                destination_ip.packed,
            ) + extension + udp
            address_family = 30
        frame = ip if link_type == 101 else address_family.to_bytes(4, "little") + ip
        micros = round(seconds * 1_000_000)
        output += struct.pack(
            "<IIII",
            UTUN_EPOCH + micros // 1_000_000,
            micros % 1_000_000,
            len(frame),
            len(frame),
        )
        output += frame
    return bytes(output)


def _tcpdump_snapshot_length(argv: list[str]) -> int:
    """Return the snapshot length tcpdump captures a utun with for argv."""

    if "-s" not in argv:
        return UTUN_DEFAULT_SNAPLEN
    return int(argv[argv.index("-s") + 1]) or UTUN_DEFAULT_SNAPLEN


def _utun_udp_datagrams(capture: bytes) -> list[tuple[str, int, str, int, bytes]]:
    """Return each record's UDP addresses, ports and payload in capture order.

    It reads the frames _utun_udp_pcap writes: no IP options or IPv6
    extension headers.
    """

    link_type = struct.unpack_from("<I", capture, 20)[0]
    datagrams: list[tuple[str, int, str, int, bytes]] = []
    offset = 24
    while offset < len(capture):
        _seconds, _micros, captured, _original = struct.unpack_from("<IIII", capture, offset)
        offset += 16
        packet = capture[offset + (4 if link_type == 0 else 0) : offset + captured]
        offset += captured
        if packet[0] >> 4 == 4:
            source, destination, udp = packet[12:16], packet[16:20], packet[20:]
        else:
            source, destination, udp = packet[8:24], packet[24:40], packet[40:]
        source_port, destination_port = struct.unpack_from("!HH", udp, 0)
        datagrams.append(
            (
                str(ipaddress.ip_address(source)),
                source_port,
                str(ipaddress.ip_address(destination)),
                destination_port,
                udp[8:],
            )
        )
    return datagrams


def _utun_dns_headers(capture: bytes) -> list[tuple[int, int]]:
    """Return each record's IP version and DNS header flags."""

    return [
        (ipaddress.ip_address(source).version, struct.unpack_from("!H", payload, 2)[0])
        for source, _source_port, _destination, _destination_port, payload
        in _utun_udp_datagrams(capture)
    ]


def _expected_tunnel_dns_filter(tokens: dict[str, str]) -> tuple[str]:
    """Independent oracle for the token-bound tunnel DNS capture filter."""

    def clause(token: str, layer: str, label: int) -> str:
        prefix, digest = token.split("-")
        return (
            f"({layer}[{label}] = {len(token)}"
            f" and {layer}[{label + 1}:4] = 0x{prefix.encode('ascii').hex()}"
            f" and {layer}[{label + 6}:4] = 0x{digest[:4].encode('ascii').hex()}"
            f" and {layer}[{label + 10}:4] = 0x{digest[4:8].encode('ascii').hex()})"
        )

    def leg(client: str, resolver: str) -> str:
        return (
            f"((src host {client} and dst host {resolver} and dst port 53)"
            f" or (src host {resolver} and src port 53 and dst host {client}))"
        )

    ipv4_names = " or ".join(clause(tokens[stage], "udp", 20) for stage in DNS_STAGES)
    ipv6_names = " or ".join(clause(tokens[stage], "ip6", 60) for stage in DNS_STAGES)
    return (
        f"(udp and {leg(*IPV4_DNS_LEG)} and ({ipv4_names}))"
        f" or (ip6 and ip6[6] = 17 and {leg(*IPV6_DNS_LEG)} and ({ipv6_names}))",
    )


def _pcap_records(capture: bytes) -> list[tuple[int, int, bytes]]:
    """Return each classic little-endian pcap record's time and frame."""

    records: list[tuple[int, int, bytes]] = []
    offset = 24
    while offset < len(capture):
        seconds, micros, captured, _original = struct.unpack_from("<IIII", capture, offset)
        offset += 16
        records.append((seconds, micros, capture[offset : offset + captured]))
        offset += captured
    return records


def _pcap_with_records(capture: bytes, records: list[tuple[int, int, bytes]]) -> bytes:
    """Rewrite capture's records in time order under its own file header."""

    ordered = sorted(records, key=lambda record: (record[0], record[1]))
    return capture[:24] + b"".join(
        struct.pack("<IIII", seconds, micros, len(frame), len(frame)) + frame
        for seconds, micros, frame in ordered
    )


def _tcpdump_stderr(capture: bytes, interface: str) -> str:
    """tcpdump's stderr through sudo when the collector stops it after capture.

    sudo's prompt precedes tcpdump's readiness line; tcpdump prints its
    statistics as it stops, as the physical capture receipts record them.
    """

    link_types = {0: "NULL (BSD loopback)", 1: "EN10MB (Ethernet)", 101: "RAW (Raw IP)"}
    count = len(_pcap_records(capture))
    link_type = link_types[struct.unpack_from("<I", capture, 20)[0]]
    return (
        f"CFM capture authorization: tcpdump: listening on {interface}, link-type "
        f"{link_type}, snapshot length {UTUN_CAPTURE_SNAPLEN} bytes\n"
        f"{count} packets captured\n{count} packets received by filter\n"
        "0 packets dropped by kernel\n"
    )


def _tunnel_dns_retransmission(
    packets: list[UtunPacket], index: int, at: float, **replacements: Any
) -> UtunPacket:
    """Copy packets[index] at another time, with any field replaced.

    Fields are those of UtunPacket: source, source_port, destination,
    destination_port and payload.
    """

    _at, source, source_port, destination, destination_port, payload = packets[index]
    fields = {
        "source": source,
        "source_port": source_port,
        "destination": destination,
        "destination_port": destination_port,
        "payload": payload,
        **replacements,
    }
    return (
        at,
        fields["source"],
        fields["source_port"],
        fields["destination"],
        fields["destination_port"],
        fields["payload"],
    )


def capture_process_argv(sudo: int) -> list[str]:
    """The observation of the process group that a capture's sudo leads.

    Its columns are pinned here, not read from the collector, because the
    fakes print rows in this order.
    """

    return ["/bin/ps", "-x", "-g", str(sudo), "-o", "pid=,ppid=,ruid=,uid=,svuid=,state=,ucomm="]

# A real child process that stands in for sudo and tcpdump: it reads the
# credential the collector writes, writes the first argv[3] bytes of argv[1] as
# its pcap before it reports readiness, then waits for the collector's SIGINT.
# As tcpdump flushes what it still holds when it stops, it then writes the
# rest and prints the statistics for argv[2] packets before it exits 0. It
# first restores SIGINT's default action: a test run that ignores SIGINT, as
# `trap '' INT` or a background job does, passes that on, and the kernel
# discards an ignored signal instead of leaving it pending for sigwait.
FAKE_TCPDUMP = (
    "import os, signal, sys\n"
    "signal.signal(signal.SIGINT, signal.SIG_DFL)\n"
    "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})\n"
    "sys.stdin.buffer.read()\n"
    "with open(sys.argv[1], 'rb') as source:\n"
    "    data = memoryview(source.read())\n"
    "def write(pending):\n"
    "    while pending:\n"
    "        pending = pending[os.write(1, pending):]\n"
    "split = int(sys.argv[3])\n"
    "write(data[:split])\n"
    "os.write(2, b'tcpdump: listening on utun6, link-type RAW (Raw IP), "
    "snapshot length 262144 bytes\\n')\n"
    "signal.sigwait({signal.SIGINT})\n"
    "write(data[split:])\n"
    "count = int(sys.argv[2])\n"
    "os.write(2, b'%d packets captured\\n%d packets received by filter\\n"
    "0 packets dropped by kernel\\n' % (count, count))\n"
)


def prepackage_stage_verifier(_repository: Path) -> dict[str, object]:
    return {}


def command(
    argv: list[str],
    *,
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    started_at: str = "2026-07-27T11:59:59Z",
    finished_at: str = "2026-07-27T12:00:06Z",
) -> dict[str, object]:
    return {
        "argv": argv,
        "document": COMMAND_DOCUMENT,
        "exit_code": exit_code,
        "finished_at": finished_at,
        "schema_version": SCHEMA_VERSION,
        "started_at": started_at,
        "stderr": stderr,
        "stdout": stdout,
    }


def check(check_id: str, **fields: object) -> dict[str, object]:
    return {
        "check_id": check_id,
        "collection": {
            "challenge": CHALLENGE,
            "ga_environment_sha256": GA_ENVIRONMENT_SHA256,
            "session_id": SESSION_ID,
        },
        "document": CHECK_DOCUMENT,
        "schema_version": SCHEMA_VERSION,
        **fields,
    }


def collection_event(index: int, phase: str, step: str) -> bytes:
    return canonical_json(
        {
            "collection": {
                "challenge": CHALLENGE,
                "ga_environment_sha256": GA_ENVIRONMENT_SHA256,
                "session_id": SESSION_ID,
            },
            "command_sha256": None,
            "document": COLLECTION_EVENT_DOCUMENT,
            "phase": phase,
            "schema_version": SCHEMA_VERSION,
            "sequence": index,
            "step": step,
        }
    )


def collection_events(repository: Path) -> list[tuple[str, str]]:
    root = repository.joinpath(*COLLECTION_RELATIVE.parts)
    documents = (
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(root.glob("event-*.json"))
    )
    return [(document["phase"], document["step"]) for document in documents]


class _SimulatedTermination(BaseException):
    """Ends a write like ^C or a forced kill: no ``except Exception`` runs."""


@contextmanager
def interrupted_write(payload_marker: bytes, final: Path) -> Iterator[list[bool]]:
    """Write half of the first payload holding ``payload_marker``, then stop.

    The yielded list records whether ``final`` existed when that payload's
    bytes were being written and right after the half write.
    """

    real_write = os.write
    final_present: list[bool] = []

    def write(descriptor: int, data: Any) -> int:
        payload = bytes(data)
        if final_present or payload_marker not in payload:
            return real_write(descriptor, data)
        final_present.append(os.path.lexists(final))
        real_write(descriptor, payload[: len(payload) // 2])
        final_present.append(os.path.lexists(final))
        raise _SimulatedTermination

    with patch.object(os, "write", side_effect=write):
        yield final_present


def host_observation(case_id: str, *, stop_cleanup: bool = False) -> dict[str, Any]:
    baseline = {
        "config_digest": "a" * 64,
        "desired_mode": "tunnel",
        "generation": 10,
        "ipv6_enabled": True,
        "owner": "packet_tunnel_system_extension",
        "phase": "tunnel_active",
        "ready": True,
    }
    test = (
        {
            "config_digest": None,
            "desired_mode": "off",
            "generation": 11,
            "ipv6_enabled": False,
            "owner": None,
            "phase": "off",
            "ready": False,
        }
        if stop_cleanup
        else {
            "config_digest": "b" * 64,
            "desired_mode": "tunnel",
            "generation": 11,
            "ipv6_enabled": True,
            "owner": "packet_tunnel_system_extension",
            "phase": "tunnel_active",
            "ready": True,
        }
    )
    restore = {**baseline, "generation": 12}
    return {
        "baseline": baseline,
        "baseline_observation_sequence": 20,
        "candidate_observation_sequence": 21,
        "case_id": case_id,
        "document": "cfw-packet-host-completed-v5",
        "restore": restore,
        "restore_observation_sequence": 22,
        "schema_version": 5,
        "sequence": 8,
        "session_id": hashlib.sha256(f"host:{case_id}".encode("ascii")).hexdigest(),
        "test": test,
        "test_observation_sequence": 21,
    }


def typed_host_receipt(case_id: str, *, stop_cleanup: bool = False) -> PacketHostReceipt:
    document = host_observation(case_id, stop_cleanup=stop_cleanup)

    def snapshot(name: str) -> PacketHostSnapshot:
        value = document[name]
        return PacketHostSnapshot(
            config_digest=value["config_digest"],
            desired_mode=value["desired_mode"],
            generation=value["generation"],
            ipv6_enabled=value["ipv6_enabled"],
            owner=value["owner"],
            phase=value["phase"],
            ready=value["ready"],
        )

    return PacketHostReceipt(
        baseline=snapshot("baseline"),
        baseline_observation_sequence=document["baseline_observation_sequence"],
        candidate_observation_sequence=document["candidate_observation_sequence"],
        case_id=case_id,
        restore=snapshot("restore"),
        restore_observation_sequence=document["restore_observation_sequence"],
        session_id=document["session_id"],
        test=snapshot("test"),
        test_observation_sequence=document["test_observation_sequence"],
    )


def off_proof_output() -> str:
    return canonical_json(
        {
            "action": "prove_off",
            "document": "cfw-current-service-maintenance-v2",
            "engine_status": "off",
            "global_authority": "enabled",
            "off_proof_profile": "current_engine_v6_authority_v1_1",
            "proxy_agent": "enabled",
        }
    ).decode("utf-8")


def guard() -> dict[str, object]:
    return {
        "cfw_processes": [
            {
                "binary_sha256": "7" * 64,
                "path": (
                    "/Applications/Clash for Windows.app/Contents/MacOS/"
                    "Clash for Windows"
                ),
                "pid": 111,
                "started_at": "Mon Jul 27 11:00:00 2026",
                "uid": 501,
            },
            {
                "binary_sha256": "8" * 64,
                "path": (
                    "/Applications/Clash for Windows.app/Contents/Resources/static/"
                    "files/darwin/x64/clash-darwin"
                ),
                "pid": 112,
                "started_at": "Mon Jul 27 11:00:01 2026",
                "uid": 0,
            },
        ],
        "dns_sha256": "9" * 64,
        "proxy_sha256": "a" * 64,
        "routes_ipv4_sha256": "b" * 64,
        "routes_ipv6_sha256": "c" * 64,
        "tun_sha256": "d" * 64,
    }


def restarted_guard() -> dict[str, object]:
    current = guard()
    for process in current["cfw_processes"]:
        process["pid"] += 1_000
        process["started_at"] = "Mon Jul 27 11:30:00 2026"
    current["tun_sha256"] = "e" * 64
    return current


# Raw network observations from the release Mac with Clash for Mac and Clash
# for Windows off (2026-10-16), trimmed to one row or block of each shape, with
# its hardware address and search domain replaced by documentation values. Its
# own utun0 and utun1 carry only link-local addresses and scoped IPv6 defaults.
NETWORK_IFCONFIG = (
    "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
    "\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>\n"
    "\tinet 127.0.0.1 netmask 0xff000000\n"
    "\tinet6 ::1 prefixlen 128 \n"
    "\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1 \n"
    "\tnd6 options=201<PERFORMNUD,DAD>\n"
    "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
    "\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>\n"
    "\tether 00:00:5e:00:53:01\n"
    "\tinet6 fe80::181c:e7c:733d:8c24%en0 prefixlen 64 secured scopeid 0xe \n"
    "\tinet 10.249.78.65 netmask 0xffffc000 broadcast 10.249.127.255\n"
    "\tnd6 options=201<PERFORMNUD,DAD>\n"
    "\tmedia: autoselect\n"
    "\tstatus: active\n"
    "pktap0: flags=1<UP> mtu 0\n"
    "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n"
    "\tinet6 fe80::5d60:a7af:ce79:11fe%utun0 prefixlen 64 scopeid 0x13 \n"
    "\tnd6 options=201<PERFORMNUD,DAD>\n"
    "utun1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n"
    "\tinet6 fe80::c854:b549:8035:ac42%utun1 prefixlen 64 scopeid 0x14 \n"
    "\tnd6 options=201<PERFORMNUD,DAD>\n"
    "bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500\n"
    "\toptions=3<RXCSUM,TXCSUM>\n"
    "\tether 02:00:00:00:00:00\n"
    "\tinet 10.211.55.2 netmask 0xffffff00 broadcast 10.211.55.255\n"
    "\tinet6 fe80::bcd0:74ff:fe47:8964%bridge100 prefixlen 64 scopeid 0x22 \n"
    "\tinet6 fdb2:2c26:f4e4::1 prefixlen 64 \n"
    "\tConfiguration:\n"
    "\t\tid 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0\n"
    "\tmember: vmenet0 flags=3<LEARNING,DISCOVER>\n"
    "\t        ifmaxaddr 0 port 33 priority 0 path cost 0\n"
    "\tstatus: active\n"
)
NETWORK_ROUTES_IPV4 = (
    "Routing tables\n"
    "\n"
    "Internet:\n"
    "Destination        Gateway            Flags               Netif Expire\n"
    "default            10.249.64.1        UGScg                 en0       \n"
    "default            link#34            UCSIg           bridge100      !\n"
    "10.211.55/24       link#34            UC              bridge100      !\n"
    "10.249.64/18       link#14            UCS                   en0      !\n"
    "10.249.64.1/32     link#14            UCS                   en0      !\n"
    "127                127.0.0.1          UCS                   lo0       \n"
    "127.0.0.1          127.0.0.1          UH                    lo0       \n"
    "169.254            link#14            UCS                   en0      !\n"
    "224.0.0/4          link#14            UmCS                  en0      !\n"
    "255.255.255.255/32 link#14            UCS                   en0      !\n"
)
NETWORK_ROUTES_IPV6 = (
    "Routing tables\n"
    "\n"
    "Internet6:\n"
    "Destination                             Gateway                                 "
    "Flags               Netif Expire\n"
    "default                                 fe80::%utun0                            "
    "UGcIg               utun0       \n"
    "default                                 fe80::%utun1                            "
    "UGcIg               utun1       \n"
    "::1                                     ::1                                     "
    "UHL                   lo0       \n"
    "fdb2:2c26:f4e4::/64                     link#34                                 "
    "UC              bridge100       \n"
    "fe80::%lo0/64                           fe80::1%lo0                             "
    "UcI                   lo0       \n"
    "fe80::%utun0/64                         fe80::5d60:a7af:ce79:11fe%utun0         "
    "UcI                 utun0       \n"
    "ff00::/8                                fe80::5d60:a7af:ce79:11fe%utun0         "
    "UmCI                utun0       \n"
)
NETWORK_DNS = (
    "DNS configuration\n"
    "\n"
    "resolver #1\n"
    "  search domain[0] : example.org\n"
    "  nameserver[0] : 10.255.0.1\n"
    "  nameserver[1] : 10.255.0.2\n"
    "  if_index : 14 (en0)\n"
    "  flags    : Request A records\n"
    "  reach    : 0x00000002 (Reachable)\n"
    "\n"
    "resolver #2\n"
    "  domain   : local\n"
    "  options  : mdns\n"
    "  timeout  : 5\n"
    "  flags    : Request A records\n"
    "  reach    : 0x00000000 (Not Reachable)\n"
    "  order    : 300000\n"
    "\n"
    "DNS configuration (for scoped queries)\n"
    "\n"
    "resolver #1\n"
    "  search domain[0] : example.org\n"
    "  nameserver[0] : 10.255.0.1\n"
    "  nameserver[1] : 10.255.0.2\n"
    "  if_index : 14 (en0)\n"
    "  flags    : Scoped, Request A records\n"
    "  reach    : 0x00000002 (Reachable)\n"
)
NETWORK_PROXY = (
    "<dictionary> {\n"
    "  ExceptionsList : <array> {\n"
    "    0 : 127.0.0.1\n"
    "    1 : 192.168.0.0/16\n"
    "    2 : 10.0.0.0/8\n"
    "    3 : localhost\n"
    "    4 : *.local\n"
    "  }\n"
    "  FTPPassive : 1\n"
    "  HTTPEnable : 0\n"
    "  HTTPSEnable : 0\n"
    "  SOCKSEnable : 0\n"
    "}\n"
)
# Synthetic Clash for Mac Packet Tunnel state in the same formats: its utun
# carries the tunnel-plan addresses, its routes run through that utun, and
# its DNS peers become the system resolvers.
CFM_UTUN_BLOCK = (
    "utun10: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n"
    "\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>\n"
    "\tinet 198.18.64.1 --> 198.18.64.1 netmask 0xfffffffc\n"
    "\tinet6 fe80::1c2b:3a4d:5e6f:7a8b%utun10 prefixlen 64 scopeid 0x2a \n"
    "\tinet6 2001:2:0:64::1 prefixlen 126 \n"
    "\tnd6 options=201<PERFORMNUD,DAD>\n"
)


def scutil_proxy(
    fields: str,
    *,
    scoped: dict[str, str] | None = None,
    supplemental: tuple[str, ...] = (),
) -> str:
    """`scutil --proxy` text for the given unindented `Key : value` lines.

    scutil indents two spaces a level, sorts keys, lists an exception array
    in each proxy dictionary, and prints a `__SCOPED__` dictionary per
    interface and a `__SUPPLEMENTAL__` array of dictionaries after the fields.
    """

    def dictionary(body: str, depth: int) -> str:
        pad = "  " * depth
        return (
            f"{pad}ExceptionsList : <array> {{\n"
            f"{pad}  0 : *.local\n"
            f"{pad}  1 : 169.254/16\n"
            f"{pad}}}\n"
            + "".join(f"{pad}{line}\n" for line in body.splitlines())
        )

    output = "<dictionary> {\n" + dictionary(fields, 1)
    if scoped is not None:
        output += "  __SCOPED__ : <dictionary> {\n"
        for name, body in scoped.items():
            output += f"    {name} : <dictionary> {{\n" + dictionary(body, 3) + "    }\n"
        output += "  }\n"
    if supplemental:
        output += "  __SUPPLEMENTAL__ : <array> {\n"
        for index, body in enumerate(supplemental):
            output += f"    {index} : <dictionary> {{\n" + dictionary(body, 3) + "    }\n"
        output += "  }\n"
    return output + "}\n"


# The values the ProxyAgent applies for System Proxy (SystemProxyPreferences
# appliedValues): HTTP, HTTPS and SOCKS on its loopback listener, automatic
# configuration off.
CFM_PROXY_FIELDS = (
    "HTTPEnable : 1\n"
    "HTTPPort : 7890\n"
    "HTTPProxy : 127.0.0.1\n"
    "HTTPSEnable : 1\n"
    "HTTPSPort : 7890\n"
    "HTTPSProxy : 127.0.0.1\n"
    "ProxyAutoConfigEnable : 0\n"
    "ProxyAutoDiscoveryEnable : 0\n"
    "SOCKSEnable : 1\n"
    "SOCKSPort : 7890\n"
    "SOCKSProxy : 127.0.0.1\n"
)
PROXY_OFF_FIELDS = "FTPPassive : 1\nHTTPEnable : 0\nHTTPSEnable : 0\nSOCKSEnable : 0\n"
LOOPBACK_PROXY = scutil_proxy(CFM_PROXY_FIELDS)


def hidden_loopback_proxies() -> dict[str, str]:
    """System proxies off, plus the product's loopback proxy where scutil nests none.

    A proxy dictionary nests only arrays of scalars such as its exception
    list, and only the global one holds the scoped and supplemental ones. The
    pre-flight and recovery read no dictionary anywhere else, so each shape
    must be refused as malformed, never read as having no loopback proxy.
    """

    def dictionary(depth: int, opener: str) -> str:
        pad = "  " * depth
        fields = "".join(f"{pad}  {line}\n" for line in CFM_PROXY_FIELDS.splitlines())
        return f"{pad}{opener} : <dictionary> {{\n{fields}{pad}}}\n"

    off = scutil_proxy(PROXY_OFF_FIELDS)
    root_end = len(off) - len("}\n")
    scoped = scutil_proxy(PROXY_OFF_FIELDS, scoped={"en0": PROXY_OFF_FIELDS})
    return {
        "unknown dictionary": off[:root_end] + dictionary(1, "Foo") + "}\n",
        "dictionary in a scoped entry": scoped.replace(
            "    en0 : <dictionary> {\n",
            "    en0 : <dictionary> {\n" + dictionary(3, "Foo"),
        ),
        "unknown array of dictionaries": off[:root_end]
        + "  Bar : <array> {\n"
        + dictionary(2, "0")
        + "  }\n}\n",
        "dictionary in an exception list": off.replace(
            "    1 : 169.254/16\n", "    1 : 169.254/16\n" + dictionary(2, "2")
        ),
    }


NETWORK_OBSERVATION_COMMANDS = {
    "interface": ("/sbin/ifconfig",),
    "IPv4 route": ("/usr/sbin/netstat", "-rn", "-f", "inet"),
    "IPv6 route": ("/usr/sbin/netstat", "-rn", "-f", "inet6"),
    "DNS": ("/usr/sbin/scutil", "--dns"),
    "system proxy": ("/usr/sbin/scutil", "--proxy"),
}
OFF_NETWORK = {
    "interface": NETWORK_IFCONFIG,
    "IPv4 route": NETWORK_ROUTES_IPV4,
    "IPv6 route": NETWORK_ROUTES_IPV6,
    "DNS": NETWORK_DNS,
    "system proxy": NETWORK_PROXY,
}


def whole_system_guard(*, proxy: str = NETWORK_PROXY) -> dict[str, object]:
    """A baseline taken without Clash for Windows: digests of the whole system."""

    return {
        "cfw_processes": [],
        "dns_sha256": "1" * 64,
        "proxy_sha256": hashlib.sha256(proxy.encode("utf-8")).hexdigest(),
        "routes_ipv4_sha256": "2" * 64,
        "routes_ipv6_sha256": "3" * 64,
        "tun_sha256": "4" * 64,
    }


def process_table(*, running: bool) -> str:
    lines = [
        (
            "111 501 Mon Jul 27 11:00:00 2026 "
            "/Applications/Clash for Windows.app/Contents/MacOS/Clash for Windows"
        ),
        (
            "112 0 Mon Jul 27 11:00:01 2026 "
            "/Applications/Clash for Windows.app/Contents/Resources/static/files/"
            "darwin/x64/clash-darwin"
        ),
    ]
    if running:
        lines.append(
            "200 501 Mon Jul 27 11:59:58 2026 "
            "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"
        )
    return "\n".join(lines) + "\n"


def launchctl_output(
    *,
    domain_target: str,
    program_identifier: str,
    service_label: str,
    parent_bundle_version: str = TO_BUILD,
) -> str:
    """Reproduce the exact `launchctl print` shape for an SMAppService job.

    The shape was captured from the release Mac's installed 40043 services;
    the parent bundle version is an explicit candidate fixture value.
    Both plists declare `BundleProgram`, so launchd resolves the executable
    inside the signed bundle and prints a bundle-relative `program identifier`
    line with resolution `mode: 2`. It never prints the absolute `program =`
    line that only an absolute-`Program` job produces. Host-specific values
    (the submitting pid and the BTM uuid) are deliberately excluded.
    """

    return (
        f"{domain_target} = {{\n"
        "\tactive count = 4\n"
        "\ttype = Submitted\n"
        "\tmanaged_by = com.apple.xpc.ServiceManagement\n"
        "\tstate = running\n"
        "\n"
        f"\tprogram identifier = {program_identifier} (mode: 2)\n"
        "\tparent bundle identifier = com.bill.clashformac\n"
        f"\tparent bundle version = {parent_bundle_version}\n"
        "\n"
        "\tLWCR = {\n"
        '\t\t"reqs" => {\n'
        f'\t\t\t"signing-identifier" => "{service_label}"\n'
        '\t\t\t"validation-category" => 6\n'
        '\t\t\t"team-identifier" => "YKUPL7Z869"\n'
        "\t\t}\n"
        '\t\t"vers" => 1\n'
        "\t}\n"
        "}\n"
    )


def system_extension_output() -> str:
    return (
        "1 extension(s)\n"
        "--- com.apple.system_extension.network_extension\n"
        "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
        "*\t*\tYKUPL7Z869\tcom.bill.clashformac.packet-tunnel "
        f"(0.5.0/{TO_BUILD})\tCFWPacketTunnel\t[activated enabled]\n"
    )


SYSTEM_EXTENSION_ACTIVATED = "[activated enabled]"
SYSTEM_EXTENSION_RETAINED = "[terminated waiting to uninstall on reboot]"
# Section lines exactly as `systemextensionsctl list` prints them on the GA Mac.
NETWORK_EXTENSION_SECTION = (
    "--- com.apple.system_extension.network_extension (Go to 'System Settings > "
    "General > Login Items & Extensions > Network Extensions' to modify these "
    "system extension(s))"
)
DRIVER_EXTENSION_SECTION = (
    "--- com.apple.system_extension.driver_extension (Go to 'System Settings > "
    "General > Login Items & Extensions > Driver Extensions' to modify these "
    "system extension(s))"
)
SAMSUNG_MTP_DRIVER_ROW = (
    "*\t*\tEZ5B6482X4\tcom.devguru.DriverKit.SamsungMTP (2.3.4/2.3.4)"
    "\tcom.devguru.DriverKit.SamsungMTP\t[activated enabled]"
)


def packet_tunnel_row(
    version: str,
    state: str,
    *,
    flags: str | None = None,
    team_id: str = "YKUPL7Z869",
    bundle_id: str = "com.bill.clashformac.packet-tunnel",
) -> str:
    # `flags` is the enabled and active columns. macOS marks both only on the
    # activated and enabled registration and leaves both empty on retained ones.
    if flags is None:
        flags = "*\t*" if state == SYSTEM_EXTENSION_ACTIVATED else "\t"
    return (
        f"{flags}\t{team_id}\t{bundle_id} ({version})"
        f"\tClash for Mac Packet Tunnel\t{state}"
    )


def system_extension_listing(*sections: tuple[str, tuple[str, ...]]) -> str:
    lines = [f"{sum(len(rows) for _section, rows in sections)} extension(s)"]
    for section, rows in sections:
        lines.extend(
            (
                section,
                "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]",
                *rows,
            )
        )
    return "\n".join(lines) + "\n"


def packet_tunnel_listing(*rows: str) -> str:
    return system_extension_listing((NETWORK_EXTENSION_SECTION, rows))


def observed_replacement_rows() -> tuple[str, ...]:
    # The GA Mac lists 50008 and 40073 retained and the predecessor activated.
    # Enabling Tunnel on the GA build replaces the predecessor, which macOS then
    # retains until reboot.
    return (
        packet_tunnel_row("0.5.0/50008", SYSTEM_EXTENSION_RETAINED),
        packet_tunnel_row("0.4.0/40073", SYSTEM_EXTENSION_RETAINED),
        packet_tunnel_row(f"0.5.0/{FROM_BUILD}", SYSTEM_EXTENSION_RETAINED),
        packet_tunnel_row(f"0.5.0/{TO_BUILD}", SYSTEM_EXTENSION_ACTIVATED),
    )


def observed_replacement_output() -> str:
    return packet_tunnel_listing(*observed_replacement_rows())


class RuntimeFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        self.acceptance, self.raw_root = _fixed_paths(self.repository)
        self.acceptance.parent.mkdir(parents=True)
        self.acceptance.parent.chmod(0o700)
        self.raw_root.mkdir(mode=0o700)
        self.environment_path = self.repository.joinpath(*ENVIRONMENT_RELATIVE.parts)
        self.environment_path.parent.parent.mkdir(mode=0o700)
        self.environment_path.parent.mkdir(mode=0o700)
        self.environment_path.write_bytes(canonical_json(GA_ENVIRONMENT))
        self.environment_path.chmod(0o600)
        self.expected = {
            "checks": CHECKS,
            "document": DOCUMENT,
            **DIGESTS,
            "from_build": FROM_BUILD,
            "ga_environment_sha256": GA_ENVIRONMENT_SHA256,
            "product_version": PRODUCT_VERSION,
            "to_build": TO_BUILD,
        }
        self.documents: dict[str, dict[str, object]] = {}
        self.pcaps: dict[str, bytes] = {}
        self._build()
        self.write_all()
        self.write_collection_receipt()

    def cleanup(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _traffic_tokens(check_id: str) -> dict[str, str]:
        return {
            stage: _derive_capture_token(CHALLENGE, check_id, stage)
            for stage in ("start", "target", "end")
        }

    def _traffic(self, check_id: str) -> dict[str, object]:
        policy = TRAFFIC_POLICY[check_id]
        tokens = self._traffic_tokens(check_id)
        pcap_name = f"{check_id.replace('_', '-')}.pcap"
        if policy["protocol"] == "dns":
            capture = _utun_udp_pcap(_tunnel_dns_packets(tokens))
            capture_filter = _expected_tunnel_dns_filter(tokens)
            interface_name, observation_ms = "utun5", DNS_OBSERVATION_MS
            endpoint = {
                "interface_name": interface_name,
                "link_type": UTUN_LINK_TYPE,
                "remote_port": 53,
                "stage_families": dict(OBSERVED_DNS_FAMILIES),
            }
        else:
            capture = pcap_bytes(
                start_marker=tokens["start"].encode("ascii"),
                token=tokens["target"].encode("ascii"),
                end_marker=tokens["end"].encode("ascii"),
                include_token=True,
                protocol=policy["protocol"],
                family="ipv4",
                local_address="198.18.64.1",
                remote_address=policy["remote_address"],
                local_port=41000,
                remote_port=policy["remote_port"],
                link_type=1,
            )
            capture_filter = packet_capture_filter_argv(
                case_id=policy["case_id"],
                tokens=(tokens["start"], tokens["target"], tokens["end"]),
            )
            interface_name, observation_ms = "en0", 5000
            endpoint = {
                "family": "ipv4",
                "interface_name": interface_name,
                "link_type": 1,
                "local_address": "198.18.64.1",
                "remote_address": policy["remote_address"],
                "remote_port": policy["remote_port"],
            }
        self.pcaps[pcap_name] = capture
        sender_commands = []
        stage_times = {
            "start": ("2026-07-27T11:59:59.500000Z", "2026-07-27T12:00:00.500000Z"),
            "target": ("2026-07-27T12:00:00.500000Z", "2026-07-27T12:00:01.500000Z"),
            "end": ("2026-07-27T12:00:04.500000Z", "2026-07-27T12:00:05.500000Z"),
        }
        for stage in ("start", "target", "end"):
            token = tokens[stage]
            sender_result = {
                "bytes_submitted": len(token),
                "case_id": policy["case_id"],
                "document": "cfw-packet-send-stage-result-v2",
                "schema_version": 2,
                "stage": stage,
                "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
            }
            if policy["protocol"] != "dns":
                sender_result.update(
                    {
                        "dns_result": None,
                        "local_address": "198.18.64.1",
                        "local_port": 41000,
                        "remote_address": policy["remote_address"],
                        "remote_port": policy["remote_port"],
                        "transport": policy["protocol"],
                    }
                )
            else:
                sender_result.update(
                    {
                        "dns_result": {
                            "query": {
                                "addresses": ["192.0.2.1"],
                                "name": f"{token}.evidence.test",
                                "token_sha256": hashlib.sha256(
                                    token.encode("ascii")
                                ).hexdigest(),
                            },
                            "requested_type": "A",
                            "resolver_role": "primary",
                            "trigger": "getaddrinfo",
                        },
                        "local_address": None,
                        "local_port": None,
                        "remote_address": None,
                        "remote_port": None,
                        "transport": "resolver",
                    }
                )
            argv = [
                COLLECTOR["python"]["executable"],
                "-I",
                "-S",
                "-B",
                "-W",
                "error",
                "scripts/physical_capture/packet_sender.py",
                "--case",
                policy["case_id"],
                "--stage",
                stage,
                "--protocol",
                policy["protocol"],
                "--family",
                "ipv4",
            ]
            if policy["protocol"] != "dns":
                argv.extend(
                    [
                        "--local-address",
                        "198.18.64.1",
                        "--local-port",
                        "0",
                        "--remote-address",
                        policy["remote_address"],
                        "--remote-port",
                        str(policy["remote_port"]),
                    ]
                )
            argv.extend(
                [
                    "--resolver-role",
                    "primary" if policy["protocol"] == "dns" else "none",
                    "--token",
                    token,
                    "--quic-version",
                    "0",
                    "--absence-window-ms",
                    "0",
                ]
            )
            sender_commands.append(
                command(
                    argv,
                    stdout=canonical_json(sender_result).decode("utf-8"),
                    started_at=stage_times[stage][0],
                    finished_at=stage_times[stage][1],
                )
            )
        return check(
            check_id,
            capture={
                "kind": "packet-pcap",
                "path": pcap_name,
                "sha256": sha256_bytes(capture),
                "size": len(capture),
            },
            capture_command=command(
                ga_runtime._capture_command_argv(interface_name, capture_filter),
                stderr=_tcpdump_stderr(capture, interface_name),
            ),
            endpoint=endpoint,
            host_observation=host_observation(policy["case_id"]),
            observation_ms=observation_ms,
            protocol=policy["protocol"],
            send_commands=sender_commands,
            tokens=tokens,
        )

    def _build(self) -> None:
        bindings = copy.deepcopy(DIGESTS)
        self.documents["exact-dmg-install.json"] = check(
            "exact_dmg_install",
            bindings=bindings,
            commands={
                "dmg_gatekeeper": command(
                    [
                        "/usr/sbin/spctl",
                        "--assess",
                        "--type",
                        "open",
                        "--context",
                        "context:primary-signature",
                        "-vv",
                        (
                            f"target/candidates/0.5.0/ga/{TO_BUILD}/packages/dmg/v0.5.0/"
                            "Clash.for.Mac_0.5.0_arm64.dmg"
                        ),
                    ],
                    stderr="accepted\nsource=Notarized Developer ID\n",
                ),
                "dmg_set_verify": command(
                    ga_runtime._dmg_verifier_command(REPOSITORY, self.repository),
                    stdout=(
                        f"DMG release set verified: "
                        f"{self.repository / ga_runtime.DMG_SET_RELATIVE}\n"
                    ),
                ),
            },
            dmg_contained_app_tree_sha256=APP_TREE,
            installed_app_tree_sha256=APP_TREE,
        )
        self.documents["launch.json"] = check(
            "launch",
            launch_command=command(
                ["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"]
            ),
            process_observation=command(
                ["/bin/ps", "-axo", "pid=,uid=,lstart=,comm="],
                stdout=process_table(running=True),
            ),
        )
        uid = os.geteuid()
        self.documents["service-registration.json"] = check(
            "service_registration",
            commands={
                "global_authority": command(
                    [
                        "/bin/launchctl",
                        "print",
                        "system/com.bill.clashformac.global-authority",
                    ],
                    stdout=launchctl_output(
                        domain_target=(
                            "system/com.bill.clashformac.global-authority"
                        ),
                        program_identifier=(
                            "Contents/Library/HelperTools/CFWGlobalAuthority"
                        ),
                        service_label="com.bill.clashformac.global-authority",
                    ),
                ),
                "proxy_agent": command(
                    [
                        "/bin/launchctl",
                        "print",
                        f"gui/{uid}/com.bill.clashformac.proxy-agent",
                    ],
                    stdout=launchctl_output(
                        domain_target=(
                            f"gui/{uid}/com.bill.clashformac.proxy-agent"
                        ),
                        program_identifier=(
                            "Contents/Library/LoginItems/CFWProxyAgent.app"
                            "/Contents/MacOS/CFWProxyAgent"
                        ),
                        service_label="com.bill.clashformac.proxy-agent",
                    ),
                ),
            },
        )
        self.documents["system-extension.json"] = check(
            "system_extension",
            command=command(
                ["/usr/bin/systemextensionsctl", "list"],
                stdout=system_extension_output(),
            ),
        )
        rejection_receipts = []
        for _probe_id, argv, exit_code, expected_stderr in HIGH_RISK_PROBES:
            rejection_receipts.append(
                command(
                    list(argv),
                    stderr=expected_stderr,
                    exit_code=exit_code,
                )
            )
        self.documents["high-risk-rejections.json"] = check(
            "high_risk_rejections", observations=rejection_receipts
        )
        state = guard()
        self.documents["shutdown-restore.json"] = check(
            "shutdown_restore",
            after_guard=copy.deepcopy(state),
            before_guard=copy.deepcopy(state),
            host_process_observation=command(
                list(PROCESS_OBSERVATION_COMMAND),
                stdout=process_table(running=False),
                started_at="2026-07-27T12:00:07Z",
                finished_at="2026-07-27T12:00:08Z",
            ),
            off_proof_command=command(
                list(OFF_PROOF_COMMAND),
                stdout=off_proof_output(),
                started_at="2026-07-27T12:00:08Z",
                finished_at="2026-07-27T12:00:09Z",
            ),
            process_observation=command(
                list(PROCESS_OBSERVATION_COMMAND),
                stdout=process_table(running=False),
                started_at="2026-07-27T12:00:09Z",
                finished_at="2026-07-27T12:00:10Z",
            ),
            shutdown_request=copy.deepcopy(OPERATOR_QUIT_REQUEST),
            stop_restore_observation=host_observation(
                "stop-cleanup", stop_cleanup=True
            ),
        )
        self.documents["legacy-cfw-preserved.json"] = check(
            "legacy_cfw_preserved",
            after_guard=copy.deepcopy(state),
            before_guard=copy.deepcopy(state),
            install_journal_sha256=DIGESTS["install_journal_sha256"],
            service_journal_tree_sha256=DIGESTS["service_journal_tree_sha256"],
        )
        for check_id in TRAFFIC_CHECKS:
            self.documents[f"{check_id.replace('_', '-')}.json"] = self._traffic(
                check_id
            )
        self.documents["network-extension.json"] = check(
            "network_extension",
            traffic_bindings={
                check_id: {
                    "case_id": TRAFFIC_POLICY[check_id]["case_id"],
                    "host_observation_sha256": sha256_bytes(
                        canonical_json(
                            self.documents[f"{check_id.replace('_', '-')}.json"][
                                "host_observation"
                            ]
                        )
                    ),
                }
                for check_id in TRAFFIC_CHECKS
            },
        )

    def _raw_bytes_without_scan(self) -> dict[str, bytes]:
        result = {
            name: canonical_json(value)
            for name, value in self.documents.items()
            if name != "credential-leak-scan.json"
        }
        result.update(self.pcaps)
        return result

    def rebuild_scan(self) -> None:
        corpus = []
        for name, data in sorted(self._raw_bytes_without_scan().items()):
            corpus.append(
                {"path": name, "sha256": sha256_bytes(data), "size": len(data)}
            )
        self.documents["credential-leak-scan.json"] = check(
            "credential_leak_scan",
            corpus=corpus,
            pattern_policy=SECRET_POLICY,
        )

    def write_all(self) -> None:
        self.rebuild_scan()
        for name in RAW_FILE_NAMES:
            data = (
                self.pcaps[name]
                if name in PCAP_FILES
                else canonical_json(self.documents[name])
            )
            path = self.raw_root / name
            path.write_bytes(data)
            path.chmod(0o600)

    def write_collection_receipt(
        self,
        events: list[tuple[str, str]] | None = None,
        *,
        baseline: dict[str, object] | None = None,
    ) -> None:
        """Write the fixture intent and an event log, by default a completed one."""

        root = self.repository.joinpath(*COLLECTION_RELATIVE.parts)
        root.mkdir(mode=0o700)
        intent = {
            "cfw_guard_baseline": guard() if baseline is None else baseline,
            "collection": {
                "challenge": CHALLENGE,
                "ga_environment_sha256": GA_ENVIRONMENT_SHA256,
                "session_id": SESSION_ID,
            },
            "collector": copy.deepcopy(COLLECTOR),
            "document": COLLECTION_DOCUMENT,
            "journal_bindings": {
                key: DIGESTS[key]
                for key in ("install_journal_sha256", "service_journal_tree_sha256")
            },
            "package_bindings": {
                key: DIGESTS[key]
                for key in (
                    "dmg_gatekeeper_sha256",
                    "dmg_set_seal_sha256",
                    "dmg_sha256",
                )
            },
            "product": {
                "from_build": FROM_BUILD,
                "to_build": TO_BUILD,
                "version": PRODUCT_VERSION,
            },
            "schema_version": COLLECTION_INTENT_SCHEMA_VERSION,
        }
        intent_path = root / "intent.json"
        intent_path.write_bytes(canonical_json(intent))
        intent_path.chmod(0o600)
        if events is None:
            events = [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        for index, (phase, step) in enumerate(events):
            path = root / f"event-{index:03d}.json"
            path.write_bytes(collection_event(index, phase, step))
            path.chmod(0o600)

    @property
    def collection_root(self) -> Path:
        return self.repository.joinpath(*COLLECTION_RELATIVE.parts)

    def rewrite_json(self, name: str) -> None:
        path = self.raw_root / name
        path.write_bytes(canonical_json(self.documents[name]))
        path.chmod(0o600)

    def rebind_receipts(self, collector: dict[str, Any]) -> None:
        """Rewrite the receipts that embed the collector's checkout and Python."""

        verification = self.documents["exact-dmg-install.json"]["commands"][
            "dmg_set_verify"
        ]
        verification["argv"] = ga_runtime._dmg_verifier_command(
            Path(collector["operator_root"]), self.repository
        )
        for check_id in TRAFFIC_CHECKS:
            document = self.documents[f"{check_id.replace('_', '-')}.json"]
            for receipt in document["send_commands"]:
                receipt["argv"][0] = collector["python"]["executable"]
        self.write_all()

    def write_intent_collector(self, collector: object) -> None:
        path = self.collection_root / "intent.json"
        intent = json.loads(path.read_text(encoding="utf-8"))
        intent["collector"] = copy.deepcopy(collector)
        path.write_bytes(canonical_json(intent))

    def remove_unsealed_raw_tree(self) -> None:
        for name in sorted(os.listdir(self.raw_root)):
            (self.raw_root / name).unlink()
        self.raw_root.rmdir()
        collection = self.repository.joinpath(*COLLECTION_RELATIVE.parts)
        for name in sorted(os.listdir(collection)):
            (collection / name).unlink()
        collection.rmdir()

    @contextmanager
    def evidence_sources(self) -> Iterator[None]:
        with patch(
            "scripts.ga_runtime_acceptance._installed_candidate_tree",
            return_value=APP_TREE,
        ), patch(
            "scripts.ga_runtime_acceptance._dmg_contained_candidate_tree",
            return_value=APP_TREE,
        ), patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ):
            yield

    def seal(self) -> dict[str, dict[str, str]]:
        with self.evidence_sources():
            return seal_ga_runtime_acceptance(
                repository=self.repository,
                expected=self.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )

    def resume_seal(self) -> dict[str, dict[str, str]]:
        with self.evidence_sources():
            return ga_runtime.resume_ga_runtime_seal(
                repository=self.repository,
                expected=self.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )

    def validate(self) -> dict[str, dict[str, str]]:
        with self.evidence_sources():
            return validate_ga_runtime_acceptance(
                repository=self.repository,
                acceptance_path=self.acceptance,
                raw_evidence_root=self.raw_root,
                expected=self.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )


class GARuntimeDmgLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.operator = self.root / "operator space;$(not-executed)"
        self.artifact = self.root / "frozen artifact"
        for repository in (self.operator, self.artifact):
            (repository / "scripts").mkdir(parents=True)
            (repository / "scripts/__init__.py").write_text("", encoding="utf-8")
        shutil.copyfile(
            REPOSITORY / "scripts/release_python_launcher.sh",
            self.operator / "scripts/release_python_launcher.sh",
        )
        (self.artifact / "scripts/release_artifact_set_cli.py").write_text(
            'raise RuntimeError("artifact verifier must not execute")\n',
            encoding="utf-8",
        )
        self.runtime = object.__new__(ProductionCollectorRuntime)
        self.runtime.repository = self.artifact
        self.runtime.environment = {
            "CFW_RELEASE_PYTHON_EXECUTABLE": os.sys.executable,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
        }

    def _run_operator_script(self, source: str) -> dict[str, Any]:
        (self.operator / "scripts/release_artifact_set_cli.py").write_text(
            source, encoding="utf-8"
        )
        with patch.object(
            ga_runtime, "__file__", str(self.operator / "scripts/ga_runtime_acceptance.py")
        ):
            argv = ga_runtime._dmg_verifier_command(
                ga_runtime._operator_root(), self.artifact
            )
        self.assertEqual(argv[:3], ["/bin/bash", "-p", "-c"])
        self.assertEqual(
            argv[4:],
            [
                "ga-dmg-verification",
                str(self.operator),
                "verify-dmg",
                "--directory",
                str(self.artifact / ga_runtime.DMG_SET_RELATIVE),
                "--version",
                "0.5.0",
                "--repository",
                str(self.artifact),
            ],
        )
        return self.runtime.run(argv, timeout=30)

    def test_dmg_verifier_uses_operator_source_and_real_isolated_launcher(self) -> None:
        poison = self.root / "ambient"
        poison.mkdir()
        (poison / "sitecustomize.py").write_text(
            'raise RuntimeError("ambient site must not execute")\n', encoding="utf-8"
        )
        bash_startup = poison / "startup.sh"
        bash_startup.write_text('echo AMBIENT_STARTUP >&2\nexit 97\n', encoding="utf-8")
        self.runtime.environment.update(
            {"PYTHONPATH": str(poison), "BASH_ENV": str(bash_startup)}
        )
        receipt = self._run_operator_script(
            "import json, os, sys\n"
            "print(json.dumps({\n"
            "    'argv': sys.argv, 'cwd': os.getcwd(), 'package': __package__,\n"
            "    'isolated': sys.flags.isolated, 'no_site': sys.flags.no_site,\n"
            "    'no_user_site': sys.flags.no_user_site,\n"
            "    'dont_write_bytecode': sys.flags.dont_write_bytecode,\n"
            "    'warnings': sys.warnoptions, 'source_root': sys.path[0],\n"
            "}))\n"
        )
        self.assertEqual(receipt["exit_code"], 0, receipt["stderr"])
        self.assertEqual(receipt["stderr"], "")
        observed = json.loads(receipt["stdout"])
        self.assertEqual(
            observed,
            {
                "argv": [
                    str(self.operator / "scripts/release_artifact_set_cli.py"),
                    *receipt["argv"][6:],
                ],
                "cwd": str(self.artifact),
                "package": "scripts",
                "isolated": 1,
                "no_site": 1,
                "no_user_site": 1,
                "dont_write_bytecode": 1,
                "warnings": ["error"],
                "source_root": str(self.operator),
            },
        )
        self.assertEqual(list(self.root.rglob("__pycache__")), [])

    def test_dmg_verifier_failure_is_not_reported_as_byte_proof(self) -> None:
        receipt = self._run_operator_script(
            'import sys\nsys.stderr.write("fixture verifier rejected bytes\\n")\n'
            "raise SystemExit(19)\n"
        )
        self.assertEqual(receipt["exit_code"], 19)
        self.assertEqual(receipt["stdout"], "")
        self.assertEqual(receipt["stderr"], "fixture verifier rejected bytes\n")
        with self.assertRaises(GARuntimeAcceptanceError) as raised:
            ga_runtime._command(
                receipt,
                expected_argv=receipt["argv"],
                expected_exit=0,
                label="DMG contained-app byte-proof observation",
            )
        self.assertEqual(
            str(raised.exception),
            "DMG contained-app byte-proof observation command identity, exit, or "
            "duration is invalid",
        )
        # The fixed message keeps its text; the notes say which check failed
        # and show the end of each stream.
        notes = getattr(raised.exception, "__notes__", [])
        self.assertEqual(len(notes), 3)
        verdict, stdout, stderr = notes
        self.assertRegex(
            verdict,
            r"^DMG contained-app byte-proof observation failed its exit check: exit "
            r"status 19, expected 0; duration [0-9]+\.[0-9]{3} s, bound 900 s$",
        )
        self.assertEqual(stdout, "DMG contained-app byte-proof observation stdout is empty")
        self.assertEqual(
            stderr,
            "DMG contained-app byte-proof observation stderr (32 bytes) ends "
            "with:\nfixture verifier rejected bytes\n",
        )
        # The operator reads the diagnosis through the existing rendering, in
        # which each line of a note is indented.
        self.assertIn(
            "\n  fixture verifier rejected bytes\n",
            common.failure_diagnostic("error: fixture headline", raised.exception) + "\n",
        )

    def test_rejected_verifier_output_is_withheld_escaped_and_bounded(self) -> None:
        token = "ghp_" + "Q" * 36
        cases = (
            (
                # The token straddles the start of the 4 KiB tail, which alone
                # would show a fragment no pattern matches; a stream holding a
                # credential anywhere is withheld whole.
                "credential across the tail boundary",
                f'sys.stderr.buffer.write(b"{token} " + b"B" * 4090 + b"\\n")',
                "stderr",
                "(4132 bytes) is withheld: it holds credential-like material",
            ),
            (
                "terminal control",
                'sys.stdout.buffer.write(b"\\x1b[2J\\x1b]0;t\\x07ok\\x7f\\xc2\\x9b\\tend\\n")',
                "stdout",
                "(20 bytes) ends with:\n\\x1b[2J\\x1b]0;t\\x07ok\\x7f\\x9b\\x09end\n",
            ),
            (
                "size",
                'sys.stderr.buffer.write(b"A" * 6000 + b"end\\n")',
                "stderr",
                "(6004 bytes) ends with:\n" + "A" * 4092 + "end\n",
            ),
            (
                "escaped expansion",
                'sys.stdout.buffer.write(b"\\x1b" * 5000)',
                "stdout",
                "(5000 bytes) ends with:\n" + "\\x1b" * 1024,
            ),
        )
        label = "DMG contained-app byte-proof observation"
        for case, statement, stream, shown in cases:
            with self.subTest(case):
                receipt = self._run_operator_script(
                    f"import sys\n{statement}\nraise SystemExit(19)\n"
                )
                self.assertEqual(receipt["exit_code"], 19, receipt["stderr"][-200:])
                with self.assertRaises(GARuntimeAcceptanceError) as raised:
                    ga_runtime._command(
                        receipt, expected_argv=receipt["argv"], expected_exit=0, label=label
                    )
                notes = getattr(raised.exception, "__notes__", [])
                self.assertEqual(len(notes), 3)
                self.assertEqual(notes[1 if stream == "stdout" else 2], f"{label} {stream} {shown}")
                tail = shown.partition("\n")[2]
                self.assertLessEqual(len(tail), ga_runtime.COMMAND_DIAGNOSTIC_TAIL_BYTES)
                self.assertNotIn("Q", "".join(notes))
                self.assertNotIn("\x1b", "".join(notes))


class GARuntimeAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RuntimeFixture()
        self.addCleanup(self.fixture.cleanup)

    def test_capture_receipt_requires_explicit_drop_to_operator(self) -> None:
        capture = self.fixture.documents["tcp-traffic.json"]["capture_command"]
        position = capture["argv"].index("-Z")
        del capture["argv"][position:position + 2]
        self.fixture.write_all()
        with self.assertRaises(GARuntimeAcceptanceError):
            self.fixture.seal()
        self.assertFalse(self.fixture.acceptance.exists())

    def test_contract_has_fixed_paths_and_twelve_raw_derived_checks(self) -> None:
        self_check()
        self.assertEqual(
            (PRODUCT_VERSION, FROM_BUILD, TO_BUILD),
            (
                ACTIVE_RELEASE_IDENTITY.product_version,
                ACTIVE_PREDECESSOR.build_number,
                ACTIVE_RELEASE_IDENTITY.ga_build,
            ),
        )
        self.assertEqual(
            (ga_runtime.MAX_COMMAND_SECONDS, DMG_BYTE_PROOF_TIMEOUT_SECONDS),
            (15 * 60, 30 * 60),
        )
        self.assertEqual(
            (
                DOCUMENT,
                SCHEMA_VERSION,
                CHECK_DOCUMENT,
                COMMAND_DOCUMENT,
                COLLECTION_DOCUMENT,
                COLLECTION_INTENT_SCHEMA_VERSION,
                COLLECTION_EVENT_DOCUMENT,
            ),
            (
                "cfm-ga-runtime-acceptance-v2",
                2,
                "cfm-ga-runtime-check-v2",
                "cfm-ga-command-observation-v2",
                "cfm-ga-runtime-collection-intent-v4",
                4,
                "cfm-ga-runtime-collection-event-v2",
            ),
        )
        self.assertEqual(len(CHECKS), 12)
        self.assertEqual(len(RAW_FILE_NAMES), 15)
        self.assertEqual(
            ACCEPTANCE_RELATIVE,
            Path(
                f"target/candidates/0.5.0/ga/{TO_BUILD}/stage-inputs/ga-acceptance/"
                "runtime-acceptance.json"
            ),
        )
        self.assertEqual(
            RAW_ROOT_RELATIVE,
            Path(
                f"target/candidates/0.5.0/ga/{TO_BUILD}/stage-inputs/ga-acceptance/"
                "runtime-evidence"
            ),
        )
        self.assertEqual(
            ENVIRONMENT_RELATIVE,
            Path(
                f"target/candidates/0.5.0/ga/{TO_BUILD}/stage-inputs/ga-acceptance/"
                "migration-journals/service-transaction/environment.json"
            ),
        )
        self.assertEqual(
            INSTALL_JOURNAL_RELATIVE,
            Path(
                f"target/candidates/0.5.0/ga/{TO_BUILD}/stage-inputs/ga-acceptance/"
                "migration-journals/dormant-install.json"
            ),
        )

    def test_historical_migration_bindings_cannot_seal_the_active_candidate(self) -> None:
        for from_build, to_build in (
            ("40041", "40043"),
            ("40041", TO_BUILD),
            ("40043", "40043"),
            ("40043", "40044"),
            ("40043", TO_BUILD),
            ("40044", "40044"),
            ("40044", "40045"),
            ("40044", TO_BUILD),
            ("40045", "40045"),
            # An older registered installation or the next allocation.
            (str(int(FROM_BUILD) - 1), TO_BUILD),
            (FROM_BUILD, NEXT_GA_BUILD),
            (TO_BUILD, NEXT_GA_BUILD),
        ):
            with self.subTest(from_build=from_build, to_build=to_build):
                self.fixture.expected["from_build"] = from_build
                self.fixture.expected["to_build"] = to_build
                with self.assertRaisesRegex(
                    GARuntimeAcceptanceError,
                    "expected identity or check set differs",
                ):
                    self.fixture.seal()
                self.assertFalse(self.fixture.acceptance.exists())

    def test_install_journal_must_record_the_active_predecessor(self) -> None:
        older = dormant_app_install.PredecessorProfile(
            ACTIVE_PREDECESSOR.product_version, str(int(FROM_BUILD) - 1), "e" * 64
        )
        registry = MappingProxyType(
            {**dormant_app_install.SUPPORTED_PREDECESSORS, older.build_number: older}
        )
        cases = (
            (older, f"is not the completed {FROM_BUILD} to {TO_BUILD} install"),
            # The active predecessor passes and reaches the installed-app read.
            (ACTIVE_PREDECESSOR, f"installed {TO_BUILD} application tree cannot be identified"),
        )
        for previous, message in cases:
            with self.subTest(previous=previous.build_number), patch.object(
                dormant_app_install, "SUPPORTED_PREDECESSORS", registry
            ):
                with patch.object(dormant_app_install, "ACTIVE_PREDECESSOR", previous):
                    journals = journal_fixture.JournalExportFixture(
                        previous=dormant_app_install.AppIdentity(
                            previous.product_version,
                            previous.build_number,
                            previous.tree_sha256,
                        )
                    )
                self.addCleanup(journals.cleanup)
                data = canonical_json(journals.install_document())
                with tempfile.TemporaryDirectory() as temporary:
                    repository = Path(temporary)
                    journal = repository.joinpath(*INSTALL_JOURNAL_RELATIVE.parts)
                    journal.parent.mkdir(parents=True)
                    journal.write_bytes(data)
                    journal.chmod(0o600)
                    with patch.object(
                        dormant_app_install,
                        "read_app_identity",
                        side_effect=dormant_app_install.InstallError(
                            "app_identity_invalid", "fixture installed app"
                        ),
                    ), self.assertRaisesRegex(GARuntimeAcceptanceError, message):
                        ga_runtime._installed_candidate_tree(
                            repository, {"install_journal_sha256": sha256_bytes(data)}
                        )

    def test_installed_tree_is_the_closed_install_journal_candidate(self) -> None:
        # The journal records the full candidate identity; the installed bundle
        # only has a version, build and tree. They must name the same app.
        journals = journal_fixture.JournalExportFixture()
        self.addCleanup(journals.cleanup)
        data = canonical_json(journals.install_document())
        candidate = journal_fixture.CANDIDATE.app
        cases = (
            (candidate, None),
            (
                dormant_app_install.AppIdentity(
                    candidate.version, candidate.build_number, "f" * 64
                ),
                "installed application bytes differ from the closed install journal",
            ),
            (
                dormant_app_install.AppIdentity(
                    candidate.version, NEXT_GA_BUILD, candidate.tree_sha256
                ),
                "installed application bytes differ from the closed install journal",
            ),
            (
                dormant_app_install.AppIdentity(
                    "0.5.1", candidate.build_number, candidate.tree_sha256
                ),
                "installed application bytes differ from the closed install journal",
            ),
        )
        for installed, message in cases:
            with self.subTest(installed=installed), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                journal = repository.joinpath(*INSTALL_JOURNAL_RELATIVE.parts)
                journal.parent.mkdir(parents=True)
                journal.write_bytes(data)
                journal.chmod(0o600)
                expected = {"install_journal_sha256": sha256_bytes(data)}
                with patch.object(
                    dormant_app_install, "read_app_identity", return_value=installed
                ) as reader:
                    if message is None:
                        self.assertEqual(
                            ga_runtime._installed_candidate_tree(repository, expected),
                            candidate.tree_sha256,
                        )
                    else:
                        with self.assertRaisesRegex(GARuntimeAcceptanceError, message):
                            ga_runtime._installed_candidate_tree(repository, expected)
                reader.assert_called_once_with(ga_runtime.INSTALLED_APP)

    def test_runtime_json_recursion_is_a_stable_domain_error(self) -> None:
        deeply_nested = (
            "{\"nested\":" * 10_000 + "0" + "}" * 10_000
        ).encode("ascii")
        with self.assertRaises(GARuntimeAcceptanceError):
            ga_runtime._strict_json(deeply_nested, "deep runtime fixture")

        with patch.object(
            ga_runtime.json,
            "loads",
            side_effect=RecursionError("fixture decoder recursion"),
        ), self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "not strict UTF-8 JSON",
        ):
            ga_runtime._strict_json(b"{}\n", "deep runtime fixture")

        excessive_integer = b'{"value":' + b"9" * 5_000 + b"}\n"
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "not strict UTF-8 JSON",
        ):
            ga_runtime._strict_json(excessive_integer, "large integer fixture")

        with patch.object(
            ga_runtime,
            "canonical_json",
            side_effect=RecursionError("fixture canonical recursion"),
        ), self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "not one canonical JSON object",
        ):
            ga_runtime._strict_json(b"{}\n", "deep runtime fixture")

        with self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "not one canonical JSON object",
        ):
            ga_runtime._strict_json(
                b'{"value":"\\ud800"}\n',
                "surrogate runtime fixture",
            )

    def test_complete_raw_evidence_seals_and_reopens_exact_records(self) -> None:
        result = self.fixture.seal()
        self.assertEqual(result, self.fixture.validate())
        self.assertEqual(result["adapter"]["path"], ACCEPTANCE_RELATIVE.as_posix())
        adapter = json.loads(self.fixture.acceptance.read_text(encoding="utf-8"))
        self.assertEqual([entry["id"] for entry in adapter["checks"]], list(CHECKS))
        self.assertNotIn("passed", self.fixture.acceptance.read_text(encoding="utf-8"))

    def test_matching_raw_guards_cannot_replace_the_durable_baseline(self) -> None:
        for name in ("shutdown-restore.json", "legacy-cfw-preserved.json"):
            document = self.fixture.documents[name]
            document["before_guard"]["tun_sha256"] = "e" * 64
            document["after_guard"]["tun_sha256"] = "e" * 64
        self.fixture.write_all()
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError, "differs from the durable collection intent"
        ):
            self.fixture.seal()
        self.assertFalse(self.fixture.acceptance.exists())

    def test_collection_intent_tampering_cannot_rebind_successful_raw_evidence(self) -> None:
        path = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts) / "intent.json"
        original = json.loads(path.read_text(encoding="utf-8"))
        cases = (
            ("cfw_guard_baseline", "tun_sha256", "e" * 64, "durable collection intent"),
            ("journal_bindings", "install_journal_sha256", "e" * 64, "migration journals"),
            ("journal_bindings", "service_journal_tree_sha256", "e" * 64, "migration journals"),
            ("package_bindings", "dmg_sha256", "e" * 64, "package evidence"),
            ("collection", "session_id", "12345678-1234-4234-8234-123456789abd", "different collection"),
        )
        for section, key, value, error in cases:
            with self.subTest(section=section, key=key):
                changed = copy.deepcopy(original)
                self.assertNotEqual(changed[section][key], value)
                changed[section][key] = value
                path.write_bytes(canonical_json(changed))
                with self.assertRaisesRegex(GARuntimeAcceptanceError, error):
                    self.fixture.seal()
                self.assertFalse(self.fixture.acceptance.exists())

    def test_intent_replacement_between_raw_validation_and_receipt_is_rejected(self) -> None:
        path = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts) / "intent.json"
        original_scan = ga_runtime._validate_credential_scan

        def replace_intent_after_guard_validation(document, snapshots):
            original_scan(document, snapshots)
            changed = json.loads(path.read_text(encoding="utf-8"))
            changed["cfw_guard_baseline"]["tun_sha256"] = "e" * 64
            path.write_bytes(canonical_json(changed))

        with patch.object(
            ga_runtime, "_validate_credential_scan",
            side_effect=replace_intent_after_guard_validation,
        ), self.assertRaisesRegex(GARuntimeAcceptanceError, "intent changed during verification"):
            self.fixture.seal()
        self.assertFalse(self.fixture.acceptance.exists())

    def test_existing_adapter_that_cannot_be_made_durable_is_refused(self) -> None:
        self.fixture.seal()
        adapter = self.fixture.acceptance.stat()
        real_full_fsync = durable_file.full_fsync

        def fail_adapter(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == (adapter.st_dev, adapter.st_ino):
                raise OSError(5, "injected adapter full-fsync failure")
            real_full_fsync(descriptor)

        with patch.object(
            durable_file, "full_fsync", side_effect=fail_adapter
        ), self.assertRaisesRegex(
            GARuntimeAcceptanceError, "existing GA runtime adapter cannot be durably reopened"
        ):
            self.fixture.seal()
        self.assertEqual(self.fixture.acceptance.stat().st_ino, adapter.st_ino)

    def test_v2_collection_intent_requires_its_original_frozen_verifier(self) -> None:
        path = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts) / "intent.json"
        legacy = json.loads(path.read_text(encoding="utf-8"))
        del legacy["cfw_guard_baseline"]
        del legacy["journal_bindings"]
        legacy["document"] = "cfm-ga-runtime-collection-intent-v2"
        legacy["schema_version"] = 2
        data = canonical_json(legacy)
        path.write_bytes(data)
        with self.assertRaisesRegex(PublicationError, "unexpected field set"):
            self.fixture.seal()
        self.assertEqual(path.read_bytes(), data)
        self.assertFalse(self.fixture.acceptance.exists())

    def test_v3_collection_intent_requires_its_original_frozen_verifier(self) -> None:
        path = self.fixture.collection_root / "intent.json"
        legacy = json.loads(path.read_text(encoding="utf-8"))
        del legacy["collector"]
        legacy["document"] = "cfm-ga-runtime-collection-intent-v3"
        legacy["schema_version"] = 3
        data = canonical_json(legacy)
        path.write_bytes(data)
        with self.assertRaisesRegex(PublicationError, "unexpected field set"):
            self.fixture.seal()
        self.assertEqual(path.read_bytes(), data)
        self.assertFalse(self.fixture.acceptance.exists())

    def test_v3_document_with_a_collector_is_still_refused(self) -> None:
        path = self.fixture.collection_root / "intent.json"
        legacy = json.loads(path.read_text(encoding="utf-8"))
        legacy["document"] = "cfm-ga-runtime-collection-intent-v3"
        legacy["schema_version"] = 3
        path.write_bytes(canonical_json(legacy))
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError, "collection intent identity is invalid"
        ):
            self.fixture.seal()
        self.assertFalse(self.fixture.acceptance.exists())

    def test_evidence_from_another_operator_root_and_python_seals(self) -> None:
        # A later operator checkout or Python pin bump must not invalidate
        # evidence: receipts are checked against the collection's own record.
        collector = copy.deepcopy(OTHER_COLLECTOR)
        self.assertNotEqual(collector["operator_root"], str(ga_runtime._operator_root()))
        self.assertNotEqual(collector["python"]["executable"], os.sys.executable)
        self.fixture.rebind_receipts(collector)
        self.fixture.write_intent_collector(collector)
        result = self.fixture.seal()
        self.assertEqual(result, self.fixture.validate())

    def test_receipts_must_match_the_recorded_collector(self) -> None:
        def other_operator(collector: dict[str, Any]) -> None:
            collector["operator_root"] = "/Volumes/Release/another-operator"

        def other_python(collector: dict[str, Any]) -> None:
            collector["python"]["executable"] = (
                "/opt/homebrew/Cellar/python@3.13/3.13.9/Frameworks/"
                "Python.framework/Versions/3.13/bin/python3.13"
            )

        dmg_error = "DMG contained-app byte-proof observation command identity"
        sender_error = "dns_traffic start traffic send command command identity"
        # Receipts from another collector, and receipts naming this verifier's
        # own checkout or Python, are refused unless the record names them.
        for receipts, mutate, error in (
            (OTHER_COLLECTOR, other_operator, dmg_error),
            (OTHER_COLLECTOR, other_python, sender_error),
            (COLLECTOR, other_operator, dmg_error),
            (COLLECTOR, other_python, sender_error),
        ):
            with self.subTest(receipts=receipts["operator_root"], case=mutate.__name__):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                fixture.rebind_receipts(receipts)
                recorded = copy.deepcopy(receipts)
                mutate(recorded)
                fixture.write_intent_collector(recorded)
                with self.assertRaisesRegex(GARuntimeAcceptanceError, error):
                    fixture.seal()
                self.assertFalse(fixture.acceptance.exists())

    def test_collector_record_is_a_normalized_absolute_release_python(self) -> None:
        def update(section: str | None, key: str, value: object):
            def mutate(collector: dict[str, Any]) -> None:
                (collector if section is None else collector[section])[key] = value

            return mutate

        def remove(collector: dict[str, Any]) -> None:
            del collector["python"]["version"]

        cases = (
            (update(None, "operator_root", "operator"), "normalized absolute path"),
            (update(None, "operator_root", "/Volumes/a/../b"), "normalized absolute path"),
            (update(None, "operator_root", "/Volumes/a/"), "normalized absolute path"),
            (update(None, "operator_root", "/Volumes/a/./b"), "normalized absolute path"),
            (update(None, "operator_root", "//Volumes/a"), "normalized absolute path"),
            (update(None, "operator_root", "/Volumes/a\nb"), "is not a bounded path"),
            (update(None, "operator_root", "/" + "a" * 1024), "is not a bounded path"),
            (update("python", "executable", ""), "is not a bounded path"),
            (update("python", "executable", 7), "is not a bounded path"),
            (update("python", "executable_sha256", "a" * 64), "unexpected field set"),
            (update("python", "version", "3.14"), "not a release Python version"),
            (update("python", "version", "2.7.18"), "not a release Python version"),
            (update("python", "version", "3.14.01"), "not a release Python version"),
            (update(None, "host", "release-mac"), "unexpected field set"),
            (remove, "unexpected field set"),
        )
        for index, (mutate, error) in enumerate(cases):
            with self.subTest(case=index, error=error):
                collector = copy.deepcopy(COLLECTOR)
                mutate(collector)
                self.fixture.write_intent_collector(collector)
                with self.assertRaisesRegex(
                    (GARuntimeAcceptanceError, PublicationError), error
                ):
                    self.fixture.seal()
                self.assertFalse(self.fixture.acceptance.exists())

    def test_collector_identity_records_the_given_checkout_and_python(self) -> None:
        # collect passes sys.executable unresolved, the operator root and
        # platform.python_version(); see the collect intent assertion.
        launcher = "/opt/homebrew/opt/python@3.14/bin/python3.14"
        self.assertEqual(
            ga_runtime._collector_identity(
                launcher, Path("/Volumes/Release/operator"), "3.14.7"
            ),
            {
                "operator_root": "/Volumes/Release/operator",
                "python": {"executable": launcher, "version": "3.14.7"},
            },
        )
        for executable, version, error in (
            ("python3", "3.14.7", "is not a normalized absolute path"),
            (launcher, "3.15.0a1", "not a release Python version"),
        ):
            with self.subTest(executable=executable, version=version), self.assertRaisesRegex(
                GARuntimeAcceptanceError, error
            ):
                ga_runtime._collector_identity(
                    executable, Path("/Volumes/Release/operator"), version
                )

    def test_dmg_byte_proof_alone_accepts_the_extended_bounded_duration(self) -> None:
        verification = self.fixture.documents["exact-dmg-install.json"]["commands"][
            "dmg_set_verify"
        ]
        verification["started_at"] = "2026-07-27T11:59:59Z"
        verification["finished_at"] = "2026-07-27T12:20:00Z"
        self.fixture.rewrite_json("exact-dmg-install.json")
        self.fixture.rebuild_scan()
        self.fixture.rewrite_json("credential-leak-scan.json")

        result = self.fixture.seal()
        self.assertEqual(result, self.fixture.validate())

    def test_ordinary_command_keeps_the_fifteen_minute_duration_bound(self) -> None:
        launch = self.fixture.documents["launch.json"]["launch_command"]
        launch["started_at"] = "2026-07-27T11:59:59Z"
        launch["finished_at"] = "2026-07-27T12:20:00Z"
        self.fixture.rewrite_json("launch.json")
        self.fixture.rebuild_scan()
        self.fixture.rewrite_json("credential-leak-scan.json")

        with self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            f"installed {TO_BUILD} launch command command identity, exit, or duration is invalid",
        ):
            self.fixture.seal()

    def test_adapter_rename_reply_loss_is_outcome_unknown_and_recoverable(self) -> None:
        publish = ga_runtime.publish_private_file_locked

        def publish_then_lose_reply(**arguments: Any) -> None:
            publish(**arguments)
            raise DurabilityOutcomeUnknown("simulated adapter rename reply loss")

        with patch.object(
            ga_runtime, "publish_private_file_locked", side_effect=publish_then_lose_reply
        ), self.assertRaises(DurabilityOutcomeUnknown):
            self.fixture.seal()
        self.assertTrue(self.fixture.acceptance.is_file())
        # The retry must not report success before the adapter and its
        # directory entry are on stable storage.
        real_full_fsync = durable_file.full_fsync
        synchronized: list[tuple[int, int]] = []

        def observe(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            synchronized.append((metadata.st_dev, metadata.st_ino))
            real_full_fsync(descriptor)

        with patch.object(durable_file, "full_fsync", side_effect=observe):
            result = self.fixture.seal()
        self.assertEqual(result, self.fixture.validate())
        for path in (self.fixture.acceptance, self.fixture.acceptance.parent):
            metadata = path.stat()
            self.assertIn((metadata.st_dev, metadata.st_ino), synchronized)

    def test_resume_seal_completes_only_a_missing_raw_published_marker(self) -> None:
        marker = self.fixture.collection_root / "event-038.json"
        original = marker.read_bytes()
        marker.unlink()
        reopen = ga_runtime.read_private_directory_contents_locked
        with patch.object(
            ga_runtime, "read_private_directory_contents_locked", side_effect=reopen
        ) as reopened:
            result = self.fixture.resume_seal()
        # The marker is written only after the published tree was reopened
        # through the fsyncing reader, not from an unsynchronized snapshot.
        self.assertEqual(
            [call.args[2] for call in reopened.call_args_list], [RAW_ROOT_RELATIVE.name]
        )
        self.assertEqual(marker.read_bytes(), original)
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )
        self.assertEqual(result, self.fixture.validate())

    def test_interrupted_marker_write_never_leaves_a_partial_event(self) -> None:
        # A power loss, forced kill or ^C inside the raw_published marker's
        # write once left a truncated event-038.json that no command repaired.
        marker = self.fixture.collection_root / "event-038.json"
        original = marker.read_bytes()
        marker.unlink()
        acceptance_root = self.fixture.acceptance.parent
        entries = sorted(os.listdir(acceptance_root))
        with interrupted_write(
            b'"phase":"raw_published"', marker
        ) as final_present, self.assertRaises(_SimulatedTermination):
            self.fixture.resume_seal()
        self.assertEqual(final_present, [False, False])
        self.assertFalse(os.path.lexists(marker))
        self.assertEqual(collection_events(self.fixture.repository), STEP_EVENTS)
        self.assertEqual(sorted(os.listdir(acceptance_root)), entries)
        # resume-seal completes the marker; nothing needs a manual quarantine.
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        self.assertEqual(marker.read_bytes(), original)

    def test_interrupted_adapter_write_never_leaves_a_partial_adapter(self) -> None:
        # The same interruption once left a truncated pending adapter that
        # resume-seal, recover and collect all refused.
        acceptance_root = self.fixture.acceptance.parent
        entries = sorted(os.listdir(acceptance_root))
        with interrupted_write(
            b'"evidence_tree":', self.fixture.acceptance
        ) as final_present, self.assertRaises(_SimulatedTermination):
            self.fixture.seal()
        self.assertEqual(final_present, [False, False])
        self.assertFalse(os.path.lexists(self.fixture.acceptance))
        self.assertEqual(sorted(os.listdir(acceptance_root)), entries)
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())

    def test_staging_left_by_a_crash_blocks_no_command(self) -> None:
        # A forced kill or power loss after the marker's bytes were staged but
        # before their rename runs no cleanup and leaves the staged file.
        marker = self.fixture.collection_root / "event-038.json"
        original = marker.read_bytes()
        marker.unlink()
        with patch.object(
            durable_file, "_renameatx_np", side_effect=_SimulatedTermination
        ), patch.object(durable_file, "_remove_created_pending"), self.assertRaises(
            _SimulatedTermination
        ):
            self.fixture.resume_seal()
        self.assertFalse(os.path.lexists(marker))
        acceptance_root = self.fixture.acceptance.parent
        staged = [
            acceptance_root / name
            for name in os.listdir(acceptance_root)
            if name.startswith(durable_file.FILE_STAGING_PREFIX)
        ]
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0].read_bytes(), original)
        # Nothing reads it: collect and recover refuse only the published raw
        # tree, and resume-seal completes the marker beside the leftover.
        collection = FakeCollectorRuntime(self.fixture)
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError, r"already exists \(runtime-evidence\)$"
        ):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=collection,
            )
        recovery = FakeCollectorRuntime(self.fixture)
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            r"already published \(runtime-evidence\); recovery would orphan it",
        ):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertEqual((collection.calls, recovery.calls), ([], []))
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        self.assertEqual(marker.read_bytes(), original)
        self.assertEqual(staged[0].read_bytes(), original)

    def test_event_publication_never_replaces_a_concurrent_event(self) -> None:
        # Staging keeps exclusive creation: an event that appears under the
        # same name before the rename is kept, and the append fails.
        marker = self.fixture.collection_root / "event-038.json"
        competing = collection_event(38, "recovery_required", "collection")
        marker.unlink()
        rename = durable_file._renameatx_np

        def competing_writer_wins(*arguments: Any) -> None:
            marker.write_bytes(competing)
            marker.chmod(0o600)
            rename(*arguments)

        with patch.object(
            durable_file, "_renameatx_np", side_effect=competing_writer_wins
        ), self.assertRaisesRegex(PublicationError, "private destination already exists"):
            ga_runtime._append_raw_published_marker(
                self.fixture.repository,
                self.fixture.collection_root,
                json.loads(competing)["collection"],
            )
        self.assertEqual(marker.read_bytes(), competing)
        self.assertEqual(
            [
                name
                for name in os.listdir(self.fixture.acceptance.parent)
                if name.startswith(durable_file.FILE_STAGING_PREFIX)
            ],
            [],
        )

    def test_event_append_leaves_the_acceptance_root_unlocked(self) -> None:
        # verify and journal-export verification hold the acceptance root lock
        # while they hash; a collection beside them keeps appending events.
        marker = self.fixture.collection_root / "event-038.json"
        original = marker.read_bytes()
        marker.unlink()
        with durable_file.exclusive_rooted_directory_lock(
            self.fixture.repository,
            self.fixture.acceptance.parent,
            require_private=True,
        ):
            ga_runtime._append_raw_published_marker(
                self.fixture.repository,
                self.fixture.collection_root,
                json.loads(original)["collection"],
            )
        self.assertEqual(marker.read_bytes(), original)

    def test_resume_seal_never_marks_invalid_raw_evidence_published(self) -> None:
        marker = self.fixture.collection_root / "event-038.json"
        marker.unlink()
        entries = sorted(os.listdir(self.fixture.acceptance.parent))
        self.fixture.documents["launch.json"]["launch_command"]["exit_code"] = 1
        self.fixture.rewrite_json("launch.json")
        self.fixture.rebuild_scan()
        self.fixture.rewrite_json("credential-leak-scan.json")
        with self.assertRaisesRegex(GARuntimeAcceptanceError, "launch command"):
            self.fixture.resume_seal()
        self.assertFalse(marker.exists())
        self.assertEqual(sorted(os.listdir(self.fixture.acceptance.parent)), entries)

    def test_resume_seal_refuses_terminal_or_incomplete_collections(self) -> None:
        def mark_recovery_required(root: Path) -> None:
            (root / "event-038.json").write_bytes(
                collection_event(38, "recovery_required", "collection")
            )

        def append_recovery_required(root: Path) -> None:
            (root / "event-039.json").write_bytes(
                collection_event(39, "recovery_required", "collection")
            )
            (root / "event-039.json").chmod(0o600)

        def drop_final_step(root: Path) -> None:
            (root / "event-038.json").unlink()
            (root / "event-037.json").unlink()

        def abort_before_mutation(root: Path) -> None:
            for index in range(4, 39):
                (root / f"event-{index:03d}.json").unlink()
            (root / "event-004.json").write_bytes(
                collection_event(4, "aborted_before_mutation", "collection")
            )
            (root / "event-004.json").chmod(0o600)

        for mutate, last in (
            (mark_recovery_required, "recovery_required/collection"),
            (append_recovery_required, "recovery_required/collection"),
            (drop_final_step, "started/shutdown-process-observation"),
            (abort_before_mutation, "aborted_before_mutation/collection"),
        ):
            with self.subTest(case=mutate.__name__):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                mutate(fixture.collection_root)
                before = {
                    path.name: path.read_bytes()
                    for path in fixture.collection_root.iterdir()
                }
                with self.assertRaisesRegex(
                    GARuntimeAcceptanceError,
                    f"not a completed collection.*last event: {last}\\)",
                ):
                    fixture.resume_seal()
                self.assertEqual(
                    {
                        path.name: path.read_bytes()
                        for path in fixture.collection_root.iterdir()
                    },
                    before,
                )
                self.assertFalse(fixture.acceptance.exists())

    def test_resume_seal_refuses_raw_evidence_it_cannot_durably_reopen(self) -> None:
        for case, bound, message in (
            ("group-readable file", ga_runtime.MAX_TOTAL_BYTES, "cannot be durably reopened"),
            ("aggregate bound", 1024, "aggregate byte bound"),
        ):
            with self.subTest(case=case):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                marker = fixture.collection_root / "event-038.json"
                marker.unlink()
                if case == "group-readable file":
                    (fixture.raw_root / "launch.json").chmod(0o644)
                with patch.object(
                    ga_runtime, "MAX_TOTAL_BYTES", bound
                ), self.assertRaisesRegex(GARuntimeAcceptanceError, message):
                    fixture.resume_seal()
                self.assertFalse(marker.exists())
                self.assertFalse(fixture.acceptance.exists())

    def test_resume_seal_requires_the_collection_receipt(self) -> None:
        self.fixture.collection_root.rename(
            self.fixture.collection_root.with_name("moved-runtime-collection")
        )
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError, "has no fixed collection receipt"
        ):
            self.fixture.resume_seal()
        self.assertFalse(self.fixture.collection_root.exists())
        self.assertFalse(self.fixture.acceptance.exists())

    def test_resume_seal_refuses_an_adapter_without_its_marker(self) -> None:
        marker = self.fixture.collection_root / "event-038.json"
        marker.unlink()
        self.fixture.acceptance.write_bytes(b"{}\n")
        self.fixture.acceptance.chmod(0o600)
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError, "before its raw_published marker"
        ):
            self.fixture.resume_seal()
        self.assertFalse(marker.exists())
        self.assertEqual(self.fixture.acceptance.read_bytes(), b"{}\n")

    def test_resume_seal_refuses_a_different_adapter_without_mutation(self) -> None:
        self.fixture.acceptance.write_bytes(b"{}\n")
        self.fixture.acceptance.chmod(0o600)
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "refusing to replace a different immutable GA runtime adapter",
        ):
            self.fixture.resume_seal()
        self.assertEqual(self.fixture.acceptance.read_bytes(), b"{}\n")

    def test_resume_seal_only_reverifies_an_existing_identical_adapter(self) -> None:
        self.fixture.seal()
        before = self.fixture.acceptance.stat()
        events = {
            path.name: path.read_bytes() for path in self.fixture.collection_root.iterdir()
        }
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        after = self.fixture.acceptance.stat()
        self.assertEqual(
            (after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns)
        )
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.fixture.collection_root.iterdir()},
            events,
        )

    def test_raw_published_append_requires_the_exact_post_step_sequence(self) -> None:
        marker = self.fixture.collection_root / "event-038.json"
        original = marker.read_bytes()
        with self.assertRaisesRegex(GARuntimeAcceptanceError, "requires sequence 38"):
            ga_runtime._append_collection_event(
                self.fixture.repository,
                self.fixture.collection_root,
                json.loads(original)["collection"],
                phase="raw_published",
                step="collection",
                expected_sequence=38,
            )
        self.assertFalse((self.fixture.collection_root / "event-039.json").exists())

        # A concurrent collect publishes its marker after resume-seal has
        # classified the 38 step events; resume-seal must not add a second one.
        marker.unlink()
        reopen = ga_runtime._durably_reopen_published_raw

        def collect_wins(repository: Path, raw_root: Path):
            snapshots = reopen(repository, raw_root)
            marker.write_bytes(original)
            marker.chmod(0o600)
            return snapshots

        with patch.object(
            ga_runtime, "_durably_reopen_published_raw", side_effect=collect_wins
        ), self.assertRaisesRegex(GARuntimeAcceptanceError, "requires sequence 38"):
            self.fixture.resume_seal()
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )
        self.assertFalse(self.fixture.acceptance.exists())

    def test_missing_or_unexpected_raw_file_fails_closed(self) -> None:
        (self.fixture.raw_root / "launch.json").unlink()
        with self.assertRaisesRegex(Exception, "missing or unexpected file set"):
            self.fixture.seal()

    def test_tampered_adapter_cannot_be_reused(self) -> None:
        self.fixture.seal()
        document = json.loads(self.fixture.acceptance.read_text(encoding="utf-8"))
        document["product_version"] = "0.4.1"
        self.fixture.acceptance.write_bytes(canonical_json(document))
        self.fixture.acceptance.chmod(0o600)
        with self.assertRaisesRegex(Exception, "differs from reopened raw evidence"):
            self.fixture.validate()

    def test_tampered_collection_receipt_invalidates_the_adapter(self) -> None:
        self.fixture.seal()
        collection = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts)
        event = collection / "event-000.json"
        document = json.loads(event.read_text(encoding="utf-8"))
        document["phase"] = "forged-completed"
        event.write_bytes(canonical_json(document))
        event.chmod(0o600)
        with self.assertRaisesRegex(Exception, "fixed command registry"):
            self.fixture.validate()

    def test_boolean_collection_sequence_invalidates_the_adapter(self) -> None:
        for index, boolean_value in ((0, False), (1, True)):
            with self.subTest(index=index):
                fixture = RuntimeFixture()
                try:
                    collection = fixture.repository.joinpath(
                        *COLLECTION_RELATIVE.parts
                    )
                    event = collection / f"event-{index:03d}.json"
                    document = json.loads(event.read_text(encoding="utf-8"))
                    document["sequence"] = boolean_value
                    event.write_bytes(canonical_json(document))
                    event.chmod(0o600)
                    with self.assertRaisesRegex(
                        GARuntimeAcceptanceError,
                        "collection event identity is invalid",
                    ):
                        fixture.seal()
                finally:
                    fixture.cleanup()

    def test_duplicate_json_key_is_rejected(self) -> None:
        path = self.fixture.raw_root / "launch.json"
        path.write_bytes(
            b'{"check_id":"launch","check_id":"launch","document":"x"}\n'
        )
        path.chmod(0o600)
        with self.assertRaisesRegex(Exception, "repeats JSON field"):
            self.fixture.seal()

    def test_symlink_and_hardlink_evidence_are_rejected(self) -> None:
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                fixture = RuntimeFixture()
                try:
                    source = fixture.raw_root / "launch.json"
                    target = fixture.acceptance.parent / "launch-original.json"
                    source.rename(target)
                    if kind == "symlink":
                        source.symlink_to(Path("..") / target.name)
                    else:
                        os.link(target, source)
                    with self.assertRaisesRegex(Exception, "single-link 0600 file"):
                        fixture.seal()
                finally:
                    fixture.cleanup()

    def test_local_all_passed_summary_cannot_satisfy_a_check(self) -> None:
        self.fixture.documents["launch.json"] = {
            "checks": {name: "passed" for name in CHECKS},
            "document": DOCUMENT,
            "schema_version": 1,
        }
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "unexpected field set"):
            self.fixture.seal()

    def test_v1_runtime_evidence_is_not_accepted_by_the_v2_contract(self) -> None:
        launch = self.fixture.documents["launch.json"]
        launch["document"] = "cfm-ga-runtime-check-v1"
        launch["schema_version"] = 1
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "evidence identity is invalid"):
            self.fixture.seal()

    def test_partial_traffic_without_target_token_is_rejected(self) -> None:
        check_id = "udp_traffic"
        tokens = self.fixture.documents["udp-traffic.json"]["tokens"]
        policy = TRAFFIC_POLICY[check_id]
        capture = pcap_bytes(
            start_marker=tokens["start"].encode("ascii"),
            token=tokens["target"].encode("ascii"),
            end_marker=tokens["end"].encode("ascii"),
            include_token=False,
            protocol="udp",
            family="ipv4",
            local_address="198.18.64.1",
            remote_address=policy["remote_address"],
            local_port=41000,
            remote_port=policy["remote_port"],
            link_type=1,
        )
        # The receipt counts the two records, so the packet proof decides.
        self._replace_capture(check_id, capture)
        self._assert_seal_rejects(
            "udp_traffic packet bytes do not prove the required traffic",
            "required unique token is absent",
        )

    # The exact capture filter for the fixture challenge's dns_traffic tokens
    # (s000-/t000-/e000- plus 32 hex digits, so every first label is 37 bytes):
    # each clause binds the stage prefix and the first eight digest characters
    # s000-96ed7030..., t000-d1f93f86... and e000-a801f52b.... The IPv4 leg
    # loads the label from udp[20]; libpcap's udp[] indexes only IPv4, so the
    # IPv6 leg loads it from ip6[60] behind a UDP next header.
    DNS_CAPTURE_FILTER = (
        "(udp and ((src host 198.18.64.1 and dst host 198.18.64.2 and dst port 53)"
        " or (src host 198.18.64.2 and src port 53 and dst host 198.18.64.1))"
        " and ((udp[20] = 37 and udp[21:4] = 0x73303030"
        " and udp[26:4] = 0x39366564 and udp[30:4] = 0x37303330)"
        " or (udp[20] = 37 and udp[21:4] = 0x74303030"
        " and udp[26:4] = 0x64316639 and udp[30:4] = 0x33663836)"
        " or (udp[20] = 37 and udp[21:4] = 0x65303030"
        " and udp[26:4] = 0x61383031 and udp[30:4] = 0x66353262)))"
        " or (ip6 and ip6[6] = 17"
        " and ((src host 2001:2:0:64::1 and dst host 2001:2:0:64::2 and dst port 53)"
        " or (src host 2001:2:0:64::2 and src port 53 and dst host 2001:2:0:64::1))"
        " and ((ip6[60] = 37 and ip6[61:4] = 0x73303030"
        " and ip6[66:4] = 0x39366564 and ip6[70:4] = 0x37303330)"
        " or (ip6[60] = 37 and ip6[61:4] = 0x74303030"
        " and ip6[66:4] = 0x64316639 and ip6[70:4] = 0x33663836)"
        " or (ip6[60] = 37 and ip6[61:4] = 0x65303030"
        " and ip6[66:4] = 0x61383031 and ip6[70:4] = 0x66353262)))"
    )

    def _reset_fixture(self) -> RuntimeFixture:
        self.fixture = RuntimeFixture()
        self.addCleanup(self.fixture.cleanup)
        return self.fixture

    def _replace_dns_capture(
        self, capture: bytes, families: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Install a DNS capture and, when given, the stage legs it records.

        The capture receipt's statistics count the installed records.
        """

        return self._replace_capture("dns_traffic", capture, families)

    def _replace_capture(
        self,
        check_id: str,
        capture: bytes,
        families: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Install a traffic capture whose receipt counts its records."""

        document = self.fixture.documents[f"{check_id.replace('_', '-')}.json"]
        name = f"{check_id.replace('_', '-')}.pcap"
        self.fixture.pcaps[name] = capture
        document["capture"] = {
            "kind": "packet-pcap",
            "path": name,
            "sha256": sha256_bytes(capture),
            "size": len(capture),
        }
        document["capture_command"]["stderr"] = _tcpdump_stderr(
            capture, document["endpoint"]["interface_name"]
        )
        if families is not None:
            document["endpoint"]["stage_families"] = dict(families)
        return document

    def _assert_seal_rejects(self, message: str, cause: str | None = None) -> None:
        self.fixture.write_all()
        with self.assertRaisesRegex(GARuntimeAcceptanceError, message) as raised:
            self.fixture.seal()
        if cause is not None:
            self.assertIsInstance(raised.exception.__cause__, PacketCaptureError)
            self.assertRegex(str(raised.exception.__cause__), cause)
        self.assertFalse(self.fixture.acceptance.exists())

    def _assert_dns_capture_rejected(
        self,
        packets: list[UtunPacket],
        message: str,
        cause: str | None = None,
        families: dict[str, str] | None = None,
    ) -> None:
        self._reset_fixture()
        self._replace_dns_capture(_utun_udp_pcap(packets), families)
        self._assert_seal_rejects(message, cause)

    def test_dns_traffic_accepts_the_observed_ipv6_tunnel_leg(self) -> None:
        document = self.fixture.documents["dns-traffic.json"]
        capture = self.fixture.pcaps["dns-traffic.pcap"]
        self.assertEqual(struct.unpack_from("<I", capture, 20)[0], UTUN_LINK_TYPE)
        self.assertEqual(
            _utun_dns_headers(capture), [(6, 0x0100), (6, 0x8500)] * 3
        )
        result = self.fixture.seal()
        self.assertEqual(result, self.fixture.validate())
        self.assertEqual(
            document["endpoint"],
            {
                "interface_name": "utun5",
                "link_type": 101,
                "remote_port": 53,
                "stage_families": {"end": "ipv6", "start": "ipv6", "target": "ipv6"},
            },
        )
        self.assertEqual(
            document["capture_command"]["argv"][-5:],
            ["-c", "32", "-w", "-", self.DNS_CAPTURE_FILTER],
        )

    def test_dns_traffic_accepts_a_different_tunnel_leg_per_stage(self) -> None:
        for legs in (
            ("ipv6", "ipv4", "ipv6"),
            ("ipv4", "ipv6", "ipv4"),
            ("ipv4", "ipv4", "ipv6"),
        ):
            with self.subTest(legs=legs):
                fixture = self._reset_fixture()
                families = dict(zip(DNS_STAGES, legs, strict=True))
                tokens = fixture.documents["dns-traffic.json"]["tokens"]
                capture = _utun_udp_pcap(
                    _tunnel_dns_packets(tokens, families=families)
                )
                self.assertEqual(
                    [version for version, _flags in _utun_dns_headers(capture)],
                    [4 if family == "ipv4" else 6 for family in legs for _ in "qr"],
                )
                self._replace_dns_capture(capture, families)
                fixture.write_all()
                self.assertEqual(fixture.seal(), fixture.validate())

    def test_dns_traffic_still_accepts_the_ipv4_tunnel_leg(self) -> None:
        families = dict.fromkeys(DNS_STAGES, "ipv4")
        for link_type in (101, 0):
            with self.subTest(link_type=link_type):
                fixture = self._reset_fixture()
                tokens = fixture.documents["dns-traffic.json"]["tokens"]
                document = self._replace_dns_capture(
                    _utun_udp_pcap(
                        _tunnel_dns_packets(tokens, families=families),
                        link_type=link_type,
                    ),
                    families,
                )
                document["endpoint"]["link_type"] = link_type
                fixture.write_all()
                self.assertEqual(fixture.seal(), fixture.validate())

    def test_dns_traffic_rejects_a_transaction_split_across_legs(self) -> None:
        tokens = self.fixture.documents["dns-traffic.json"]["tokens"]
        for query_family, response_family in (("ipv6", "ipv4"), ("ipv4", "ipv6")):
            with self.subTest(query=query_family, response=response_family):
                families = {**OBSERVED_DNS_FAMILIES, "target": query_family}
                packets = _tunnel_dns_packets(tokens, families=families)
                at, _resolver, _port, _client, client_port, response = packets[3]
                client, resolver = DNS_LEGS[response_family]
                packets[3] = (at, resolver, 53, client, client_port, response)
                self._assert_dns_capture_rejected(
                    packets,
                    "DNS capture endpoints are invalid",
                    "does not answer an earlier query of its token",
                    families,
                )

    def test_dns_traffic_rejects_foreign_ipv6_addresses_and_ports(self) -> None:
        tokens = self.fixture.documents["dns-traffic.json"]["tokens"]

        def target_ports(query_port: int, response_port: int) -> list[UtunPacket]:
            packets = _tunnel_dns_packets(tokens)
            at, client, client_port, resolver, _port, query = packets[2]
            packets[2] = (at, client, client_port, resolver, query_port, query)
            at, resolver, _port, client, client_port, response = packets[3]
            packets[3] = (at, resolver, response_port, client, client_port, response)
            return packets

        off_legs = "DNS capture record is outside the resolver legs"
        cases = (
            (
                "foreign IPv6 client",
                _tunnel_dns_packets(tokens, client="2001:2:0:64::9"),
                "DNS capture endpoints are invalid",
                off_legs,
            ),
            (
                "foreign IPv6 resolver",
                _tunnel_dns_packets(tokens, resolver="2001:2:0:64::3"),
                "DNS capture endpoints are invalid",
                off_legs,
            ),
            (
                "IPv6 resolver port 5353",
                target_ports(5353, 5353),
                "DNS capture endpoints are invalid",
                off_legs,
            ),
            (
                "IPv6 answer from port 5353",
                target_ports(53, 5353),
                "DNS capture endpoints are invalid",
                off_legs,
            ),
        )
        for label, packets, message, cause in cases:
            with self.subTest(label):
                self._assert_dns_capture_rejected(packets, message, cause)

    def test_dns_traffic_rejects_an_aaaa_query_for_a_token(self) -> None:
        tokens = self.fixture.documents["dns-traffic.json"]["tokens"]
        observed = _tunnel_dns_packets(tokens)
        aaaa = _tunnel_dns_transaction(
            tokens["target"],
            "ipv6",
            at=1.05,
            port=DNS_CLIENT_PORTS["target"],
            identifier=0x5A22,
            question_type=28,
        )
        aaaa_elsewhere = _tunnel_dns_transaction(
            tokens["target"],
            "ipv6",
            at=1.05,
            port=53122,
            identifier=0x5A22,
            question_type=28,
        )
        not_a = "required A/AAAA question"
        cases = (
            (
                "AAAA instead of A",
                observed[:2] + aaaa + observed[4:],
                "DNS capture endpoints are invalid",
                not_a,
            ),
            (
                "AAAA beside A on one socket",
                observed + aaaa[:1],
                "DNS capture endpoints are invalid",
                not_a,
            ),
            (
                "AAAA beside A on another socket",
                observed + aaaa_elsewhere,
                "DNS capture endpoints are invalid",
                not_a,
            ),
        )
        for label, packets, message, cause in cases:
            with self.subTest(label):
                self._assert_dns_capture_rejected(packets, message, cause)

    def _assert_dns_capture_accepted(
        self, packets: list[UtunPacket], families: dict[str, str] | None = None
    ) -> None:
        fixture = self._reset_fixture()
        self._replace_dns_capture(_utun_udp_pcap(packets), families)
        fixture.write_all()
        self.assertEqual(fixture.seal(), fixture.validate())

    def test_dns_traffic_accepts_identical_retransmissions_and_leg_failover(self) -> None:
        # The time-stopped capture keeps every query mDNSResponder repeats and
        # every answer libbox relays for a token, on either leg. No case moves
        # the start or end stage's first answer, so the observation window
        # stays the fixture's.
        tokens = self.fixture.documents["dns-traffic.json"]["tokens"]
        observed = _tunnel_dns_packets(tokens)
        target_name = f"{tokens['target']}.evidence.test"
        ipv4_target = _tunnel_dns_transaction(
            tokens["target"], "ipv4", at=1.10, port=53102, identifier=0x5A12
        )
        client, resolver = IPV4_DNS_LEG
        ipv4_start_query = _tunnel_dns_query(0x5A11, f"{tokens['start']}.evidence.test")
        ipv4_start = [
            (0.21, client, 53101, resolver, 53, ipv4_start_query),
            (0.31, resolver, 53, client, 53101, _tunnel_dns_response(ipv4_start_query)),
        ]
        target_on_ipv4 = {**OBSERVED_DNS_FAMILIES, "target": "ipv4"}
        cases = (
            (
                "target query retransmitted, first one answered",
                observed + [_tunnel_dns_retransmission(observed, 2, 1.20)],
                OBSERVED_DNS_FAMILIES,
            ),
            (
                "target query retransmitted, both answered under one ID",
                observed
                + [
                    _tunnel_dns_retransmission(observed, 2, 1.20),
                    _tunnel_dns_retransmission(observed, 3, 1.35),
                ],
                OBSERVED_DNS_FAMILIES,
            ),
            (
                "target query retransmitted under a new ID, both answered",
                observed
                + _tunnel_dns_transaction(
                    tokens["target"],
                    "ipv6",
                    at=1.20,
                    port=DNS_CLIENT_PORTS["target"],
                    identifier=0x5A12,
                ),
                OBSERVED_DNS_FAMILIES,
            ),
            (
                "target query retransmitted from a new socket and ID",
                observed
                + [
                    _tunnel_dns_retransmission(
                        observed,
                        2,
                        1.20,
                        source_port=53102,
                        payload=_tunnel_dns_query(0x5A12, target_name),
                    )
                ],
                OBSERVED_DNS_FAMILIES,
            ),
            # mDNSResponder's failover: the IPv6 query goes unanswered and the
            # same name is asked again of the IPv4 peer.
            (
                "target fails over from IPv6 to IPv4",
                observed[:3] + observed[4:] + ipv4_target,
                target_on_ipv4,
            ),
            (
                "target answered on both legs, IPv4 first",
                observed + ipv4_target,
                target_on_ipv4,
            ),
            (
                "start fails over from IPv6 to IPv4",
                observed[:1] + observed[2:] + ipv4_start,
                {**OBSERVED_DNS_FAMILIES, "start": "ipv4"},
            ),
        )
        for label, packets, families in cases:
            with self.subTest(label):
                self._assert_dns_capture_accepted(packets, families)

    def test_dns_traffic_accepts_late_duplicates_until_the_capture_stops(self) -> None:
        # A stage's resolver can still repeat its query, and libbox still
        # answers, after the stage's sender returned; the collector keeps
        # capturing through its settle. Such records never move a stage's
        # first answered query, the marker window or the response digest.
        tokens = self.fixture.documents["dns-traffic.json"]["tokens"]
        observed = _tunnel_dns_packets(tokens)
        cases = (
            (
                "start answer repeated during the target sender",
                observed + [_tunnel_dns_retransmission(observed, 1, 0.90)],
            ),
            (
                "end query and answer repeated during the settle",
                observed
                + [
                    _tunnel_dns_retransmission(observed, 4, 5.60),
                    _tunnel_dns_retransmission(observed, 5, 5.80),
                ],
            ),
            # The capture receipt ends at 12:00:06; the target sender starts at
            # 12:00:00.5. A record exactly at either bound is inside it.
            (
                "end answer repeated as the capture stops",
                observed + [_tunnel_dns_retransmission(observed, 5, 6.00)],
            ),
            (
                "target query under another ID as its sender starts",
                observed
                + [
                    _tunnel_dns_retransmission(
                        observed,
                        2,
                        0.50,
                        payload=_tunnel_dns_query(0x5A32, f"{tokens['target']}.evidence.test"),
                    )
                ],
            ),
        )
        for label, packets in cases:
            with self.subTest(label):
                self._assert_dns_capture_accepted(packets)

    def test_dns_traffic_rejects_records_identical_retransmission_does_not_admit(
        self,
    ) -> None:
        tokens = self.fixture.documents["dns-traffic.json"]["tokens"]
        observed = _tunnel_dns_packets(tokens)
        client, resolver = IPV6_DNS_LEG
        port = DNS_CLIENT_PORTS["target"]
        target_name = f"{tokens['target']}.evidence.test"
        target_query = observed[2][5]
        # The target query again with an EDNS OPT record (ARCOUNT 1).
        opt_query = (
            struct.pack("!HHHHHH", DNS_QUERY_IDS["target"], 0x0100, 1, 0, 0, 1)
            + target_query[12:]
            + b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"
        )
        # The target answer again, as exact, but with its owner name a
        # pointer to the question instead of written out.
        question = target_query[12:]
        target_answer = observed[3][5]
        compressed_answer = (
            target_answer[: 12 + len(question)]
            + b"\xc0\x0c"
            + target_answer[12 + 2 * len(question) - 4 :]
        )
        cases = (
            (
                "AAAA query for a token name",
                observed
                + [
                    (
                        1.05,
                        client,
                        port,
                        resolver,
                        53,
                        _tunnel_dns_query(0x5A22, target_name, question_type=28),
                    )
                ],
                "required A/AAAA question",
            ),
            (
                "wrong answer address",
                _tunnel_dns_packets(tokens, target_response={"answer": "198.18.0.7"}),
                "answer address differs",
            ),
            (
                "orphan answer",
                observed
                + [
                    (
                        1.35,
                        resolver,
                        53,
                        client,
                        port,
                        _tunnel_dns_response(_tunnel_dns_query(0x5AFF, target_name)),
                    )
                ],
                "does not answer an earlier query of its token",
            ),
            (
                "conflicting second answer",
                observed
                + [
                    _tunnel_dns_retransmission(
                        observed,
                        3,
                        1.35,
                        payload=_tunnel_dns_response(target_query, answer="198.18.0.7"),
                    )
                ],
                "answer address differs",
            ),
            (
                "query with OPT added",
                observed + [_tunnel_dns_retransmission(observed, 2, 1.20, payload=opt_query)],
                "not exact authoritative non-recursive data",
            ),
            (
                "answer repeated with its owner name compressed",
                observed
                + [_tunnel_dns_retransmission(observed, 3, 1.35, payload=compressed_answer)],
                "answers differ beyond their ID",
            ),
            (
                "record of a foreign name",
                observed
                + [(0.50, client, 53100, resolver, 53, _tunnel_dns_query(0x7B01, "www.apple.com"))],
                "names no evidence token",
            ),
            (
                "answer before its query",
                observed[:3] + [_tunnel_dns_retransmission(observed, 3, 0.95)] + observed[4:],
                "does not answer an earlier query of its token",
            ),
            (
                "query repeated with other flags",
                observed
                + [
                    _tunnel_dns_retransmission(
                        observed,
                        2,
                        1.20,
                        payload=_tunnel_dns_query(
                            DNS_QUERY_IDS["target"], target_name, flags=0x0000
                        ),
                    )
                ],
                "queries differ beyond their ID",
            ),
            (
                "token never answered",
                observed[:3] + observed[4:],
                "has no answered query",
            ),
            (
                "query repeated from off the legs",
                observed
                + [_tunnel_dns_retransmission(observed, 2, 1.20, source="2001:2:0:64::9")],
                "outside the resolver legs",
            ),
            # The target answer's own bytes, its ID included, to another port.
            (
                "answer to another client port",
                observed + [_tunnel_dns_retransmission(observed, 3, 1.35, destination_port=53999)],
                "does not answer an earlier query of its token",
            ),
            (
                "query sent from the resolver to the client",
                observed
                + [
                    _tunnel_dns_retransmission(
                        observed,
                        2,
                        1.20,
                        source=resolver,
                        source_port=53,
                        destination=client,
                        destination_port=port,
                    )
                ],
                "direction differs from its resolver leg",
            ),
            (
                "answer at its query's own time",
                observed[:3] + [_tunnel_dns_retransmission(observed, 3, 1.00)] + observed[4:],
                "does not answer an earlier query of its token",
            ),
            ("start stage never asked", observed[2:], "has no exact query"),
            (
                "query repeated to another resolver port",
                observed + [_tunnel_dns_retransmission(observed, 2, 1.20, destination_port=5353)],
                "outside the resolver legs",
            ),
        )
        for label, packets, cause in cases:
            with self.subTest(label):
                self._assert_dns_capture_rejected(
                    packets, "DNS capture endpoints are invalid", cause
                )

    def test_traffic_records_must_lie_between_their_sender_and_the_capture_end(
        self,
    ) -> None:
        # Counted from 12:00:00, as packet times are, the sender receipts run
        # -0.5..0.5 s (start), 0.5..1.5 s (target) and 4.5..5.5 s (end), and
        # the capture receipt ends at 6.0 s.
        tokens = self.fixture.documents["dns-traffic.json"]["tokens"]
        observed = _tunnel_dns_packets(tokens)
        target_name = f"{tokens['target']}.evidence.test"
        cases = (
            (
                "end answer repeated after the capture stopped",
                observed + [_tunnel_dns_retransmission(observed, 5, 6.20)],
                "end",
            ),
            # Another ID, so it is not the target's first answered query.
            (
                "target query before its sender started",
                observed
                + [
                    _tunnel_dns_retransmission(
                        observed, 2, 0.40, payload=_tunnel_dns_query(0x5A32, target_name)
                    )
                ],
                "target",
            ),
        )
        for label, packets, stage in cases:
            with self.subTest(label):
                self._assert_dns_capture_rejected(
                    packets,
                    f"dns_traffic {stage} packets lie outside its sender's start and "
                    "the capture's end",
                )
        with self.subTest("TCP segment repeated after the capture stopped"):
            fixture = self._reset_fixture()
            capture = fixture.pcaps["tcp-traffic.pcap"]
            records = _pcap_records(capture)
            end_seconds, _micros, end = records[2]
            self._replace_capture(
                "tcp_traffic",
                _pcap_with_records(capture, [*records, (end_seconds + 1, 200_000, end)]),
            )
            self._assert_seal_rejects(
                "tcp_traffic end packets lie outside its sender's start and the "
                "capture's end"
            )

    def test_each_stage_event_must_lie_within_its_own_sender(self) -> None:
        # Counted from 12:00:00, the target sender runs 0.5..1.5 s and the end
        # sender starts at 4.5 s. A target event after its sender returned
        # still lies in the marker window, the capture and its stage's span,
        # so only the command and packet timeline refuses it.
        tokens = self.fixture.documents["dns-traffic.json"]["tokens"]
        observed = _tunnel_dns_packets(tokens)
        with self.subTest("DNS target answered after its sender returned"):
            # The target's first matched pair is its 1.0 s query and this answer.
            self._assert_dns_capture_rejected(
                observed[:3] + [_tunnel_dns_retransmission(observed, 3, 2.0)] + observed[4:],
                "dns_traffic command and packet timelines are not causal",
            )
        with self.subTest("UDP target datagram after its sender returned"):
            fixture = self._reset_fixture()
            capture = fixture.pcaps["udp-traffic.pcap"]
            start, (seconds, micros, target), end = _pcap_records(capture)
            self._replace_capture(
                "udp_traffic",
                _pcap_with_records(capture, [start, (seconds + 1, micros, target), end]),
            )
            self._assert_seal_rejects("udp_traffic command and packet timelines are not causal")

    def test_command_and_packet_timeline_orders_every_receipt_and_stage_event(
        self,
    ) -> None:
        # Counted from 12:00:00, the capture receipt runs -1.0..6.0 s, the
        # sender receipts -0.5..0.5 s (start), 0.5..1.5 s (target) and
        # 4.5..5.5 s (end), and each stage's first matched pair lies at
        # 0.00..0.31 s, 1.00..1.29 s and 5.00..5.27 s. Each receipt time below
        # breaks the order with one neighbour only, so the timeline itself
        # refuses it before any check of the stages' record spans.
        cases = (
            ("capture started after the start sender", None, "started_at", "11:59:59.600000"),
            ("start query before its sender started", 0, "started_at", "12:00:00.100000"),
            ("start sender returned before its answer", 0, "finished_at", "12:00:00.200000"),
            (
                "target sender started before the start sender returned",
                1,
                "started_at",
                "12:00:00.400000",
            ),
            ("target query before its sender started", 1, "started_at", "12:00:01.100000"),
            (
                "end sender started before the target sender returned",
                1,
                "finished_at",
                "12:00:04.600000",
            ),
            ("end query before its sender started", 2, "started_at", "12:00:05.100000"),
            ("end sender returned before its answer", 2, "finished_at", "12:00:05.200000"),
            (
                "capture stopped before the end sender returned",
                None,
                "finished_at",
                "12:00:05.400000",
            ),
        )
        for label, stage, field, clock in cases:
            with self.subTest(label):
                fixture = self._reset_fixture()
                document = fixture.documents["dns-traffic.json"]
                receipt = (
                    document["capture_command"]
                    if stage is None
                    else document["send_commands"][stage]
                )
                receipt[field] = f"2026-07-27T{clock}Z"
                self._assert_seal_rejects(
                    "dns_traffic command and packet timelines are not causal"
                )

    def test_tolerant_proof_without_stage_record_spans_fails_closed(self) -> None:
        # The repeats' timeline rests on the harness's stage spans; a proof
        # without them under the tolerant policy is refused, never skipped.
        real = ga_runtime.validate_staged_capture_tokens

        for check_id in ("dns_traffic", "tcp_traffic"):
            protocol = TRAFFIC_POLICY[check_id]["protocol"]

            def without_spans(*arguments: Any, **options: Any) -> Any:
                proof = real(*arguments, **options)
                if options["protocol"] != protocol:
                    return proof
                return dataclasses.replace(proof, stage_record_spans=None)

            with self.subTest(check_id=check_id):
                self._reset_fixture()
                with patch.object(
                    ga_runtime, "validate_staged_capture_tokens", side_effect=without_spans
                ):
                    self._assert_seal_rejects(
                        f"{check_id} packet proof lacks the stage record spans its "
                        "retransmission policy requires"
                    )

    @staticmethod
    def _tcp_frame(
        frame: bytes,
        *,
        source_port: int | None = None,
        sequence: int | None = None,
        payload: bytes | None = None,
    ) -> bytes:
        """Replace a fixture Ethernet/IPv4/TCP frame's source port, sequence or payload."""

        changed = bytearray(frame)
        if source_port is not None:
            changed[34:36] = struct.pack("!H", source_port)
        if sequence is not None:
            changed[38:42] = struct.pack("!I", sequence)
        if payload is not None:
            changed[54:] = payload
            # The IPv4 total length after the 14-byte Ethernet header.
            changed[16:18] = struct.pack("!H", 40 + len(payload))
        return bytes(changed)

    def test_tcp_traffic_accepts_identical_retransmitted_segments(self) -> None:
        for label, stage, delay in (
            ("target segment repeated during its sender", 1, 300_000),
            ("end segment repeated during the settle", 2, 700_000),
        ):
            with self.subTest(label):
                fixture = self._reset_fixture()
                capture = fixture.pcaps["tcp-traffic.pcap"]
                records = _pcap_records(capture)
                seconds, _micros, frame = records[stage]
                self._replace_capture(
                    "tcp_traffic",
                    _pcap_with_records(capture, [*records, (seconds, delay, frame)]),
                )
                fixture.write_all()
                self.assertEqual(fixture.seal(), fixture.validate())

    def test_tcp_traffic_rejects_segments_that_are_not_identical_retransmissions(
        self,
    ) -> None:
        for label, stage, fields, cause in (
            (
                "retransmission carrying other bytes",
                1,
                {"payload": b"t000-" + b"0" * 32},
                "not a stage's data segment",
            ),
            (
                "start token in another flow",
                0,
                {"source_port": 41001},
                "not a stage's data segment",
            ),
            (
                "target token again at another sequence number",
                1,
                {"sequence": 1100},
                "another sequence number",
            ),
        ):
            with self.subTest(label):
                fixture = self._reset_fixture()
                capture = fixture.pcaps["tcp-traffic.pcap"]
                records = _pcap_records(capture)
                seconds, _micros, frame = records[stage]
                self._replace_capture(
                    "tcp_traffic",
                    _pcap_with_records(
                        capture,
                        [*records, (seconds, 300_000, self._tcp_frame(frame, **fields))],
                    ),
                )
                self._assert_seal_rejects(
                    "tcp_traffic packet bytes do not prove the required traffic", cause
                )
        with self.subTest("end stage without its segment"):
            fixture = self._reset_fixture()
            capture = fixture.pcaps["tcp-traffic.pcap"]
            self._replace_capture(
                "tcp_traffic", _pcap_with_records(capture, _pcap_records(capture)[:2])
            )
            self._assert_seal_rejects(
                "tcp_traffic packet bytes do not prove the required traffic",
                "TCP stage has no data segment",
            )

    def _per_stage_tcp_capture(self, fixture: RuntimeFixture) -> bytes:
        """tcp_traffic with each stage on its own connection, as on the device.

        Each sender binds local port 0, so each stage has its own flow; the
        fixture capture shares one. The sender receipts are rewritten to match.
        """

        document = fixture.documents["tcp-traffic.json"]
        tokens = document["tokens"]
        policy = TRAFFIC_POLICY["tcp_traffic"]
        ports = (41001, 41002, 41003)
        for receipt, port in zip(document["send_commands"], ports, strict=True):
            result = json.loads(receipt["stdout"])
            result["local_port"] = port
            receipt["stdout"] = canonical_json(result).decode("utf-8")
        return pcap_bytes(
            start_marker=tokens["start"].encode("ascii"),
            token=tokens["target"].encode("ascii"),
            end_marker=tokens["end"].encode("ascii"),
            include_token=True,
            protocol="tcp",
            family="ipv4",
            local_address=TUNNEL_CLIENT,
            remote_address=policy["remote_address"],
            stage_local_ports=ports,
            remote_port=policy["remote_port"],
            link_type=1,
        )

    def test_tcp_traffic_judges_each_stage_in_its_own_flow(self) -> None:
        with self.subTest("each stage in its own flow, target repeated"):
            fixture = self._reset_fixture()
            capture = self._per_stage_tcp_capture(fixture)
            records = _pcap_records(capture)
            seconds, _micros, target = records[1]
            self._replace_capture(
                "tcp_traffic", _pcap_with_records(capture, [*records, (seconds, 300_000, target)])
            )
            fixture.write_all()
            self.assertEqual(fixture.seal(), fixture.validate())
        with self.subTest("start token in the target's flow"):
            fixture = self._reset_fixture()
            capture = self._per_stage_tcp_capture(fixture)
            records = _pcap_records(capture)
            seconds, _micros, start = records[0]
            self._replace_capture(
                "tcp_traffic",
                _pcap_with_records(
                    capture,
                    [*records, (seconds, 300_000, self._tcp_frame(start, source_port=41002))],
                ),
            )
            self._assert_seal_rejects(
                "tcp_traffic packet bytes do not prove the required traffic",
                "not a stage's data segment",
            )
        # A segment at the target's own sequence number in its own flow
        # repeats it only when it carries exactly the token.
        for label, extend in (
            ("token prefix in the target's flow", lambda token: token[:16]),
            ("token and more in the target's flow", lambda token: token + b"!"),
        ):
            with self.subTest(label):
                fixture = self._reset_fixture()
                capture = self._per_stage_tcp_capture(fixture)
                records = _pcap_records(capture)
                seconds, _micros, target = records[1]
                token = fixture.documents["tcp-traffic.json"]["tokens"]["target"].encode("ascii")
                repeat = self._tcp_frame(target, payload=extend(token))
                self._replace_capture(
                    "tcp_traffic",
                    _pcap_with_records(capture, [*records, (seconds, 300_000, repeat)]),
                )
                self._assert_seal_rejects(
                    "tcp_traffic packet bytes do not prove the required traffic",
                    "not a stage's data segment",
                )

    def test_udp_traffic_still_rejects_a_duplicate_datagram(self) -> None:
        # Nothing retransmits a UDP datagram, so UDP keeps one per stage.
        capture = self.fixture.pcaps["udp-traffic.pcap"]
        records = _pcap_records(capture)
        seconds, _micros, frame = records[1]
        self._replace_capture(
            "udp_traffic", _pcap_with_records(capture, [*records, (seconds, 200_000, frame)])
        )
        self._assert_seal_rejects("udp_traffic packet proof is partial or has extra traffic")

    def test_capture_receipt_statistic_must_count_the_pcap_below_the_cap(self) -> None:
        receipt = self.fixture.documents["dns-traffic.json"]["capture_command"]
        self.assertIn("\n6 packets captured\n", receipt["stderr"])
        lacks = "dns_traffic tcpdump output lacks a capture receipt"
        cases = (
            ("no statistic", "\n6 packets captured\n", "\n", lacks),
            (
                "two statistics",
                "\n6 packets captured\n",
                "\n6 packets captured\n6 packets captured\n",
                lacks,
            ),
            (
                "statistic differs from the pcap",
                "\n6 packets captured\n",
                "\n7 packets captured\n",
                "dns_traffic tcpdump captured 7 packets but its pcap holds 6 records",
            ),
            (
                "cap reached",
                "\n6 packets captured\n",
                "\n32 packets captured\n",
                "dns_traffic tcpdump reached its 32-packet cap: extra traffic",
            ),
            # The rules for repeated packets judge every matching packet, so
            # one the kernel dropped before tcpdump read it fails the capture.
            (
                "matching packet dropped by the kernel",
                "\n0 packets dropped by kernel\n",
                "\n1 packet dropped by kernel\n",
                "dns_traffic tcpdump reports 1 matching packets dropped by the kernel",
            ),
            (
                "no kernel drop statistic",
                "\n0 packets dropped by kernel\n",
                "\n",
                lacks,
            ),
            (
                "statistic with more on its line",
                "\n6 packets captured\n",
                "\n6 packets captured, 6 packets received by filter\n",
                lacks,
            ),
        )
        for label, old, new, message in cases:
            with self.subTest(label):
                fixture = self._reset_fixture()
                document = fixture.documents["dns-traffic.json"]
                stderr = document["capture_command"]["stderr"]
                document["capture_command"]["stderr"] = stderr.replace(old, new)
                self._assert_seal_rejects(message)
        with self.subTest("cap reached beside a record of a foreign name"):
            # tcpdump's own receipt is judged before the packets it wrote.
            fixture = self._reset_fixture()
            observed = _tunnel_dns_packets(fixture.documents["dns-traffic.json"]["tokens"])
            client, resolver = IPV6_DNS_LEG
            document = self._replace_dns_capture(
                _utun_udp_pcap(
                    observed
                    + [(0.50, client, 53100, resolver, 53, _tunnel_dns_query(0x7B01, "www.apple.com"))]
                )
            )
            stderr = document["capture_command"]["stderr"]
            document["capture_command"]["stderr"] = stderr.replace(
                "\n7 packets captured\n", "\n32 packets captured\n"
            )
            self._assert_seal_rejects(
                "dns_traffic tcpdump reached its 32-packet cap: extra traffic"
            )

    def test_traffic_policy_counts_records_only_for_exact_checks(self) -> None:
        self.assertEqual(
            {check_id: policy["retransmissions"] for check_id, policy in TRAFFIC_POLICY.items()},
            {
                "dns_traffic": RetransmissionPolicy.IDENTICAL_RETRANSMISSIONS,
                "tcp_traffic": RetransmissionPolicy.IDENTICAL_RETRANSMISSIONS,
                "udp_traffic": RetransmissionPolicy.EXACT,
            },
        )
        for check_id, policy in TRAFFIC_POLICY.items():
            with self.subTest(check_id=check_id):
                self.assertEqual(
                    "expected_records" in policy,
                    policy["retransmissions"] is RetransmissionPolicy.EXACT,
                )
        self.assertEqual(TRAFFIC_POLICY["udp_traffic"]["expected_records"], 3)

    def test_capture_argv_stops_every_check_at_the_fixed_cap(self) -> None:
        # The cap bounds the pcap file at the full snapshot length.
        self.assertEqual(ga_runtime.CAPTURE_PACKET_CAP, 32)
        self.assertLessEqual(
            24 + ga_runtime.CAPTURE_PACKET_CAP * (16 + ga_runtime.MAX_SNAPLEN),
            ga_runtime.MAX_PCAP_BYTES,
        )
        for check_id in TRAFFIC_CHECKS:
            with self.subTest(check_id=check_id):
                argv = self.fixture.documents[f"{check_id.replace('_', '-')}.json"][
                    "capture_command"
                ]["argv"]
                self.assertEqual(argv[argv.index("-c") + 1], "32")
                self.assertEqual(argv.count("-c"), 1)
                # libpcap hands each packet to tcpdump as it arrives instead
                # of holding it for its read timeout.
                self.assertEqual(argv.count("--immediate-mode"), 1)
                self.assertLess(argv.index("--immediate-mode"), argv.index("-i"))

    def test_dns_endpoint_records_each_stage_leg_from_the_capture(self) -> None:
        fixed = "dns_traffic endpoint differs from the fixed capture policy"
        cases = (
            (
                "one stage misrecorded",
                {"stage_families": {"end": "ipv6", "start": "ipv6", "target": "ipv4"}},
                GARuntimeAcceptanceError,
                "dns_traffic DNS stage families differ from the capture",
            ),
            (
                "dual family",
                {"stage_families": {"end": "ipv6", "start": "ipv6", "target": "dual"}},
                GARuntimeAcceptanceError,
                fixed,
            ),
            (
                "numeric family",
                {"stage_families": {"end": "ipv6", "start": "ipv6", "target": 6}},
                GARuntimeAcceptanceError,
                fixed,
            ),
            (
                "missing stage",
                {"stage_families": {"start": "ipv6", "target": "ipv6"}},
                PublicationError,
                "dns_traffic stage families has an unexpected field set",
            ),
            (
                "one family for every stage",
                {"stage_families": "ipv6"},
                PublicationError,
                "dns_traffic stage families has an unexpected field set",
            ),
            (
                "former single-family endpoint",
                {
                    "family": "ipv4",
                    "local_address": TUNNEL_CLIENT,
                    "remote_address": TUNNEL_DNS_PEER,
                },
                PublicationError,
                "dns_traffic endpoint has an unexpected field set",
            ),
            ("resolver port", {"remote_port": 5353}, GARuntimeAcceptanceError, fixed),
            ("resolver port text", {"remote_port": "53"}, GARuntimeAcceptanceError, fixed),
            # 53.0 == 53, 101.0 == 101 and True == 1 (Ethernet): only the
            # exact integer type rejects them.
            ("resolver port float", {"remote_port": 53.0}, GARuntimeAcceptanceError, fixed),
            ("link type", {"link_type": 102}, GARuntimeAcceptanceError, fixed),
            ("link type float", {"link_type": 101.0}, GARuntimeAcceptanceError, fixed),
            ("link type boolean", {"link_type": True}, GARuntimeAcceptanceError, fixed),
            ("interface", {"interface_name": "lo0"}, GARuntimeAcceptanceError, fixed),
        )
        for label, fields, error, message in cases:
            with self.subTest(label):
                fixture = self._reset_fixture()
                fixture.documents["dns-traffic.json"]["endpoint"].update(fields)
                fixture.write_all()
                with self.assertRaisesRegex(error, message):
                    fixture.seal()
                self.assertFalse(fixture.acceptance.exists())

    def test_dns_traffic_rejects_the_upstream_vantage_shape(self) -> None:
        upstream = "34.80.107.183"
        with self.subTest(shape="pre-fix upstream document"):
            document = self.fixture.documents["dns-traffic.json"]
            tokens = document["tokens"]
            self._replace_dns_capture(
                pcap_bytes(
                    start_marker=tokens["start"].encode("ascii"),
                    token=tokens["target"].encode("ascii"),
                    end_marker=tokens["end"].encode("ascii"),
                    include_token=True,
                    protocol="dns",
                    family="ipv4",
                    local_address=TUNNEL_CLIENT,
                    remote_address=upstream,
                    local_port=41000,
                    remote_port=53,
                    link_type=1,
                )
            )
            document["endpoint"] = {
                "family": "ipv4",
                "interface_name": "en0",
                "link_type": 1,
                "local_address": TUNNEL_CLIENT,
                "remote_address": upstream,
                "remote_port": 53,
            }
            document["capture_command"]["argv"] = ga_runtime._capture_command_argv(
                "en0", ("udp", "and", "port", "53")
            )
            document["observation_ms"] = 5000
            self.fixture.write_all()
            with self.assertRaisesRegex(
                PublicationError, "dns_traffic endpoint has an unexpected field set"
            ):
                self.fixture.seal()
            self.assertFalse(self.fixture.acceptance.exists())
        with self.subTest(shape="upstream capture command on en0"):
            fixture = self._reset_fixture()
            document = fixture.documents["dns-traffic.json"]
            document["endpoint"].update(interface_name="en0", link_type=1)
            document["capture_command"]["argv"] = ga_runtime._capture_command_argv(
                "en0", ("udp", "and", "port", "53")
            )
            self._assert_seal_rejects(
                "dns_traffic packet capture command command identity"
            )
        with self.subTest(shape="upstream packets under the tunnel endpoint"):
            families = dict.fromkeys(DNS_STAGES, "ipv4")
            self._assert_dns_capture_rejected(
                _tunnel_dns_packets(tokens, families=families, resolver=upstream),
                "DNS capture endpoints are invalid",
                "DNS capture record is outside the resolver legs",
                families,
            )

    def test_dns_traffic_rejects_interleaved_unrelated_resolver_traffic(self) -> None:
        for family in ("ipv6", "ipv4"):
            with self.subTest(unrelated_leg=family):
                self._assert_unrelated_resolver_traffic_rejected(family)

    def _assert_unrelated_resolver_traffic_rejected(self, family: str) -> None:
        query = _tunnel_dns_query(0x7B01, "www.apple.com")
        client, resolver = DNS_LEGS[family]
        unrelated = [
            (0.50, client, 53100, resolver, 53, query),
            (
                0.56,
                resolver,
                53,
                client,
                53100,
                _tunnel_dns_response(
                    query, flags=0x8180, answer="17.253.144.10", ttl=60
                ),
            ),
        ]
        # Packets are start, target and end query/response pairs in order.
        # The unrelated answer sets RA, so it is not an exact evidence answer;
        # its query alone names no token.
        cases = (
            (
                "interleaved pair",
                lambda packets: packets + unrelated,
                "DNS capture endpoints are invalid",
                "not exact authoritative non-recursive data",
            ),
            (
                "pair displaced the end transaction",
                lambda packets: packets[:4] + unrelated,
                "DNS capture endpoints are invalid",
                "not exact authoritative non-recursive data",
            ),
            (
                "query displaced the end response",
                lambda packets: packets[:5] + unrelated[:1],
                "DNS capture endpoints are invalid",
                "names no evidence token",
            ),
        )
        for label, shape, message, cause in cases:
            with self.subTest(label):
                fixture = self._reset_fixture()
                tokens = fixture.documents["dns-traffic.json"]["tokens"]
                self._replace_dns_capture(
                    _utun_udp_pcap(shape(_tunnel_dns_packets(tokens)))
                )
                self._assert_seal_rejects(message, cause)

    def test_dns_traffic_rejects_synthesized_fakeip_or_non_echo_answers(self) -> None:
        unproven = "DNS capture endpoints are invalid"
        cases = (
            (
                "libbox synthesized answer sets RA",
                {"target_response": {"flags": 0x8580}},
                unproven,
                "not exact authoritative non-recursive data",
            ),
            (
                "FakeIP answer",
                {"target_response": {"answer": "198.18.0.7"}},
                unproven,
                "answer address differs",
            ),
            (
                "cached TTL",
                {"target_response": {"ttl": 600}},
                unproven,
                "TTL",
            ),
            (
                "RD is not echoed",
                {"target_response": {"flags": 0x8400}},
                unproven,
                "not causal and exact",
            ),
            (
                "query sets AD",
                {"target_query_flags": 0x0120},
                "DNS capture endpoints are invalid",
                "not exact authoritative non-recursive data",
            ),
        )
        for label, shape, message, cause in cases:
            with self.subTest(label):
                fixture = self._reset_fixture()
                tokens = fixture.documents["dns-traffic.json"]["tokens"]
                self._replace_dns_capture(
                    _utun_udp_pcap(_tunnel_dns_packets(tokens, **shape))
                )
                self._assert_seal_rejects(message, cause)

    def test_dns_sender_must_return_exactly_the_evidence_answer(self) -> None:
        for addresses in (["198.18.0.7"], ["192.0.2.1", "198.18.0.7"], []):
            with self.subTest(addresses=addresses):
                fixture = self._reset_fixture()
                receipt = fixture.documents["dns-traffic.json"]["send_commands"][1]
                result = json.loads(receipt["stdout"])
                result["dns_result"]["query"]["addresses"] = addresses
                receipt["stdout"] = canonical_json(result).decode("utf-8")
                self._assert_seal_rejects(
                    "dns_traffic target getaddrinfo did not return the evidence answer"
                )

    def test_tunnel_dns_capture_filter_is_exact(self) -> None:
        tokens = RuntimeFixture._traffic_tokens("dns_traffic")
        self.assertEqual(
            ga_runtime._traffic_capture_filter_argv("dns_traffic", tokens),
            (self.DNS_CAPTURE_FILTER,),
        )
        self.assertEqual(_expected_tunnel_dns_filter(tokens), (self.DNS_CAPTURE_FILTER,))
        for check_id in ("tcp_traffic", "udp_traffic"):
            with self.subTest(check_id=check_id):
                tokens = RuntimeFixture._traffic_tokens(check_id)
                self.assertEqual(
                    ga_runtime._traffic_capture_filter_argv(check_id, tokens),
                    packet_capture_filter_argv(
                        case_id=TRAFFIC_POLICY[check_id]["case_id"],
                        tokens=(tokens["start"], tokens["target"], tokens["end"]),
                    ),
                )

    def test_tunnel_dns_filter_rejects_non_label_tokens(self) -> None:
        tokens = RuntimeFixture._traffic_tokens("dns_traffic")
        not_label = "not single DNS evidence labels"
        cases = (
            ("target", "t000.0123456789abcdef", not_label),
            ("target", tokens["target"].upper(), not_label),
            ("target", "t000-" + "a" * 59, not_label),
            ("target", "t000_0123456789abcdef", not_label),
            ("target", "t000:0123456789abcdef", not_label),
            ("end", "e000-0123456789abcde-", not_label),
            # One lowercase label, but not the derived prefix-dash-digest shape
            # whose fixed offsets the filter loads.
            ("target", "t000-0123456789abcdef", not_label),
            ("target", "t000-" + "g" * 32, not_label),
            ("target", "t000x" + tokens["target"][5:], not_label),
            ("target", "t00-" + tokens["target"][4:], not_label),
            ("target", "s000" + tokens["target"][4:], "prefixes are not unique"),
        )
        for stage, token, message in cases:
            with self.subTest(stage=stage, token=token):
                candidate = {**tokens, stage: token}
                # Each candidate is an admitted GA token; only the DNS label
                # rule can keep it out of the BPF expression.
                self.assertEqual(ga_runtime._tokens(candidate, "dns_traffic"), candidate)
                with self.assertRaisesRegex(GARuntimeAcceptanceError, message):
                    ga_runtime._traffic_capture_filter_argv("dns_traffic", candidate)

    def test_tunnel_dns_filter_binds_this_collection_digests(self) -> None:
        tokens = RuntimeFixture._traffic_tokens("dns_traffic")
        other_challenge = base64.urlsafe_b64encode(b"D" * 32).decode("ascii").rstrip("=")
        other = {
            stage: _derive_capture_token(other_challenge, "dns_traffic", stage)
            for stage in DNS_STAGES
        }
        # Another challenge keeps every stage prefix and label length, so only
        # the digest words can keep its token names out of this capture.
        self.assertEqual(
            [(token[:5], len(token)) for token in tokens.values()],
            [(token[:5], len(token)) for token in other.values()],
        )
        (expression,) = ga_runtime._traffic_capture_filter_argv("dns_traffic", tokens)
        (other_expression,) = ga_runtime._traffic_capture_filter_argv("dns_traffic", other)
        for own, foreign in zip(tokens.values(), other.values(), strict=True):
            # The IPv4 leg's label starts at udp[20], the IPv6 leg's at ip6[60].
            for layer, label in (("udp", 20), ("ip6", 60)):
                with self.subTest(token=own, layer=layer):
                    for offset, start in ((label + 6, 5), (label + 10, 9)):
                        own_word = (
                            f"{layer}[{offset}:4] = "
                            f"0x{own[start:start + 4].encode('ascii').hex()}"
                        )
                        foreign_word = (
                            f"{layer}[{offset}:4] = "
                            f"0x{foreign[start:start + 4].encode('ascii').hex()}"
                        )
                        self.assertNotEqual(own_word, foreign_word)
                        self.assertIn(own_word, expression)
                        self.assertNotIn(foreign_word, expression)
                        self.assertIn(foreign_word, other_expression)

    def test_tunnel_dns_capture_filter_selects_only_this_collections_dns(
        self,
    ) -> None:
        # The string checks above share the filter's structure, so a valid
        # expression that loads the wrong bytes passes them; the former
        # udp[20] form matched no IPv6 datagram. This runs the exact
        # expression through the system tcpdump, offline.
        tokens = RuntimeFixture._traffic_tokens("dns_traffic")
        other_challenge = base64.urlsafe_b64encode(b"D" * 32).decode("ascii").rstrip("=")
        other = {
            stage: _derive_capture_token(other_challenge, "dns_traffic", stage)
            for stage in DNS_STAGES
        }
        (expression,) = ga_runtime._traffic_capture_filter_argv("dns_traffic", tokens)
        admitted = _tunnel_dns_packets(
            tokens, families={"start": "ipv6", "target": "ipv4", "end": "ipv6"}
        )
        foreign_hosts = {
            "ipv4": ("198.18.64.9", "198.18.64.3"),
            "ipv6": ("2001:2:0:64::9", "2001:2:0:64::3"),
        }
        rejected: list[UtunPacket] = []
        for family, (client, resolver) in DNS_LEGS.items():
            foreign_client, foreign_resolver = foreign_hosts[family]
            for index, (source, source_port, destination, destination_port, name) in enumerate(
                (
                    (client, 54001, resolver, 5353, tokens["start"]),
                    (client, 53, resolver, 54002, tokens["start"]),
                    (foreign_client, 54003, resolver, 53, tokens["target"]),
                    (client, 54004, foreign_resolver, 53, tokens["end"]),
                    (client, 54005, resolver, 53, other["target"]),
                    (client, 54006, resolver, 53, "www.apple.com"),
                )
            ):
                if name != "www.apple.com":
                    name = f"{name}.evidence.test"
                query = _tunnel_dns_query(0x6B00 + index, name)
                at = 0.5 + index / 10
                rejected.append((at, source, source_port, destination, destination_port, query))
                rejected.append(
                    (at + 0.05, destination, destination_port, source, source_port,
                     _tunnel_dns_response(query))
                )
        # The upstream leg libbox sends outside the tunnel.
        upstream = _tunnel_dns_query(0x6C00, f"{tokens['target']}.evidence.test")
        rejected.append((1.5, "192.168.1.10", 54010, "34.80.107.183", 53, upstream))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        def tcpdump(name: str, capture: bytes, bpf: str) -> bytes:
            # Apple's tcpdump refuses a pcap on a pipe as an unknown file
            # format, so it reads a file.
            capture_path = Path(temporary.name) / name
            capture_path.write_bytes(capture)
            completed = subprocess.run(
                ["/usr/sbin/tcpdump", "-n", "-r", str(capture_path), "-w", "-", bpf],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return completed.stdout

        for link_type in (UTUN_LINK_TYPE, 0):
            with self.subTest(link_type=link_type):
                capture = _utun_udp_pcap(admitted + rejected, link_type=link_type)
                name = f"link-type-{link_type}.pcap"
                # "udp" admits every datagram on both families, which shows the
                # system tcpdump reads each fixture record.
                every = _utun_udp_datagrams(tcpdump(name, capture, "udp"))
                self.assertEqual(every, _utun_udp_datagrams(capture))
                self.assertEqual(len(every), len(admitted) + len(rejected))
                self.assertEqual(
                    _utun_udp_datagrams(tcpdump(name, capture, expression)),
                    _utun_udp_datagrams(_utun_udp_pcap(admitted, link_type=link_type)),
                )
        with self.subTest("IPv6 Hop-by-Hop header"):
            # RELEASE.md: a token query behind an IPv6 extension header is not
            # captured, so the live capture times out and fails closed.
            capture = _utun_udp_pcap(_tunnel_dns_packets(tokens), ipv6_hop_by_hop=True)
            # "ip6" reads all six records; the token filter writes only the
            # pcap file header.
            self.assertEqual(tcpdump("hop-by-hop.pcap", capture, "ip6"), capture)
            self.assertEqual(tcpdump("hop-by-hop.pcap", capture, expression), capture[:24])

    def test_tunnel_addresses_match_the_cross_language_contract(self) -> None:
        plan = json.loads(
            (REPOSITORY / "contracts/tunnel-address-plan-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            TUNNEL_CAPTURE_LOCAL_ADDRESSES,
            {"ipv4": plan["ipv4Address"], "ipv6": plan["ipv6Address"]},
        )
        self.assertEqual(
            (ga_runtime.TUNNEL_DNS_PEER_IPV4, ga_runtime.TUNNEL_DNS_PEER_IPV6),
            (plan["ipv4DnsPeer"], plan["ipv6DnsPeer"]),
        )
        self.assertEqual(
            ga_runtime.TUNNEL_DNS_LEGS,
            (
                DnsResolverLeg(plan["ipv4Address"], plan["ipv4DnsPeer"]),
                DnsResolverLeg(plan["ipv6Address"], plan["ipv6DnsPeer"]),
            ),
        )
        # The DNS policy names no single resolver; its legs come from the plan.
        self.assertNotIn("remote_address", TRAFFIC_POLICY["dns_traffic"])
        self.assertEqual(
            (IPV4_DNS_LEG, IPV6_DNS_LEG),
            (
                (plan["ipv4Address"], plan["ipv4DnsPeer"]),
                (plan["ipv6Address"], plan["ipv6DnsPeer"]),
            ),
        )

    def test_dns_queries_must_originate_from_the_tunnel_client(self) -> None:
        tokens = self.fixture.documents["dns-traffic.json"]["tokens"]
        for family, client in (("ipv4", "198.18.64.9"), ("ipv6", "2001:2:0:64::9")):
            with self.subTest("foreign DNS client", family=family):
                families = dict.fromkeys(DNS_STAGES, family)
                self._assert_dns_capture_rejected(
                    _tunnel_dns_packets(tokens, families=families, client=client),
                    "DNS capture endpoints are invalid",
                    "DNS capture record is outside the resolver legs",
                    families,
                )
        cases = (
            ("tcp_traffic", "local_address", "10.0.0.5"),
            ("tcp_traffic", "local_address", int(ipaddress.ip_address(TUNNEL_CLIENT))),
            ("dns_traffic", "remote_port", 5353),
        )
        for check_id, field, value in cases:
            with self.subTest(check_id=check_id, field=field, value=value):
                fixture = self._reset_fixture()
                name = f"{check_id.replace('_', '-')}.json"
                fixture.documents[name]["endpoint"][field] = value
                self._assert_seal_rejects(
                    f"{check_id} endpoint differs from the fixed capture policy"
                )

    def test_traffic_requires_authenticated_candidate_tunnel_state(self) -> None:
        traffic = self.fixture.documents["tcp-traffic.json"]
        traffic["host_observation"]["test"]["owner"] = "proxy_agent"
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "ready Packet Tunnel observation"):
            self.fixture.seal()

    def test_network_extension_binding_cannot_forge_a_passed_summary(self) -> None:
        network = self.fixture.documents["network-extension.json"]
        network["traffic_bindings"] = {"all_passed": True}
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "unexpected field set"):
            self.fixture.seal()

    def test_packet_host_session_cannot_be_replayed_across_checks(self) -> None:
        tcp = self.fixture.documents["tcp-traffic.json"]["host_observation"]
        udp = self.fixture.documents["udp-traffic.json"]["host_observation"]
        udp["session_id"] = tcp["session_id"]
        network = self.fixture.documents["network-extension.json"]
        network["traffic_bindings"]["udp_traffic"][
            "host_observation_sha256"
        ] = sha256_bytes(canonical_json(udp))
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "reuse an authenticated Packet Host session"):
            self.fixture.seal()

    def test_credential_scan_fails_without_echoing_secret(self) -> None:
        secret = "-----BEGIN PRIVATE KEY-----fixture-private-material"
        launch = self.fixture.documents["launch.json"]
        launch["process_observation"]["stderr"] = secret
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "credential-like material") as captured:
            self.fixture.seal()
        self.assertNotIn(secret, str(captured.exception))

    def test_output_bound_is_enforced(self) -> None:
        launch = self.fixture.documents["launch.json"]
        launch["process_observation"]["stderr"] = "x" * (256 * 1024 + 1)
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "bounded UTF-8 command output"):
            self.fixture.seal()

    def test_before_after_cfw_state_drift_is_rejected(self) -> None:
        shutdown = self.fixture.documents["shutdown-restore.json"]
        shutdown["after_guard"]["proxy_sha256"] = "e" * 64
        legacy = self.fixture.documents["legacy-cfw-preserved.json"]
        legacy["after_guard"] = copy.deepcopy(shutdown["after_guard"])
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "restore the exact pre-run CFW state"):
            self.fixture.seal()

    def test_shutdown_allows_recommissioned_service_process_only_with_off_proof(self) -> None:
        shutdown = self.fixture.documents["shutdown-restore.json"]
        shutdown["process_observation"]["stdout"] += (
            "201 501 Mon Jul 27 12:00:07 2026 "
            "/Applications/Clash for Mac.app/Contents/Library/LoginItems/"
            "CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent\n"
        )
        self.fixture.write_all()
        self.fixture.seal()
        shutdown["off_proof_command"]["stdout"] = ""
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "did not prove the candidate globally Off"):
            self.fixture.seal()

    def test_shutdown_observations_must_follow_one_another(self) -> None:
        # The Host is seen gone (12:00:07..08), then the one signed Off proof
        # runs (08..09), then the final process table (09..10). An Off proof
        # that starts before the Host was seen gone, or a final table taken
        # before the proof returned, does not show that order.
        for label, name, started_at in (
            (
                "Off proof before the Host was seen gone",
                "off_proof_command",
                "2026-07-27T12:00:07.500000Z",
            ),
            (
                "final process table during the Off proof",
                "process_observation",
                "2026-07-27T12:00:08.500000Z",
            ),
        ):
            with self.subTest(label):
                fixture = self._reset_fixture()
                fixture.documents["shutdown-restore.json"][name]["started_at"] = started_at
                self._assert_seal_rejects(
                    "candidate shutdown, Off proof, and Host process observations are not "
                    "causal"
                )

    def test_shutdown_restore_requires_the_exact_operator_quit_instruction(self) -> None:
        shutdown = self.fixture.documents["shutdown-restore.json"]
        self.assertEqual(shutdown["shutdown_request"], OPERATOR_QUIT_REQUEST)
        legacy_receipt = command(
            list(LEGACY_APPLE_EVENT_QUIT),
            started_at="2026-07-27T12:00:06Z",
            finished_at="2026-07-27T12:00:07Z",
        )
        document_shape = "shutdown_restore evidence has an unexpected field set"
        record_shape = "candidate shutdown request has an unexpected field set"
        record_value = "candidate shutdown request is not the fixed operator quit instruction"
        cases = {
            "the retired AppleEvent receipt": (
                lambda document: (
                    document.pop("shutdown_request"),
                    document.__setitem__("shutdown_command", legacy_receipt),
                ),
                document_shape,
            ),
            "an AppleEvent receipt beside the record": (
                lambda document: document.__setitem__(
                    "shutdown_command", legacy_receipt
                ),
                document_shape,
            ),
            "no shutdown request": (
                lambda document: document.pop("shutdown_request"),
                document_shape,
            ),
            "an AppleEvent receipt as the request": (
                lambda document: document.__setitem__(
                    "shutdown_request", copy.deepcopy(legacy_receipt)
                ),
                record_shape,
            ),
            "a request that is not an object": (
                lambda document: document.__setitem__(
                    "shutdown_request", OPERATOR_QUIT_INSTRUCTION
                ),
                record_shape,
            ),
            "a request without its kind": (
                lambda document: document["shutdown_request"].pop("kind"),
                record_shape,
            ),
            "a request with an extra observation": (
                lambda document: document["shutdown_request"].__setitem__(
                    "observed_at", "2026-07-27T12:00:06Z"
                ),
                record_shape,
            ),
            "a different instruction": (
                lambda document: document["shutdown_request"].__setitem__(
                    "instruction",
                    OPERATOR_QUIT_INSTRUCTION.partition(";")[0],
                ),
                record_value,
            ),
            "the retired instruction that forbade the app's own Force Quit": (
                lambda document: document["shutdown_request"].__setitem__(
                    "instruction",
                    OPERATOR_QUIT_INSTRUCTION.partition(";")[0]
                    + "; do not quit it from the Dock, AppleScript, Activity "
                    "Monitor or Force Quit",
                ),
                record_value,
            ),
            "an AppleEvent kind": (
                lambda document: document["shutdown_request"].__setitem__(
                    "kind", "apple_event_quit"
                ),
                record_value,
            ),
            "the retired kind that named a quit path": (
                lambda document: document["shutdown_request"].__setitem__(
                    "kind", "operator_menu_quit"
                ),
                record_value,
            ),
        }
        for label, (mutate, message) in cases.items():
            with self.subTest(label):
                self.fixture.documents["shutdown-restore.json"] = copy.deepcopy(shutdown)
                mutate(self.fixture.documents["shutdown-restore.json"])
                self.fixture.write_all()
                with self.assertRaisesRegex(Exception, message):
                    self.fixture.seal()
                self.assertFalse(self.fixture.acceptance.exists())
        self.fixture.documents["shutdown-restore.json"] = shutdown
        self.fixture.write_all()
        self.fixture.seal()

    def _service_stdout(self, service: str) -> str:
        commands = self.fixture.documents["service-registration.json"]["commands"]
        return commands[service]["stdout"]

    def _set_service_stdout(self, service: str, stdout: str) -> None:
        commands = self.fixture.documents["service-registration.json"]["commands"]
        commands[service]["stdout"] = stdout
        self.fixture.write_all()

    def test_service_registration_rejects_a_different_parent_bundle_build(self) -> None:
        original = self._service_stdout("proxy_agent")
        for build in (
            "40041", "40043", "40044", "40045", "40046", "40047", "40048", "40067",
            # Services still registered by the replaced predecessor.
            FROM_BUILD,
            NEXT_GA_BUILD,
        ):
            with self.subTest(build=build):
                self._set_service_stdout(
                    "proxy_agent",
                    original.replace(
                        f"parent bundle version = {TO_BUILD}",
                        f"parent bundle version = {build}",
                    ),
                )
                with self.assertRaisesRegex(
                    GARuntimeAcceptanceError,
                    "does not show the fixed running ProxyAgent",
                ):
                    self.fixture.seal()

    def test_service_registration_rejects_a_foreign_program_identifier(self) -> None:
        self._set_service_stdout(
            "global_authority",
            self._service_stdout("global_authority").replace(
                "program identifier = Contents/Library/HelperTools/"
                "CFWGlobalAuthority (mode: 2)",
                "program identifier = Contents/Library/HelperTools/"
                "CFWGlobalAuthorityOld (mode: 2)",
            ),
        )
        with self.assertRaisesRegex(
            Exception, "does not show the fixed running GlobalAuthority"
        ):
            self.fixture.seal()

    def test_service_registration_rejects_a_job_that_is_not_running(self) -> None:
        self._set_service_stdout(
            "proxy_agent",
            self._service_stdout("proxy_agent").replace(
                "state = running",
                "state = not running",
            ),
        )
        with self.assertRaisesRegex(
            Exception, "does not show the fixed running ProxyAgent"
        ):
            self.fixture.seal()

    def test_service_registration_rejects_a_foreign_parent_bundle(self) -> None:
        self._set_service_stdout(
            "global_authority",
            self._service_stdout("global_authority").replace(
                "parent bundle identifier = com.bill.clashformac",
                "parent bundle identifier = com.example.other",
            ),
        )
        with self.assertRaisesRegex(
            Exception, "does not show the fixed running GlobalAuthority"
        ):
            self.fixture.seal()

    def test_service_registration_rejects_a_foreign_signing_team(self) -> None:
        self._set_service_stdout(
            "proxy_agent",
            self._service_stdout("proxy_agent").replace(
                '"team-identifier" => "YKUPL7Z869"',
                '"team-identifier" => "AAAAAAAAAA"',
            ),
        )
        with self.assertRaisesRegex(
            Exception, "does not show the fixed running ProxyAgent"
        ):
            self.fixture.seal()

    def test_service_registration_rejects_a_foreign_signing_identifier(self) -> None:
        self._set_service_stdout(
            "global_authority",
            self._service_stdout("global_authority").replace(
                '"signing-identifier" => "com.bill.clashformac.global-authority"',
                '"signing-identifier" => "com.bill.clashformac.proxy-agent"',
            ),
        )
        with self.assertRaisesRegex(
            Exception, "does not show the fixed running GlobalAuthority"
        ):
            self.fixture.seal()

    def test_service_registration_rejects_an_unmanaged_job(self) -> None:
        self._set_service_stdout(
            "proxy_agent",
            self._service_stdout("proxy_agent").replace(
                "managed_by = com.apple.xpc.ServiceManagement",
                "managed_by = com.apple.launchd",
            ),
        )
        with self.assertRaisesRegex(
            Exception, "does not show the fixed running ProxyAgent"
        ):
            self.fixture.seal()

    def test_service_registration_rejects_a_synthetic_absolute_program_line(
        self,
    ) -> None:
        # launchd never emits an absolute `program =` line for these
        # BundleProgram jobs. Accepting one would mean the assertion was
        # written against a fabricated fixture rather than real output.
        self._set_service_stdout(
            "proxy_agent",
            "state = running\n"
            "program = /Applications/Clash for Mac.app/Contents/Library/"
            "LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent\n",
        )
        with self.assertRaisesRegex(
            Exception, "does not show the fixed running ProxyAgent"
        ):
            self.fixture.seal()

    def _set_system_extension_stdout(self, stdout: str) -> None:
        document = self.fixture.documents["system-extension.json"]
        document["command"]["stdout"] = stdout
        self.fixture.write_all()

    def test_observed_retained_extensions_seal_and_reopen(self) -> None:
        self._set_system_extension_stdout(observed_replacement_output())
        result = self.fixture.seal()
        self.assertEqual(result, self.fixture.validate())

    def test_activated_predecessor_cannot_seal_as_the_candidate(self) -> None:
        self._set_system_extension_stdout(
            packet_tunnel_listing(
                packet_tunnel_row(f"0.5.0/{FROM_BUILD}", SYSTEM_EXTENSION_ACTIVATED)
            )
        )
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError, f"lacks the fixed {TO_BUILD} extension"
        ):
            self.fixture.seal()

    def test_package_or_journal_binding_drift_is_rejected(self) -> None:
        self.fixture.expected["dmg_sha256"] = "f" * 64
        with self.assertRaisesRegex(Exception, "different package or journal"):
            self.fixture.seal()

    def test_dmg_contained_app_tree_cannot_be_self_assigned_from_install(self) -> None:
        with patch(
            "scripts.ga_runtime_acceptance._installed_candidate_tree",
            return_value=APP_TREE,
        ), patch(
            "scripts.ga_runtime_acceptance._dmg_contained_candidate_tree",
            return_value="f" * 64,
        ), patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ), self.assertRaisesRegex(Exception, "DMG-contained app and installed"):
            seal_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )

    def test_toctou_replacement_after_validation_is_rejected(self) -> None:
        self.fixture.seal()
        original = _confirm_snapshot

        def replace_then_confirm(root: Path, snapshots: object) -> None:
            path = root / "launch.json"
            data = path.read_bytes()
            replacement = root / ".launch-replacement"
            replacement.write_bytes(data)
            replacement.chmod(0o600)
            replacement.replace(path)
            original(root, snapshots)

        with patch(
            "scripts.ga_runtime_acceptance._confirm_snapshot",
            side_effect=replace_then_confirm,
        ), self.assertRaisesRegex(Exception, "changed during verification"):
            self.fixture.validate()


class GARuntimeSystemExtensionTests(unittest.TestCase):
    """macOS lists each replaced Packet Tunnel version until reboot, so only
    the exact candidate row can prove the candidate extension is live."""

    MISSING = f"raw system extension output lacks the fixed {TO_BUILD} extension"
    NOT_ENABLED = "fixed system extension is not both activated and enabled"
    NOT_RETAINED = (
        "another Packet Tunnel registration is not terminated and waiting to "
        "uninstall on reboot"
    )
    FOREIGN_TEAM = "raw system extension output lists a foreign-team Packet Tunnel"
    MALFORMED = "raw systemextensionsctl output is malformed"
    NOT_EARLIER = f"another Packet Tunnel registration is not an earlier build than {TO_BUILD}"
    MALFORMED_RETAINED_VERSION = (
        "another Packet Tunnel registration has a malformed version"
    )

    @staticmethod
    def _validate(stdout: str) -> None:
        ga_runtime._validate_system_extension(
            check(
                "system_extension",
                command=command(
                    ["/usr/bin/systemextensionsctl", "list"], stdout=stdout
                ),
            )
        )

    def _assert_rejected(self, cases: dict[str, tuple[str, str]]) -> None:
        for label, (stdout, message) in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(GARuntimeAcceptanceError) as raised:
                    self._validate(stdout)
                self.assertEqual(str(raised.exception), message)

    def test_observed_replacement_listing_accepts_the_activated_candidate(
        self,
    ) -> None:
        observed = observed_replacement_rows()
        listings = {
            "observed order": observed_replacement_output(),
            "candidate listed first": packet_tunnel_listing(
                observed[-1], *observed[:-1]
            ),
            "observed with driver extensions": system_extension_listing(
                (NETWORK_EXTENSION_SECTION, observed),
                (DRIVER_EXTENSION_SECTION, (SAMSUNG_MTP_DRIVER_ROW,)),
            ),
            "candidate alone after reboot": system_extension_output(),
        }
        for label, stdout in listings.items():
            with self.subTest(label=label):
                self._validate(stdout)

    def test_near_match_bundle_identifiers_are_ignored(self) -> None:
        candidate = packet_tunnel_row(f"0.5.0/{TO_BUILD}", SYSTEM_EXTENSION_ACTIVATED)
        for bundle_id in (
            "com.bill.clashformac.packet-tunnelx",
            "com.bill.clashformac.packet-tunnel.helper",
            "xcom.bill.clashformac.packet-tunnel",
        ):
            for team_id in ("YKUPL7Z869", "ABCDE12345"):
                near_match = packet_tunnel_row(
                    f"0.5.0/{TO_BUILD}",
                    SYSTEM_EXTENSION_ACTIVATED,
                    team_id=team_id,
                    bundle_id=bundle_id,
                )
                with self.subTest(bundle_id=bundle_id, team_id=team_id):
                    self._validate(packet_tunnel_listing(candidate, near_match))

    def test_activated_predecessor_is_not_the_candidate(self) -> None:
        row = packet_tunnel_row
        activated = SYSTEM_EXTENSION_ACTIVATED
        retained = SYSTEM_EXTENSION_RETAINED
        self._assert_rejected(
            {
                "predecessor alone after reboot": (
                    packet_tunnel_listing(row(f"0.5.0/{FROM_BUILD}", activated)),
                    self.MISSING,
                ),
                f"listing before the {TO_BUILD} replacement": (
                    packet_tunnel_listing(
                        row("0.5.0/50008", retained),
                        row("0.4.0/40073", retained),
                        row(f"0.5.0/{FROM_BUILD}", activated),
                    ),
                    self.MISSING,
                ),
                "candidate build under another product version": (
                    packet_tunnel_listing(row(f"0.5.1/{TO_BUILD}", activated)),
                    self.MISSING,
                ),
            }
        )

    def test_second_activated_registration_is_rejected(self) -> None:
        row = packet_tunnel_row
        activated = SYSTEM_EXTENSION_ACTIVATED
        self._assert_rejected(
            {
                "predecessor still activated": (
                    packet_tunnel_listing(
                        row(f"0.5.0/{FROM_BUILD}", activated), row(f"0.5.0/{TO_BUILD}", activated)
                    ),
                    self.NOT_RETAINED,
                ),
                "later build activated": (
                    packet_tunnel_listing(
                        row(f"0.5.0/{TO_BUILD}", activated), row(f"0.5.0/{NEXT_GA_BUILD}", activated)
                    ),
                    self.NOT_RETAINED,
                ),
            }
        )

    def test_candidate_must_be_activated_enabled_and_flagged(self) -> None:
        row = packet_tunnel_row
        activated = SYSTEM_EXTENSION_ACTIVATED
        predecessor = row(f"0.5.0/{FROM_BUILD}", SYSTEM_EXTENSION_RETAINED)
        cases = {
            "waiting for user": (
                packet_tunnel_listing(
                    predecessor,
                    row(f"0.5.0/{TO_BUILD}", "[activated waiting for user]", flags="*\t*"),
                ),
                self.NOT_ENABLED,
            ),
            "retained itself": (
                packet_tunnel_listing(
                    predecessor, row(f"0.5.0/{TO_BUILD}", SYSTEM_EXTENSION_RETAINED)
                ),
                self.NOT_ENABLED,
            ),
        }
        # The state column alone is not proof: both flag columns must agree.
        for flags in ("\t", "*\t", "\t*"):
            cases[f"flags {flags!r}"] = (
                packet_tunnel_listing(row(f"0.5.0/{TO_BUILD}", activated, flags=flags)),
                self.NOT_ENABLED,
            )
        self._assert_rejected(cases)

    def test_predecessor_in_an_unexpected_state_is_rejected(self) -> None:
        candidate = packet_tunnel_row(f"0.5.0/{TO_BUILD}", SYSTEM_EXTENSION_ACTIVATED)
        self._assert_rejected(
            {
                state: (
                    packet_tunnel_listing(
                        packet_tunnel_row(f"0.5.0/{FROM_BUILD}", state), candidate
                    ),
                    self.NOT_RETAINED,
                )
                for state in (
                    "[terminating for uninstall but still running]",
                    "[activated waiting for user]",
                    "[activated disabled]",
                    "[terminated waiting to uninstall]",
                )
            }
        )

    def test_fixture_rows_keep_the_observed_listing_layout(self) -> None:
        # Copied byte for byte from one read-only `systemextensionsctl list` on
        # the GA Mac before the GA install replaced the 0.5.0 preview: retained
        # rows lead with two empty flag columns.
        observed = (
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]",
            "\t\tYKUPL7Z869\tcom.bill.clashformac.packet-tunnel (0.5.0/50008)"
            "\tClash for Mac Packet Tunnel\t[terminated waiting to uninstall on reboot]",
            "\t\tYKUPL7Z869\tcom.bill.clashformac.packet-tunnel (0.4.0/40073)"
            "\tClash for Mac Packet Tunnel\t[terminated waiting to uninstall on reboot]",
            "*\t*\tYKUPL7Z869\tcom.bill.clashformac.packet-tunnel (0.5.0/50025)"
            "\tClash for Mac Packet Tunnel\t[activated enabled]",
        )
        self.assertEqual(
            packet_tunnel_listing(
                packet_tunnel_row("0.5.0/50008", SYSTEM_EXTENSION_RETAINED),
                packet_tunnel_row("0.4.0/40073", SYSTEM_EXTENSION_RETAINED),
                packet_tunnel_row("0.5.0/50025", SYSTEM_EXTENSION_ACTIVATED),
            ),
            "\n".join(("3 extension(s)", NETWORK_EXTENSION_SECTION, *observed)) + "\n",
        )

    def test_retained_registration_must_be_disabled_and_inactive(self) -> None:
        candidate = packet_tunnel_row(f"0.5.0/{TO_BUILD}", SYSTEM_EXTENSION_ACTIVATED)
        # A retained state beside either flag is a self-contradicting row.
        self._assert_rejected(
            {
                f"retained flags {flags!r}": (
                    packet_tunnel_listing(
                        packet_tunnel_row(
                            f"0.5.0/{FROM_BUILD}", SYSTEM_EXTENSION_RETAINED, flags=flags
                        ),
                        candidate,
                    ),
                    self.NOT_RETAINED,
                )
                for flags in ("*\t*", "*\t", "\t*")
            }
        )

    def test_retained_registration_must_be_an_earlier_build(self) -> None:
        candidate = packet_tunnel_row(f"0.5.0/{TO_BUILD}", SYSTEM_EXTENSION_ACTIVATED)

        def listing(version: str) -> str:
            return packet_tunnel_listing(
                packet_tunnel_row(version, SYSTEM_EXTENSION_RETAINED), candidate
            )

        cases = {
            f"retained {version}": (listing(version), self.NOT_EARLIER)
            for version in (
                f"0.5.1/{TO_BUILD}",
                f"0.5.0/{NEXT_GA_BUILD}",
                "0.6.0/60001",
                "0.4.0/9223372036854775807",
            )
        }
        for version in (
            "0.5.0",
            "0.5.0/",
            "/50025",
            "0.5/50025",
            "0.5.0.1/50025",
            "v0.5.0/50025",
            "00.5.0/50025",
            "0.5.0 /50025",
            "0.5.0/050025",
            "0.5.0/0",
            "0.5.0/-50025",
            "0.5.0/50025a",
            "0.5.0/50025/1",
            "0.5.0/9223372036854775808",
        ):
            cases[f"malformed {version!r}"] = (
                listing(version),
                self.MALFORMED_RETAINED_VERSION,
            )
        self._assert_rejected(cases)

    def test_foreign_team_packet_tunnel_is_rejected(self) -> None:
        row = packet_tunnel_row
        activated = SYSTEM_EXTENSION_ACTIVATED
        retained = SYSTEM_EXTENSION_RETAINED
        self._assert_rejected(
            {
                "foreign predecessor": (
                    packet_tunnel_listing(
                        row(f"0.5.0/{FROM_BUILD}", retained, team_id="ABCDE12345"),
                        row(f"0.5.0/{TO_BUILD}", activated),
                    ),
                    self.FOREIGN_TEAM,
                ),
                "foreign candidate": (
                    packet_tunnel_listing(
                        row(f"0.5.0/{FROM_BUILD}", retained),
                        row(f"0.5.0/{TO_BUILD}", activated, team_id="ABCDE12345"),
                    ),
                    self.FOREIGN_TEAM,
                ),
            }
        )

    def test_duplicate_or_miscounted_listing_is_malformed(self) -> None:
        row = packet_tunnel_row
        candidate = row(f"0.5.0/{TO_BUILD}", SYSTEM_EXTENSION_ACTIVATED)
        self._assert_rejected(
            {
                "duplicate candidate registration": (
                    packet_tunnel_listing(
                        row(f"0.5.0/{TO_BUILD}", SYSTEM_EXTENSION_RETAINED), candidate
                    ),
                    self.MALFORMED,
                ),
                # The summary counts distinct registrations here, so only the
                # repeated version itself exposes the inconsistency.
                "duplicate under a distinct-registration count": (
                    packet_tunnel_listing(candidate).replace(
                        candidate,
                        f"{row(f'0.5.0/{TO_BUILD}', SYSTEM_EXTENSION_RETAINED)}\n{candidate}",
                        1,
                    ),
                    self.MALFORMED,
                ),
                "count omits a retained registration": (
                    observed_replacement_output().replace(
                        "4 extension(s)", "3 extension(s)", 1
                    ),
                    self.MALFORMED,
                ),
            }
        )


class FakeCollectorRuntime:
    def require_host_quit_and_tunnel_disconnected(self) -> None:
        return None

    def require_capture_authority(self) -> None:
        return None

    def release_capture_authority(self) -> None:
        return None

    def __init__(
        self,
        fixture: RuntimeFixture,
        *,
        environments: list[dict[str, object]] | None = None,
        fail_launch: bool = False,
    ) -> None:
        self.fixture = fixture
        self.fail_launch = fail_launch
        self.calls: list[tuple[list[str], int]] = []
        documents = fixture.documents
        self.receipts: dict[tuple[str, ...], list[dict[str, object]]] = {}

        def add(receipt: dict[str, object]) -> None:
            self.receipts.setdefault(tuple(receipt["argv"]), []).append(
                copy.deepcopy(receipt)
            )

        install_commands = documents["exact-dmg-install.json"]["commands"]
        add(install_commands["dmg_gatekeeper"])
        add(install_commands["dmg_set_verify"])
        add(documents["launch.json"]["launch_command"])
        add(documents["launch.json"]["process_observation"])
        services = documents["service-registration.json"]["commands"]
        add(services["proxy_agent"])
        add(services["global_authority"])
        add(documents["system-extension.json"]["command"])
        for receipt in documents["high-risk-rejections.json"]["observations"]:
            add(receipt)
        # The operator-quit wait ends on the first process table without the Host.
        add(documents["shutdown-restore.json"]["host_process_observation"])
        add(documents["shutdown-restore.json"]["host_process_observation"])
        add(documents["shutdown-restore.json"]["off_proof_command"])
        add(documents["shutdown-restore.json"]["process_observation"])
        self.operator_quit_waits = 0
        # collect observes its baseline, the same guard again before launch,
        # and the restored guard.
        self.guards = [guard(), guard(), guard()]
        self.environments = (
            [copy.deepcopy(GA_ENVIRONMENT) for _ in range(3)]
            if environments is None
            else copy.deepcopy(environments)
        )

    def capture_environment(self) -> dict[str, object]:
        if not self.environments:
            raise AssertionError("unexpected extra GA environment capture")
        return copy.deepcopy(self.environments.pop(0))

    def run(self, argv: list[str], *, timeout: int = 900) -> dict[str, object]:
        self.calls.append((list(argv), timeout))
        if self.fail_launch and argv[:2] == ["/usr/bin/open", "-a"]:
            raise GARuntimeAcceptanceError("simulated launch failure")
        queue = self.receipts.get(tuple(argv))
        if not queue:
            raise AssertionError(f"unexpected collector command: {argv}")
        return queue.pop(0)

    def capture_guard(self) -> dict[str, object]:
        if not self.guards:
            raise AssertionError("unexpected extra CFW guard capture")
        return copy.deepcopy(self.guards.pop(0))

    def capture_traffic(
        self, check_id: str, tokens: dict[str, str], *, interpreter: str
    ) -> tuple[dict[str, object], bytes]:
        if interpreter != COLLECTOR["python"]["executable"]:
            raise AssertionError("collector senders must use the recorded Python")
        document = self.fixture.documents[f"{check_id.replace('_', '-')}.json"]
        self.assert_tokens(tokens, document["tokens"])
        return (
            {
                "capture_command": copy.deepcopy(document["capture_command"]),
                "endpoint": copy.deepcopy(document["endpoint"]),
                "host_observation": copy.deepcopy(document["host_observation"]),
                "observation_ms": document["observation_ms"],
                "send_commands": copy.deepcopy(document["send_commands"]),
            },
            self.fixture.pcaps[f"{check_id.replace('_', '-')}.pcap"],
        )

    def capture_stop_restore(self) -> dict[str, object]:
        return copy.deepcopy(
            self.fixture.documents["shutdown-restore.json"][
                "stop_restore_observation"
            ]
        )

    def await_host_absence(self, *, timeout: int) -> dict[str, object]:
        return self.run(list(PROCESS_OBSERVATION_COMMAND), timeout=timeout)

    def await_operator_quit(self) -> dict[str, object]:
        self.operator_quit_waits += 1
        return self.run(list(PROCESS_OBSERVATION_COMMAND), timeout=10 * 60)

    @staticmethod
    def assert_tokens(observed: dict[str, str], expected: object) -> None:
        if observed != expected:
            raise AssertionError("collector traffic tokens differ from the session challenge")


class NetworkObservingRuntime(FakeCollectorRuntime):
    """A recovery runtime that also answers recover's raw network observations.

    Each settle round reads the five observations: the release Mac's off state
    overridden by that round's outputs. The last round repeats once the list
    is used up.
    """

    def __init__(self, fixture: RuntimeFixture, rounds: list[dict[str, str]]) -> None:
        super().__init__(fixture, environments=[GA_ENVIRONMENT, GA_ENVIRONMENT])
        self.rounds = rounds
        self.completed_rounds = 0

    def run(self, argv: list[str], *, timeout: int = 900) -> dict[str, object]:
        names = {command: name for name, command in NETWORK_OBSERVATION_COMMANDS.items()}
        name = names.get(tuple(argv))
        if name is None:
            return super().run(argv, timeout=timeout)
        self.calls.append((list(argv), timeout))
        outputs = {
            **OFF_NETWORK,
            **self.rounds[min(self.completed_rounds, len(self.rounds) - 1)],
        }
        if name == "system proxy":
            self.completed_rounds += 1
        return command(list(argv), stdout=outputs[name])


class GARuntimeCollectorTests(unittest.TestCase):
    class _CapturePipe:
        def __init__(self, descriptor: int, *, close_error: bool = False) -> None:
            self.descriptor = descriptor
            self.close_error = close_error
            self.closed = False

        def fileno(self) -> int:
            return self.descriptor

        def close(self) -> None:
            self.closed = True
            if self.close_error:
                raise OSError("fixture capture pipe close failure")

    class _CaptureProcess:
        def __init__(
            self,
            stdout: "GARuntimeCollectorTests._CapturePipe | None",
            stderr: "GARuntimeCollectorTests._CapturePipe",
        ) -> None:
            self.pid = 525_252
            self.stdout = stdout
            self.stderr = stderr
            self.stdin = io.BytesIO()
            self.returncode = None

    def setUp(self) -> None:
        self.fixture = RuntimeFixture()
        self.fixture.remove_unsealed_raw_tree()
        self.addCleanup(self.fixture.cleanup)

    def _patch_evidence_sources(self):
        return (
            patch(
                "scripts.ga_runtime_acceptance._installed_candidate_tree",
                return_value=APP_TREE,
            ),
            patch(
                "scripts.ga_runtime_acceptance._dmg_contained_candidate_tree",
                return_value=APP_TREE,
            ),
            patch(
                "scripts.ga_runtime_acceptance._installed_guard_baseline",
                return_value=guard(),
            ),
        )

    def _capture_runtime(self) -> ProductionCollectorRuntime:
        runtime = object.__new__(ProductionCollectorRuntime)
        runtime.repository = self.fixture.repository
        runtime.environment = {}
        runtime._capture_password = bytearray()
        return runtime

    def test_capture_authorization_precedes_any_collection_state(self) -> None:
        # A run without a terminal, a mistyped password or an interrupt at the
        # prompt records nothing, so the next collect needs no recover, and
        # whatever the runtime held is released. Only the admission
        # environment and the baseline guard were observed before it.
        for failure in (
            GARuntimeAcceptanceError(
                "packet capture needs administrator authorization in a terminal "
                "before collection"
            ),
            GARuntimeAcceptanceError(
                "packet capture administrator authorization failed before collection"
            ),
            KeyboardInterrupt(),
        ):
            with self.subTest(failure=repr(failure)):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                fixture.remove_unsealed_raw_tree()
                runtime = FakeCollectorRuntime(fixture)
                sources = self._patch_evidence_sources()
                with sources[0], sources[1], sources[2], patch.object(
                    runtime, "require_capture_authority", side_effect=failure
                ), patch.object(
                    runtime, "release_capture_authority"
                ) as release, self.assertRaises(type(failure)) as raised:
                    self._collect(fixture, runtime)
                self.assertIs(raised.exception, failure)
                self.assertEqual(
                    getattr(raised.exception, "__notes__", []),
                    [PREFLIGHT_RETRY_GUIDANCE]
                    if isinstance(failure, GARuntimeAcceptanceError)
                    else [],
                )
                release.assert_called_once_with()
                self.assertEqual(runtime.calls, [])
                self.assertEqual((len(runtime.environments), len(runtime.guards)), (2, 2))
                self.assertFalse(fixture.collection_root.exists())
                self.assertFalse(fixture.raw_root.exists())

    def test_capture_authorization_is_released_when_the_intent_cannot_be_published(
        self,
    ) -> None:
        unknown = DurabilityOutcomeUnknown("fixture intent publication outcome unknown")
        runtime = FakeCollectorRuntime(self.fixture)
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], patch.object(
            ga_runtime, "_publish_collection_intent", side_effect=unknown
        ), patch.object(runtime, "require_capture_authority") as authority, patch.object(
            runtime, "release_capture_authority"
        ) as release, self.assertRaises(DurabilityOutcomeUnknown) as raised:
            self._collect(self.fixture, runtime)
        self.assertIs(raised.exception, unknown)
        authority.assert_called_once_with()
        release.assert_called_once_with()
        self.assertEqual(runtime.calls, [])

    @staticmethod
    def _preflight_runner(
        *,
        host: bool = False,
        host_path: str | None = None,
        vpn: str = "Disconnected",
        relisted_vpn: str | None = None,
        extension_team: str = "YKUPL7Z869",
        failing: tuple[tuple[str, ...], ...] = (),
        cfw: tuple[str, ...] = (dormant_app_install.CFW_GUI, dormant_app_install.CFW_CORE),
        proxy: str = NETWORK_PROXY,
    ) -> tuple[Any, list[tuple[str, ...]]]:
        """Fake the installer's production runner for the collection pre-flight.

        Like that runner, it first refuses any command outside the installer's
        fixed registry, so a pre-flight command that drifts from it fails here.
        ``relisted_vpn`` is the VPN state the second service listing shows.
        ``cfw`` names the Clash for Windows processes that run; ``proxy`` is
        the `scutil --proxy` output.
        """

        def vpn_list(state: str) -> str:
            return (
                "Available network connection services in the current set (*=enabled):\n"
                f'* ({state}) {PREFLIGHT_VPN_ID} VPN (com.bill.clashformac) '
                '"Clash for Mac Tunnel" [VPN:com.bill.clashformac]\n'
            )

        calls: list[tuple[str, ...]] = []
        processes = "1 0 Mon Jul 27 10:00:00 2026 /sbin/launchd\n" + "".join(
            line
            for line in process_table(running=host).splitlines(keepends=True)
            if "/Clash for Windows.app/" not in line or line.rstrip("\n").endswith(cfw)
        )
        if host_path is not None:
            processes += f"300 501 Mon Jul 27 11:59:58 2026 {host_path}\n"
        vpns = ("/usr/sbin/scutil", "--nc", "list")
        outputs = {
            tuple(PROCESS_OBSERVATION_COMMAND): processes,
            ("/usr/bin/systemextensionsctl", "list"): packet_tunnel_listing(
                packet_tunnel_row(
                    f"0.5.0/{TO_BUILD}", SYSTEM_EXTENSION_ACTIVATED, team_id=extension_team
                )
            ),
            vpns: vpn_list(vpn),
            ("/usr/sbin/scutil", "--nc", "status", PREFLIGHT_VPN_ID): f"{vpn}\n",
            ("/usr/sbin/scutil", "--proxy"): proxy,
        }

        def run(arguments: tuple[str, ...]) -> dormant_app_install.CommandResult:
            dormant_app_install._require_fixed_command(arguments)
            calls.append(arguments)
            if arguments not in outputs:
                raise AssertionError(f"unexpected pre-flight command: {arguments}")
            if arguments in failing:
                return dormant_app_install.CommandResult(1, "", "fixture failure\n")
            if arguments == vpns and relisted_vpn is not None and calls.count(vpns) == 2:
                return dormant_app_install.CommandResult(0, vpn_list(relisted_vpn), "")
            return dormant_app_install.CommandResult(0, outputs[arguments], "")

        return run, calls

    def test_collection_preflight_refuses_a_running_host_or_a_connected_vpn(self) -> None:
        runtime = self._capture_runtime()
        ps = tuple(PROCESS_OBSERVATION_COMMAND)
        extensions = ("/usr/bin/systemextensionsctl", "list")
        vpns = ("/usr/sbin/scutil", "--nc", "list")
        status = ("/usr/sbin/scutil", "--nc", "status", PREFLIGHT_VPN_ID)
        # A Host opened from the DMG runs from a translocated copy, not the
        # installed path; it can still own the system proxy.
        translocated = (
            "/private/var/folders/zz/T/AppTranslocation/0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9"
            "/d/Clash for Mac.app/Contents/MacOS/clash-for-mac"
        )
        cases = (
            ("Host running", {"host": True}, HOST_PREFLIGHT_REFUSAL, "service_host_running", [ps]),
            (
                "translocated Host running",
                {"host_path": translocated},
                HOST_PREFLIGHT_REFUSAL,
                "service_host_running",
                [ps],
            ),
            ("VPN connected", {"vpn": "Connected"}, VPN_PREFLIGHT_REFUSAL, "cfm_tunnel_not_disconnected", [ps, extensions, vpns]),
            ("VPN connecting", {"vpn": "Connecting"}, VPN_PREFLIGHT_REFUSAL, "cfm_tunnel_not_disconnected", [ps, extensions, vpns]),
            (
                "VPN connecting while observed",
                {"relisted_vpn": "Connecting"},
                VPN_PREFLIGHT_REFUSAL,
                "cfm_tunnel_state_changed",
                [ps, extensions, vpns, status, vpns],
            ),
            (
                "process table unobservable",
                {"failing": (ps,)},
                "Clash for Mac processes could not be observed before collection",
                "command_failed",
                [ps],
            ),
            (
                "VPN state unobservable",
                {"failing": (vpns,)},
                "Clash for Mac VPN state could not be proven disconnected before collection",
                "command_failed",
                [ps, extensions, vpns],
            ),
            # Turning TUN Mode off cannot repair another team's extension.
            (
                "foreign-team extension",
                {"extension_team": "AAAAAAAAAA"},
                "Clash for Mac VPN state could not be proven disconnected before collection",
                "cfm_system_extension_identity_invalid",
                [ps, extensions],
            ),
        )
        for label, options, message, code, commands in cases:
            with self.subTest(label):
                runner, calls = self._preflight_runner(**options)
                with patch.object(
                    dormant_app_install, "production_command_runner", side_effect=runner
                ), self.assertRaises(GARuntimeAcceptanceError) as raised:
                    runtime.require_host_quit_and_tunnel_disconnected()
                self.assertEqual(str(raised.exception), message)
                cause = raised.exception.__cause__
                self.assertIsInstance(cause, dormant_app_install.InstallError)
                self.assertEqual(cause.code, code)
                self.assertEqual(calls, commands)
        runner, calls = self._preflight_runner()
        with patch.object(dormant_app_install, "production_command_runner", side_effect=runner):
            runtime.require_host_quit_and_tunnel_disconnected()
        self.assertEqual(calls, [ps, extensions, vpns, status, vpns])

    PREFLIGHT_PROXY_CALLS = [
        tuple(PROCESS_OBSERVATION_COMMAND),
        ("/usr/bin/systemextensionsctl", "list"),
        ("/usr/sbin/scutil", "--nc", "list"),
        ("/usr/sbin/scutil", "--nc", "status", PREFLIGHT_VPN_ID),
        ("/usr/sbin/scutil", "--nc", "list"),
        ("/usr/sbin/scutil", "--proxy"),
    ]

    def test_collection_preflight_refuses_an_enabled_loopback_system_proxy(self) -> None:
        runtime = self._capture_runtime()
        cases = (
            (
                "global",
                LOOPBACK_PROXY,
                [
                    f"{kind} system proxy on loopback host 127.0.0.1:7890"
                    for kind in ("HTTP", "HTTPS", "SOCKS")
                ],
            ),
            (
                "scoped",
                scutil_proxy(PROXY_OFF_FIELDS, scoped={"en0": CFM_PROXY_FIELDS}),
                [
                    f"{kind} system proxy for en0 on loopback host 127.0.0.1:7890"
                    for kind in ("HTTP", "HTTPS", "SOCKS")
                ],
            ),
            (
                "supplemental",
                scutil_proxy(
                    PROXY_OFF_FIELDS,
                    supplemental=(
                        "SOCKSEnable : 1\nSOCKSPort : 1080\nSOCKSProxy : localhost\n",
                    ),
                ),
                ["SOCKS system proxy in supplemental entry 0 on loopback host localhost:1080"],
            ),
            # Another local proxy tool on the IPv6 loopback.
            (
                "IPv6 loopback",
                scutil_proxy(
                    "HTTPEnable : 1\nHTTPPort : 6152\nHTTPProxy : ::1\n"
                    "HTTPSEnable : 0\nSOCKSEnable : 0\n"
                ),
                ["HTTP system proxy on loopback host [::1]:6152"],
            ),
            # scutil passes on any byte of a scope; the refusal escapes it.
            (
                "IPv6 loopback with a control byte in its scope",
                scutil_proxy(
                    "HTTPEnable : 1\nHTTPPort : 6152\nHTTPProxy : ::1%\x1b[2J\n"
                    "HTTPSEnable : 0\nSOCKSEnable : 0\n"
                ),
                ['HTTP system proxy on loopback host ["::1%\\u001b[2J"]:6152'],
            ),
        )
        for label, proxy, found in cases:
            with self.subTest(label):
                runner, calls = self._preflight_runner(cfw=(), proxy=proxy)
                with patch.object(
                    dormant_app_install, "production_command_runner", side_effect=runner
                ), self.assertRaises(GARuntimeAcceptanceError) as raised:
                    runtime.require_host_quit_and_tunnel_disconnected()
                self.assertEqual(str(raised.exception), loopback_proxy_refusal(found))
                self.assertIsNone(raised.exception.__cause__)
                self.assertEqual(calls, self.PREFLIGHT_PROXY_CALLS)

    def test_collection_preflight_admits_a_system_proxy_off_loopback(self) -> None:
        runtime = self._capture_runtime()
        corporate = (
            "HTTPEnable : 1\nHTTPPort : 3128\nHTTPProxy : proxy.example.org\n"
            "HTTPSEnable : 1\nHTTPSPort : 3128\nHTTPSProxy : 10.0.0.1\n"
            "SOCKSEnable : 1\nSOCKSPort : 1080\nSOCKSProxy : 2001:db8::5\n"
        )
        cases = (
            ("no proxy", NETWORK_PROXY),
            (
                "global, scoped and supplemental proxies off loopback",
                scutil_proxy(corporate, scoped={"en0": corporate}, supplemental=(corporate,)),
            ),
            (
                "loopback proxy switched off",
                scutil_proxy(
                    "HTTPEnable : 0\nHTTPPort : 7890\nHTTPProxy : 127.0.0.1\n"
                    "HTTPSEnable : 0\nSOCKSEnable : 0\n"
                ),
            ),
        )
        for label, proxy in cases:
            with self.subTest(label):
                runner, calls = self._preflight_runner(cfw=(), proxy=proxy)
                with patch.object(
                    dormant_app_install, "production_command_runner", side_effect=runner
                ):
                    runtime.require_host_quit_and_tunnel_disconnected()
                self.assertEqual(calls, self.PREFLIGHT_PROXY_CALLS)

    def test_collection_preflight_leaves_the_clash_for_windows_proxy_to_its_guard(
        self,
    ) -> None:
        # While Clash for Windows runs it owns 127.0.0.1:7890 as the system
        # proxy; the baseline guard then requires exactly that binding and the
        # collection must leave it unchanged, so the pre-flight does not read it.
        runtime = self._capture_runtime()
        gui, core = dormant_app_install.CFW_GUI, dormant_app_install.CFW_CORE
        for label, cfw in (
            ("GUI and core", (gui, core)),
            ("GUI alone", (gui,)),
            ("core alone", (core,)),
        ):
            with self.subTest(label):
                runner, calls = self._preflight_runner(cfw=cfw, proxy=LOOPBACK_PROXY)
                with patch.object(
                    dormant_app_install, "production_command_runner", side_effect=runner
                ):
                    runtime.require_host_quit_and_tunnel_disconnected()
                self.assertEqual(calls, self.PREFLIGHT_PROXY_CALLS[:-1])

    def test_collection_preflight_refuses_an_unobservable_system_proxy(self) -> None:
        runtime = self._capture_runtime()
        proxy_command = ("/usr/sbin/scutil", "--proxy")
        malformed = "system proxy observation before collection is malformed"
        cases = (
            (
                "scutil fails",
                {"failing": (proxy_command,)},
                "system proxy could not be observed before collection",
                dormant_app_install.InstallError,
            ),
            (
                "not one dictionary",
                {"proxy": "HTTPEnable : 1\n"},
                malformed,
                ga_runtime.NetworkObservationError,
            ),
            (
                "switch neither 0 nor 1",
                {"proxy": NETWORK_PROXY.replace("SOCKSEnable : 0", "SOCKSEnable : 2")},
                malformed,
                ga_runtime.NetworkObservationError,
            ),
            (
                "repeated field",
                {"proxy": scutil_proxy("HTTPEnable : 0\nHTTPEnable : 1\n")},
                malformed,
                dormant_app_install.InstallError,
            ),
            (
                "enabled without a host",
                {"proxy": NETWORK_PROXY.replace("HTTPEnable : 0", "HTTPEnable : 1")},
                "collection pre-flight system proxy observation enables HTTP without a host",
                type(None),
            ),
        ) + tuple(
            # A loopback proxy where scutil nests no proxy dictionary is not read.
            (shape, {"proxy": proxy}, malformed, ga_runtime.NetworkObservationError)
            for shape, proxy in hidden_loopback_proxies().items()
        )
        for label, options, message, cause in cases:
            with self.subTest(label):
                runner, calls = self._preflight_runner(cfw=(), **options)
                with patch.object(
                    dormant_app_install, "production_command_runner", side_effect=runner
                ), self.assertRaises(GARuntimeAcceptanceError) as raised:
                    runtime.require_host_quit_and_tunnel_disconnected()
                self.assertEqual(str(raised.exception), message)
                self.assertIsInstance(raised.exception.__cause__, cause)
                self.assertEqual(calls, self.PREFLIGHT_PROXY_CALLS)

    def test_collect_preflight_precedes_the_baseline_and_runs_again_before_launch(
        self,
    ) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        observed: list[tuple[int, int, bool, bool]] = []

        def preflight() -> None:
            launched = ["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"] in [
                argv for argv, _timeout in runtime.calls
            ]
            observed.append(
                (
                    len(runtime.environments),
                    len(runtime.guards),
                    self.fixture.collection_root.exists(),
                    launched,
                )
            )

        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], patch.object(
            runtime, "require_host_quit_and_tunnel_disconnected", side_effect=preflight
        ):
            self._collect(self.fixture, runtime)
        # First after the admission environment, before the baseline guard and
        # the intent; again after the pre-mutation environment and the
        # pre-launch guard, right before launch.
        self.assertEqual(observed, [(2, 3, False, False), (1, 1, True, False)])

    def test_collect_refused_by_its_preflight_leaves_no_collection_state(self) -> None:
        production = self._capture_runtime()
        for label, options, message in (
            ("Host running", {"host": True}, HOST_PREFLIGHT_REFUSAL),
            ("VPN connected", {"vpn": "Connected"}, VPN_PREFLIGHT_REFUSAL),
            (
                "loopback system proxy",
                {"cfw": (), "proxy": LOOPBACK_PROXY},
                loopback_proxy_refusal(
                    [
                        f"{kind} system proxy on loopback host 127.0.0.1:7890"
                        for kind in ("HTTP", "HTTPS", "SOCKS")
                    ]
                ),
            ),
        ):
            with self.subTest(label):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                fixture.remove_unsealed_raw_tree()
                runtime = FakeCollectorRuntime(fixture)
                runner, _calls = self._preflight_runner(**options)
                sources = self._patch_evidence_sources()
                with sources[0], sources[1], sources[2], patch.object(
                    runtime,
                    "require_host_quit_and_tunnel_disconnected",
                    side_effect=lambda: production.require_host_quit_and_tunnel_disconnected(),
                ), patch.object(
                    dormant_app_install, "production_command_runner", side_effect=runner
                ), self.assertRaises(GARuntimeAcceptanceError) as raised:
                    self._collect(fixture, runtime)
                self.assertEqual(str(raised.exception), message)
                self.assertEqual(
                    getattr(raised.exception, "__notes__", []), [PREFLIGHT_RETRY_GUIDANCE]
                )
                self.assertFalse(fixture.collection_root.exists())
                self.assertFalse(fixture.raw_root.exists())
                self.assertEqual(runtime.calls, [])
                self.assertEqual(runtime.guards, [guard(), guard(), guard()])

    def test_collect_refuses_a_host_started_before_launch_before_mutation(self) -> None:
        # A Host the operator starts during the DMG proof would otherwise be
        # taken for the one this collection launches.
        runtime = FakeCollectorRuntime(self.fixture)
        started = GARuntimeAcceptanceError(HOST_PREFLIGHT_REFUSAL)
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], patch.object(
            runtime, "require_host_quit_and_tunnel_disconnected", side_effect=[None, started]
        ) as preflight, self.assertRaises(GARuntimeAcceptanceError) as raised:
            self._collect(self.fixture, runtime)
        self.assertIs(raised.exception, started)
        # recover archives this attempt before collect can run again.
        self.assertEqual(
            getattr(raised.exception, "__notes__", []), [PRE_MUTATION_ABORT_GUIDANCE]
        )
        self.assertEqual(preflight.call_count, 2)
        self.assertNotIn(
            ["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"],
            [argv for argv, _timeout in runtime.calls],
        )
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS[:4], ABORTED_EVENT]
        )

    def test_an_unfinished_collection_is_named_before_the_preflight(self) -> None:
        # recover, not the pre-flight's quit and rerun, is the next step for an
        # unfinished collection, whatever the Host and VPN now show.
        self.fixture.write_collection_receipt(events=[*STEP_EVENTS[:5], RECOVERY_REQUIRED_EVENT])
        runtime = FakeCollectorRuntime(self.fixture)
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], patch.object(
            runtime,
            "require_host_quit_and_tunnel_disconnected",
            side_effect=GARuntimeAcceptanceError(HOST_PREFLIGHT_REFUSAL),
        ) as preflight, self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "^an unfinished GA runtime collection already exists; recover it$",
        ):
            self._collect(self.fixture, runtime)
        preflight.assert_not_called()
        self.assertEqual(runtime.calls, [])
        self.assertEqual(len(runtime.environments), 3)
        self.assertEqual(runtime.guards, [guard(), guard(), guard()])

    @staticmethod
    def _fake_clock() -> tuple[list[float], list[float], tuple[Any, Any]]:
        """A monotonic clock the patched sleeps advance; a test may advance it too."""

        clock = [0.0]
        sleeps: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock[0] += seconds

        return clock, sleeps, (
            patch.object(ga_runtime.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(ga_runtime.time, "sleep", side_effect=sleep),
        )

    @staticmethod
    def _configd_transient() -> dict[str, object]:
        # configd has not yet restored the system proxy; processes are intact.
        return {**guard(), "proxy_sha256": "f" * 64}

    def test_collect_waits_for_the_restored_guard_to_settle(self) -> None:
        # configd can still be restoring the proxy, DNS and routes when the
        # Off proof completes; the restored guard must then equal the baseline.
        runtime = FakeCollectorRuntime(self.fixture)
        runtime.guards = [
            guard(),
            guard(),
            self._configd_transient(),
            self._configd_transient(),
            guard(),
        ]
        _clock, sleeps, clock_patches = self._fake_clock()
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[1]:
            result = self._collect(self.fixture, runtime)
        self.assertEqual(result, self.fixture.validate())
        self.assertEqual(runtime.guards, [])
        self.assertEqual(sleeps, [1.0, 1.0])
        raw = json.loads((self.fixture.raw_root / "shutdown-restore.json").read_bytes())
        self.assertEqual((raw["before_guard"], raw["after_guard"]), (guard(), guard()))

    def test_collect_refuses_a_restored_guard_that_never_settles(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        # The baseline and the same guard before launch, then one restored
        # observation a second for the whole 30 seconds.
        runtime.guards = [guard(), guard(), *(self._configd_transient() for _ in range(31))]
        _clock, sleeps, clock_patches = self._fake_clock()
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[1], self.assertRaises(
            GACollectionRecoveryRequired
        ) as raised:
            self._collect(self.fixture, runtime)
        self.assertEqual(
            str(raised.exception.__cause__),
            "collection did not restore the exact pre-run CFW state",
        )
        # Only guard keys are named, never their values.
        self.assertEqual(
            getattr(raised.exception.__cause__, "__notes__", []),
            ["collection restored guard still differs from its baseline in proxy_sha256 after 30 s"],
        )
        self.assertEqual(runtime.guards, [])
        self.assertEqual(sleeps, [1.0] * 30)
        self.assertFalse(self.fixture.raw_root.exists())
        self.assertEqual(collection_events(self.fixture.repository)[-1], RECOVERY_REQUIRED_EVENT)

    def test_restored_guard_settle_is_bounded_in_wall_time(self) -> None:
        # Each guard capture runs several commands: with 14.25-second captures
        # the 30-second settle after the baseline's and the pre-launch capture
        # starts only three, the last exactly at its bound after a pause cut
        # to half a second.
        runtime = FakeCollectorRuntime(self.fixture)
        clock, sleeps, clock_patches = self._fake_clock()
        captures = [0]

        def capture() -> dict[str, object]:
            captures[0] += 1
            clock[0] += 14.25
            return guard() if captures[0] <= 2 else self._configd_transient()

        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[
            1
        ], patch.object(runtime, "capture_guard", side_effect=capture), self.assertRaises(
            GACollectionRecoveryRequired
        ) as raised:
            self._collect(self.fixture, runtime)
        self.assertEqual(
            str(raised.exception.__cause__),
            "collection did not restore the exact pre-run CFW state",
        )
        self.assertEqual(captures[0], 2 + 3)
        self.assertEqual(sleeps, [1.0, 0.5])

    def test_an_unobservable_restored_guard_fails_collect_at_once(self) -> None:
        # Only a guard that differs is observed again; one that cannot be
        # observed is a failure, not a state that may still settle.
        unobservable = GARuntimeAcceptanceError("fixed CFW guard could not be observed")
        runtime = FakeCollectorRuntime(self.fixture)
        _clock, sleeps, clock_patches = self._fake_clock()
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[
            1
        ], patch.object(
            runtime, "capture_guard", side_effect=[guard(), guard(), unobservable, guard()]
        ) as observed, self.assertRaises(GACollectionRecoveryRequired) as raised:
            self._collect(self.fixture, runtime)
        self.assertIs(raised.exception.__cause__, unobservable)
        self.assertEqual(observed.call_count, 3)
        self.assertEqual(sleeps, [])

    def test_collect_refuses_a_guard_that_drifted_before_launch_before_mutation(
        self,
    ) -> None:
        # The DMG proof takes minutes; a guard that changed in them would fail
        # the run only at its end, after the launch, and need full recovery.
        # It is judged before launch as the restored guard is at the end.
        for key, value in (
            ("proxy_sha256", "f" * 64),
            # Clash for Windows restarted during the DMG proof.
            ("cfw_processes", restarted_guard()["cfw_processes"]),
        ):
            with self.subTest(key=key):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                fixture.remove_unsealed_raw_tree()
                runtime = FakeCollectorRuntime(fixture)
                drifted = {**guard(), key: value}
                runtime.guards = [guard(), *(copy.deepcopy(drifted) for _ in range(31))]
                _clock, sleeps, clock_patches = self._fake_clock()
                sources = self._patch_evidence_sources()
                with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[
                    1
                ], patch.object(
                    runtime,
                    "require_host_quit_and_tunnel_disconnected",
                    wraps=runtime.require_host_quit_and_tunnel_disconnected,
                ) as preflight, self.assertRaises(GARuntimeAcceptanceError) as raised:
                    self._collect(fixture, runtime)
                self.assertNotIsInstance(raised.exception, GACollectionRecoveryRequired)
                self.assertEqual(
                    str(raised.exception),
                    "CFW state changed after the collection baseline, before launch",
                )
                # Only guard keys are named, never their values; recover only
                # archives an attempt that stopped before its boundary.
                self.assertEqual(
                    raised.exception.__notes__,
                    [
                        "collection pre-launch guard still differs from its baseline in "
                        f"{key} after 30 s",
                        PRE_MUTATION_ABORT_GUIDANCE,
                    ],
                )
                self.assertEqual(sleeps, [1.0] * 30)
                self.assertEqual(runtime.guards, [])
                # The final pre-flight right before launch never ran.
                self.assertEqual(preflight.call_count, 1)
                self.assertNotIn(
                    ["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"],
                    [argv for argv, _timeout in runtime.calls],
                )
                self.assertEqual(
                    collection_events(fixture.repository), [*STEP_EVENTS[:4], ABORTED_EVENT]
                )
                self.assertFalse(fixture.raw_root.exists())

    def test_collect_launches_once_a_guard_that_differed_before_launch_settles(
        self,
    ) -> None:
        # configd may be applying another change when the DMG proof ends; one
        # that settles back to the baseline within the bound is no drift.
        runtime = FakeCollectorRuntime(self.fixture)
        runtime.guards = [guard(), self._configd_transient(), guard(), guard()]
        _clock, sleeps, clock_patches = self._fake_clock()
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[1]:
            result = self._collect(self.fixture, runtime)
        self.assertEqual(result, self.fixture.validate())
        self.assertEqual(runtime.guards, [])
        self.assertEqual(sleeps, [1.0])
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )

    def test_an_unobservable_restored_guard_fails_recovery_at_once(self) -> None:
        # recover keeps the exact guard for a Clash for Windows baseline.
        self._create_recoverable_collection()
        unobserved = GARuntimeAcceptanceError("fixed CFW guard could not be observed")
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        _clock, sleeps, clock_patches = self._fake_clock()
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), clock_patches[0], clock_patches[1], patch.object(
            recovery, "capture_guard", side_effect=[unobserved, guard()]
        ) as recovered, self.assertRaises(GARuntimeAcceptanceError) as raised:
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertIs(raised.exception, unobserved)
        self.assertEqual(recovered.call_count, 1)
        self.assertEqual(sleeps, [])

    def test_recovery_waits_for_the_restored_guard_to_settle(self) -> None:
        self._create_recoverable_collection()
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        recovery.guards = [self._configd_transient(), guard()]
        _clock, sleeps, clock_patches = self._fake_clock()
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), clock_patches[0], clock_patches[1]:
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertTrue(archived.is_dir())
        self.assertEqual(recovery.guards, [])
        self.assertEqual(sleeps, [1.0])

    @staticmethod
    def _service_not_running(receipt: dict[str, object]) -> dict[str, object]:
        # launchd lists an on-demand MachService job before it spawns it.
        idle = copy.deepcopy(receipt)
        stdout = str(idle["stdout"])
        if "\tstate = running\n" not in stdout:
            raise AssertionError("fixture launchctl output has no running state")
        idle["stdout"] = stdout.replace("\tstate = running\n", "\tstate = not running\n")
        return idle

    def test_collect_keeps_the_exact_guard_for_a_whole_system_baseline(self) -> None:
        # Judging by Clash for Mac remnants is recover's alone: collect's
        # restored guard must equal even a baseline without Clash for Windows.
        runtime = FakeCollectorRuntime(self.fixture)
        drifted = {**whole_system_guard(), "routes_ipv6_sha256": "5" * 64}
        runtime.guards = [
            whole_system_guard(),
            whole_system_guard(),
            *(copy.deepcopy(drifted) for _ in range(31)),
        ]
        _clock, sleeps, clock_patches = self._fake_clock()
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[
            1
        ], self.assertRaises(GACollectionRecoveryRequired) as raised:
            self._collect(self.fixture, runtime)
        self.assertEqual(
            str(raised.exception.__cause__),
            "collection did not restore the exact pre-run CFW state",
        )
        self.assertEqual(
            getattr(raised.exception.__cause__, "__notes__", []),
            [
                "collection restored guard still differs from its baseline in "
                "routes_ipv6_sha256 after 30 s"
            ],
        )
        self.assertEqual(runtime.guards, [])
        self.assertEqual(sleeps, [1.0] * 30)
        observed = [tuple(argv) for argv, _timeout in runtime.calls]
        self.assertFalse(set(observed) & set(NETWORK_OBSERVATION_COMMANDS.values()))

    def test_collect_records_the_first_process_table_that_lists_the_launched_host(
        self,
    ) -> None:
        # `open -a` returns before the Host need be listed; only the accepted
        # observation is recorded, inside one started/completed pair.
        runtime = FakeCollectorRuntime(self.fixture)
        ps = tuple(PROCESS_OBSERVATION_COMMAND)
        listed = copy.deepcopy(runtime.receipts[ps][0])
        not_listed = command(list(ps), stdout=process_table(running=False))
        runtime.receipts[ps][0:0] = [copy.deepcopy(not_listed), copy.deepcopy(not_listed)]
        _clock, sleeps, clock_patches = self._fake_clock()
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[1]:
            result = self._collect(self.fixture, runtime)
        self.assertEqual(result, self.fixture.validate())
        self.assertEqual(sleeps, [1.0, 1.0])
        raw = json.loads((self.fixture.raw_root / "launch.json").read_bytes())
        self.assertEqual(raw["process_observation"], listed)
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )

    def test_collect_records_the_first_observation_of_each_running_service(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        services = self.fixture.documents["service-registration.json"]["commands"]
        for name, waits in (("proxy_agent", 3), ("global_authority", 1)):
            queue = runtime.receipts[tuple(services[name]["argv"])]
            queue[0:0] = [self._service_not_running(queue[0]) for _ in range(waits)]
        _clock, sleeps, clock_patches = self._fake_clock()
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[1]:
            result = self._collect(self.fixture, runtime)
        self.assertEqual(result, self.fixture.validate())
        self.assertEqual(sleeps, [1.0] * 4)
        raw = json.loads((self.fixture.raw_root / "service-registration.json").read_bytes())
        self.assertEqual(raw["commands"], services)
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )

    def _never_ready(
        self,
        runtime: FakeCollectorRuntime,
        argv: list[str],
        receipt: dict[str, object],
        *,
        clock: list[float] | None = None,
        seconds_per_observation: float = 0.0,
    ) -> tuple[Any, list[int]]:
        observations: list[int] = []
        run = runtime.run

        def observe(called: list[str], *, timeout: int = 900) -> dict[str, object]:
            if called == argv:
                runtime.calls.append((list(called), timeout))
                observations.append(timeout)
                if clock is not None:
                    clock[0] += seconds_per_observation
                return copy.deepcopy(receipt)
            return run(called, timeout=timeout)

        return patch.object(runtime, "run", side_effect=observe), observations

    def test_readiness_waits_are_bounded_and_fail_before_any_traffic(self) -> None:
        services = self.fixture.documents["service-registration.json"]["commands"]
        ps = list(PROCESS_OBSERVATION_COMMAND)
        cases = (
            (
                "launched Host never listed",
                ps,
                command(ps, stdout=process_table(running=False)),
                30,
                f"raw process table does not contain exactly one installed {TO_BUILD} Host",
                "launch-process-observation",
            ),
            (
                "ProxyAgent never running",
                services["proxy_agent"]["argv"],
                self._service_not_running(services["proxy_agent"]),
                60,
                "raw launchctl output does not show the fixed running ProxyAgent",
                "proxy-service-observation",
            ),
            (
                "GlobalAuthority never running",
                services["global_authority"]["argv"],
                self._service_not_running(services["global_authority"]),
                60,
                "raw launchctl output does not show the fixed running GlobalAuthority",
                "authority-service-observation",
            ),
        )
        # The bound is wall time: with instant observations it is one a second
        # up to and including the bound; with seven-second observations far
        # fewer fit before the same bound ends the wait, and an observation
        # that outlasts the bound is the only one.
        for seconds_per_observation in (0.0, 7.0, 61.0):
            for label, argv, receipt, bound, message, step in cases:
                with self.subTest(label, seconds_per_observation=seconds_per_observation):
                    fixture = RuntimeFixture()
                    self.addCleanup(fixture.cleanup)
                    fixture.remove_unsealed_raw_tree()
                    runtime = FakeCollectorRuntime(fixture)
                    clock, sleeps, clock_patches = self._fake_clock()
                    never_ready, observations = self._never_ready(
                        runtime,
                        list(argv),
                        receipt,
                        clock=clock,
                        seconds_per_observation=seconds_per_observation,
                    )
                    sources = self._patch_evidence_sources()
                    with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[
                        1
                    ], never_ready, patch.object(
                        runtime, "capture_traffic", wraps=runtime.capture_traffic
                    ) as traffic, self.assertRaises(GACollectionRecoveryRequired) as raised:
                        self._collect(fixture, runtime)
                    failure = raised.exception.__cause__
                    self.assertEqual(str(failure), message)
                    # The n-th observation ends at n * (observation + 1 s) - 1 s.
                    attempts = math.ceil((bound + 1) / (seconds_per_observation + 1))
                    # Each observation keeps the step's own command timeout.
                    self.assertEqual(observations, [60] * attempts)
                    self.assertEqual(sleeps, [1.0] * (attempts - 1))
                    counted = (
                        "1 observation" if attempts == 1 else f"{attempts} observations"
                    )
                    self.assertEqual(
                        getattr(failure, "__notes__", []),
                        [f"GA collection {step} was not ready after {counted} within {bound} s"],
                    )
                    traffic.assert_not_called()
                    self.assertEqual(
                        collection_events(fixture.repository)[-2:],
                        [("started", step), RECOVERY_REQUIRED_EVENT],
                    )

    def test_readiness_wait_never_starts_an_observation_after_its_bound(self) -> None:
        # With 14.25-second observations the pause after the second is cut to
        # half a second, so the third starts exactly at the 30-second bound.
        fixture = RuntimeFixture()
        self.addCleanup(fixture.cleanup)
        fixture.remove_unsealed_raw_tree()
        runtime = FakeCollectorRuntime(fixture)
        ps = list(PROCESS_OBSERVATION_COMMAND)
        clock, sleeps, clock_patches = self._fake_clock()
        never_ready, observations = self._never_ready(
            runtime,
            ps,
            command(ps, stdout=process_table(running=False)),
            clock=clock,
            seconds_per_observation=14.25,
        )
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[
            1
        ], never_ready, self.assertRaises(GACollectionRecoveryRequired):
            self._collect(fixture, runtime)
        self.assertEqual(observations, [60, 60, 60])
        self.assertEqual(sleeps, [1.0, 0.5])

    def test_readiness_waits_only_for_state_that_is_not_ready_yet(self) -> None:
        # A valid observation of a Host not listed yet, or of a job launchd
        # has not started yet, is waited for. Any other rejection cannot be a
        # readiness delay, so it ends the step at its first observation.
        services = self.fixture.documents["service-registration.json"]["commands"]
        ps = list(PROCESS_OBSERVATION_COMMAND)
        second_host = (
            "201 501 Mon Jul 27 11:59:59 2026 "
            "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac\n"
        )
        foreign_team = copy.deepcopy(services["global_authority"])
        foreign_team["stdout"] = str(foreign_team["stdout"]).replace(
            '"team-identifier" => "YKUPL7Z869"', '"team-identifier" => "AAAAAAAAAA"'
        )
        predecessor = copy.deepcopy(services["proxy_agent"])
        predecessor["stdout"] = str(predecessor["stdout"]).replace(
            f"parent bundle version = {TO_BUILD}", f"parent bundle version = {FROM_BUILD}"
        )
        doubled = copy.deepcopy(services["proxy_agent"])
        doubled["stdout"] = str(doubled["stdout"]).replace(
            "\tstate = running\n", "\tstate = running\n\tstate = running\n"
        )
        cases = (
            (
                "two installed Hosts",
                ps,
                command(ps, stdout=process_table(running=True) + second_host),
                f"raw process table does not contain exactly one installed {TO_BUILD} Host",
                "launch-process-observation",
            ),
            (
                "malformed process table",
                ps,
                command(ps, stdout="not a process table\n"),
                "raw process-table output is malformed",
                "launch-process-observation",
            ),
            (
                "foreign-team GlobalAuthority",
                services["global_authority"]["argv"],
                foreign_team,
                "raw launchctl output does not show the fixed running GlobalAuthority",
                "authority-service-observation",
            ),
            (
                "predecessor ProxyAgent",
                services["proxy_agent"]["argv"],
                predecessor,
                "raw launchctl output does not show the fixed running ProxyAgent",
                "proxy-service-observation",
            ),
            (
                "doubled running state",
                services["proxy_agent"]["argv"],
                doubled,
                "raw launchctl output does not show the fixed running ProxyAgent",
                "proxy-service-observation",
            ),
            # A job that is not running yet is waited for only when it is
            # otherwise the fixed job; starting cannot change its identity.
            (
                "foreign-team GlobalAuthority not running yet",
                services["global_authority"]["argv"],
                self._service_not_running(foreign_team),
                "raw launchctl output does not show the fixed running GlobalAuthority",
                "authority-service-observation",
            ),
            (
                "predecessor ProxyAgent not running yet",
                services["proxy_agent"]["argv"],
                self._service_not_running(predecessor),
                "raw launchctl output does not show the fixed running ProxyAgent",
                "proxy-service-observation",
            ),
        )
        for label, argv, receipt, message, step in cases:
            with self.subTest(label):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                fixture.remove_unsealed_raw_tree()
                runtime = FakeCollectorRuntime(fixture)
                never_ready, observations = self._never_ready(runtime, list(argv), receipt)
                _clock, sleeps, clock_patches = self._fake_clock()
                sources = self._patch_evidence_sources()
                with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[
                    1
                ], never_ready, self.assertRaises(GACollectionRecoveryRequired) as raised:
                    self._collect(fixture, runtime)
                self.assertEqual(str(raised.exception.__cause__), message)
                self.assertEqual(len(observations), 1)
                self.assertEqual(sleeps, [])
                self.assertEqual(
                    collection_events(fixture.repository)[-2:],
                    [("started", step), RECOVERY_REQUIRED_EVENT],
                )

    def test_readiness_waits_never_repeat_a_failed_command(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        services = self.fixture.documents["service-registration.json"]["commands"]
        argv = tuple(services["proxy_agent"]["argv"])
        runtime.receipts[argv][0].update(exit_code=113, stdout="", stderr="Could not find service\n")
        _clock, sleeps, clock_patches = self._fake_clock()
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[1], self.assertRaises(
            GACollectionRecoveryRequired
        ) as raised:
            self._collect(self.fixture, runtime)
        self.assertEqual(
            str(raised.exception.__cause__),
            "GA collection proxy-service-observation command identity, exit, or duration is invalid",
        )
        self.assertEqual([called for called, _timeout in runtime.calls].count(list(argv)), 1)
        self.assertEqual(sleeps, [])

    def test_collect_validates_each_pre_traffic_receipt_when_its_step_completes(
        self,
    ) -> None:
        # A rejected receipt ends the collection at its own step, before any
        # traffic: before the mutation boundary nothing needs recovery.
        def install_command(name: str) -> Any:
            return lambda documents: documents["exact-dmg-install.json"]["commands"][name]

        cases = [
            (
                "Gatekeeper verdict",
                install_command("dmg_gatekeeper"),
                {"stderr": "rejected\nsource=Unnotarized Developer ID\n"},
                "raw DMG Gatekeeper output is not notarized acceptance",
                False,
                "dmg-gatekeeper",
            ),
            (
                "byte-proof result",
                install_command("dmg_set_verify"),
                {"stdout": "DMG release set verified: /Volumes/elsewhere\n"},
                "raw DMG verifier output is not the fixed byte-proof result",
                False,
                "dmg-contained-app-byte-proof",
            ),
            (
                "byte-proof diagnostics",
                install_command("dmg_set_verify"),
                {"stderr": "warning: fixture verifier diagnostic\n"},
                "raw DMG verifier output is not the fixed byte-proof result",
                False,
                "dmg-contained-app-byte-proof",
            ),
            (
                "launch diagnostics",
                lambda documents: documents["launch.json"]["launch_command"],
                {"stderr": "LSOpenURLsWithRole() failed with error -10810\n"},
                f"installed {TO_BUILD} launch command emitted an error",
                True,
                "launch",
            ),
        ] + [
            (
                f"{probe_id} rejection",
                lambda documents, index=index: documents["high-risk-rejections.json"][
                    "observations"
                ][index],
                {"stderr": "fixture accepted the request\n"},
                f"{probe_id} did not produce the fixed candidate rejection",
                True,
                f"high-risk-{probe_id}",
            )
            for index, (probe_id, _argv, _exit, _stderr) in enumerate(HIGH_RISK_PROBES)
        ]
        for label, select, changes, message, crossed, step in cases:
            with self.subTest(label):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                fixture.remove_unsealed_raw_tree()
                runtime = FakeCollectorRuntime(fixture)
                argv = tuple(select(fixture.documents)["argv"])
                runtime.receipts[argv][0].update(changes)
                _clock, sleeps, clock_patches = self._fake_clock()
                sources = self._patch_evidence_sources()
                expected_error = GACollectionRecoveryRequired if crossed else GARuntimeAcceptanceError
                with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[
                    1
                ], patch.object(
                    runtime, "capture_traffic", wraps=runtime.capture_traffic
                ) as traffic, self.assertRaises(expected_error) as raised:
                    self._collect(fixture, runtime)
                failure = raised.exception.__cause__ if crossed else raised.exception
                if not crossed:
                    self.assertNotIsInstance(raised.exception, GACollectionRecoveryRequired)
                self.assertEqual(str(failure), message)
                # A step without a readiness wait never repeats its command.
                self.assertEqual(sleeps, [])
                traffic.assert_not_called()
                self.assertEqual(
                    collection_events(fixture.repository)[-2:],
                    [
                        ("started", step),
                        RECOVERY_REQUIRED_EVENT if crossed else ABORTED_EVENT,
                    ],
                )
                commands = [called for called, _timeout in runtime.calls]
                if not crossed:
                    self.assertNotIn(["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"], commands)

    def test_collect_validates_post_traffic_receipts_before_shutdown_continues(
        self,
    ) -> None:
        cases = (
            (
                "system extension listing",
                lambda documents: documents["system-extension.json"]["command"],
                {"stdout": "0 extension(s)\n"},
                f"raw system extension output lacks the fixed {TO_BUILD} extension",
                "system-extension-observation",
            ),
            (
                "Off proof receipt",
                lambda documents: documents["shutdown-restore.json"]["off_proof_command"],
                {"stdout": ""},
                "signed installed Host did not prove the candidate globally Off",
                "shutdown-off-proof",
            ),
        )
        for label, select, changes, message, step in cases:
            with self.subTest(label):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                fixture.remove_unsealed_raw_tree()
                runtime = FakeCollectorRuntime(fixture)
                argv = tuple(select(fixture.documents)["argv"])
                runtime.receipts[argv][0].update(changes)
                _clock, sleeps, clock_patches = self._fake_clock()
                sources = self._patch_evidence_sources()
                with sources[0], sources[1], sources[2], clock_patches[0], clock_patches[
                    1
                ], patch.object(
                    runtime, "capture_stop_restore", wraps=runtime.capture_stop_restore
                ) as stop_restore, self.assertRaises(GACollectionRecoveryRequired) as raised:
                    self._collect(fixture, runtime)
                self.assertEqual(str(raised.exception.__cause__), message)
                self.assertEqual(sleeps, [])
                self.assertEqual(
                    collection_events(fixture.repository)[-2:],
                    [("started", step), RECOVERY_REQUIRED_EVENT],
                )
                if step == "system-extension-observation":
                    stop_restore.assert_not_called()
                # Nothing after the rejected step observes the restored guard.
                self.assertEqual(runtime.guards, [guard()])
                self.assertFalse(fixture.raw_root.exists())

    def test_terminal_collection_always_holds_a_proven_capture_password(self) -> None:
        # A cached sudo ticket can expire during the DMG proof and the operator
        # waits, before tcpdump's own sudo first reads the held password.
        runtime = self._capture_runtime()
        proven = ga_runtime.subprocess.CompletedProcess([], 0, b"tcpdump version 4.99\n", b"")
        with patch.object(
            runtime, "run", return_value={"exit_code": 0}
        ) as cached, patch.object(
            ga_runtime.sys.stdin, "isatty", return_value=True
        ), patch.object(
            ga_runtime.getpass, "getpass", return_value="fixture-authorization"
        ) as prompt, patch.object(
            ga_runtime, "run_bounded_process", return_value=proven
        ) as verify:
            runtime.require_capture_authority()
        prompt.assert_called_once_with("Authorize bounded CFM packet capture: ")
        cached.assert_not_called()
        self.assertEqual(runtime._capture_password, bytearray(b"fixture-authorization\n"))
        self.assertEqual(
            verify.call_args.args[0],
            [
                "/usr/bin/sudo",
                "-k",
                "-S",
                "-p",
                "CFM capture authorization: ",
                "--",
                "/usr/sbin/tcpdump",
                "--version",
            ],
        )
        self.assertEqual(verify.call_args.kwargs["input_bytes"], b"fixture-authorization\n")
        runtime.release_capture_authority()
        self.assertEqual(runtime._capture_password, bytearray())

    def test_terminal_capture_password_is_proven_despite_a_cached_ticket(self) -> None:
        # sudo -k ignores a cached ticket, so a mistyped password is refused
        # now rather than when tcpdump's sudo first needs it.
        runtime = self._capture_runtime()

        def sudo(argv: list[str], *, input_bytes: bytes, **_options: object) -> Any:
            # The cached ticket admits sudo without reading its input.
            admitted = "-k" not in argv or input_bytes == b"fixture-authorization\n"
            return ga_runtime.subprocess.CompletedProcess(argv, 0 if admitted else 1, b"", b"")

        with patch.object(runtime, "run", return_value={"exit_code": 1}), patch.object(
            ga_runtime.sys.stdin, "isatty", return_value=True
        ), patch.object(
            ga_runtime.getpass, "getpass", return_value="mistyped-authorization"
        ), patch.object(
            ga_runtime, "run_bounded_process", side_effect=sudo
        ), self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "^packet capture administrator authorization failed before collection$",
        ):
            runtime.require_capture_authority()
        self.assertEqual(runtime._capture_password, bytearray())

    def test_unattended_capture_relies_only_on_a_ticket_sudo_already_holds(self) -> None:
        runtime = self._capture_runtime()
        with patch.object(
            runtime, "run", return_value={"exit_code": 0}
        ) as cached, patch.object(
            ga_runtime.sys.stdin, "isatty", return_value=False
        ), patch.object(ga_runtime.getpass, "getpass") as prompt, patch.object(
            ga_runtime, "run_bounded_process"
        ) as verify:
            runtime.require_capture_authority()
        cached.assert_called_once_with(
            ["/usr/bin/sudo", "-n", "--", "/usr/sbin/tcpdump", "--version"], timeout=10
        )
        prompt.assert_not_called()
        verify.assert_not_called()
        self.assertEqual(runtime._capture_password, bytearray())

    def test_capture_authorization_boundary_failure_is_a_diagnosed_refusal(self) -> None:
        # sudo can be held past its ten seconds, or exit before reading its
        # input; either is the fixed refusal with its diagnosis, never a
        # traceback, and the held password is cleared.
        runtime = self._capture_runtime()
        token = "ghp_" + "S" * 30
        cases = (
            (
                ga_runtime.BoundedProcessError(
                    "timeout",
                    "bounded command timed out",
                    stdout=b"",
                    stderr=f"CFM capture authorization: {token}\n".encode("ascii"),
                ),
                [
                    "sudo verification failed its timeout boundary: timeout 10 s, output "
                    "limit 4096 bytes",
                    "sudo verification stdout is empty",
                    "sudo verification stderr (62 bytes) is withheld: it holds "
                    "credential-like material",
                ],
            ),
            (
                ga_runtime.BoundedProcessError("start", "bounded command could not start"),
                [
                    "sudo verification failed its start boundary: timeout 10 s, output "
                    "limit 4096 bytes",
                    "sudo verification retained no output",
                ],
            ),
        )
        for failure, notes in cases:
            with self.subTest(failure.reason):
                runtime._capture_password = bytearray(b"fixture-authorization\n")
                with patch.object(
                    ga_runtime, "run_bounded_process", side_effect=failure
                ), self.assertRaises(GARuntimeAcceptanceError) as raised:
                    runtime.require_capture_authority()
                self.assertEqual(
                    str(raised.exception),
                    "packet capture administrator authorization failed before collection",
                )
                self.assertIs(raised.exception.__cause__, failure)
                self.assertEqual(getattr(raised.exception, "__notes__", []), notes)
                self.assertEqual(runtime._capture_password, bytearray())
                rendered = common.failure_diagnostic("error: fixture headline", raised.exception)
                self.assertNotIn(token, rendered)
                self.assertNotIn("fixture-authorization", rendered)

    def test_terminal_password_that_is_not_utf8_is_refused_without_its_bytes(self) -> None:
        # A non-UTF-8 terminal makes getpass fail on the password's own bytes;
        # the refusal names neither a byte nor its position.
        runtime = self._capture_runtime()
        undecodable = UnicodeDecodeError("utf-8", b"pass\xe9word", 4, 5, "invalid continuation byte")
        for label, prompt in (
            ("undecodable input", {"side_effect": undecodable}),
            ("unencodable input", {"return_value": "pass\udce9word"}),
        ):
            with self.subTest(label):
                with patch.object(
                    ga_runtime.sys.stdin, "isatty", return_value=True
                ), patch.object(ga_runtime.getpass, "getpass", **prompt), patch.object(
                    ga_runtime, "run_bounded_process"
                ) as verify, self.assertRaises(GARuntimeAcceptanceError) as raised:
                    runtime.require_capture_authority()
                self.assertEqual(
                    str(raised.exception),
                    "packet capture authorization input is not UTF-8",
                )
                rendered = common.failure_diagnostic(
                    "error: fixture headline", raised.exception
                )
                self.assertNotIn("0xe9", rendered)
                self.assertNotIn("position", rendered)
                verify.assert_not_called()
                self.assertEqual(runtime._capture_password, bytearray())

    def test_bounded_command_failure_without_output_says_so(self) -> None:
        runtime = self._capture_runtime()
        failure = ga_runtime.BoundedProcessError("start", "bounded command could not start")
        with patch.object(
            ga_runtime, "run_bounded_process", side_effect=failure
        ), self.assertRaises(GARuntimeAcceptanceError) as raised:
            runtime.run(["/usr/bin/systemextensionsctl", "list"], timeout=60)
        self.assertEqual(
            getattr(raised.exception, "__notes__", []),
            [
                'command ["/usr/bin/systemextensionsctl", "list"] failed its start '
                "boundary: timeout 60 s, output limit 262144 bytes",
                "bounded command retained no output",
            ],
        )

    def test_bounded_command_failure_keeps_escaped_tails_and_withholds_credentials(
        self,
    ) -> None:
        runtime = self._capture_runtime()
        token = "ghp_" + "R" * 30
        failure = ga_runtime.BoundedProcessError(
            "timeout",
            "bounded command timed out",
            stdout=b"partial \x1b[31mred\n",
            stderr=f"retrying with {token}\n".encode("ascii"),
        )
        with patch.object(
            ga_runtime, "run_bounded_process", side_effect=failure
        ), self.assertRaises(GARuntimeAcceptanceError) as raised:
            runtime.run(["/usr/sbin/spctl", "--assess", "--type", "open"], timeout=60)
        self.assertEqual(
            str(raised.exception),
            "fixed GA collection command failed its bounded process boundary",
        )
        self.assertIs(raised.exception.__cause__, failure)
        self.assertEqual(
            getattr(raised.exception, "__notes__", []),
            [
                'command ["/usr/sbin/spctl", "--assess", "--type", "open"] failed its '
                "timeout boundary: timeout 60 s, output limit 262144 bytes",
                "bounded command stdout (17 bytes) ends with:\npartial \\x1b[31mred\n",
                "bounded command stderr (49 bytes) is withheld: it holds credential-like "
                "material",
            ],
        )
        rendered = common.failure_diagnostic("error: fixture headline", raised.exception)
        self.assertNotIn(token, rendered)
        self.assertNotIn("\x1b", rendered)

    def test_terminal_refusal_records_nothing_so_collect_runs_again_at_once(self) -> None:
        # RELEASE.md step 7: the terminal refusal comes before the collection
        # intent, so a fresh collect from a terminal follows it without recover.
        refused = FakeCollectorRuntime(self.fixture)
        no_terminal = GARuntimeAcceptanceError(
            "packet capture needs administrator authorization in a terminal "
            "before collection"
        )
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], patch.object(
            refused, "require_capture_authority", side_effect=no_terminal
        ), self.assertRaises(GARuntimeAcceptanceError) as raised:
            self._collect(self.fixture, refused)
        self.assertIs(raised.exception, no_terminal)
        self.assertEqual(raised.exception.__notes__, [PREFLIGHT_RETRY_GUIDANCE])
        self.assertEqual(refused.calls, [])
        self.assertFalse(self.fixture.collection_root.exists())
        # recover has nothing to archive.
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), self.assertRaisesRegex(
            GARuntimeAcceptanceError, "^there is no active GA runtime collection to recover$"
        ):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=FakeCollectorRuntime(self.fixture),
            )
        fresh = FakeCollectorRuntime(self.fixture)
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2]:
            collected = self._collect(self.fixture, fresh)
        self.assertEqual(collected, self.fixture.validate())
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )

    def test_no_terminal_never_reads_password_from_unattended_input(self) -> None:
        runtime = self._capture_runtime()
        with patch.object(runtime, "run", return_value={"exit_code": 1}), patch.object(ga_runtime.sys.stdin, "isatty", return_value=False), patch.object(ga_runtime.getpass, "getpass") as prompt:
            with self.assertRaisesRegex(GARuntimeAcceptanceError, "terminal before collection"):
                runtime.require_capture_authority()
        prompt.assert_not_called()
        self.assertEqual(runtime._capture_password, bytearray())

    def test_capture_authorization_uses_private_input_and_clears_on_failure(self) -> None:
        runtime = self._capture_runtime()
        credential = bytearray(b"fixture-authorization\n")
        runtime._capture_password = credential
        failed = ga_runtime.subprocess.CompletedProcess([], 1, b"", b"authorization denied")
        with patch.object(ga_runtime, "run_bounded_process", return_value=failed) as runner:
            with self.assertRaisesRegex(GARuntimeAcceptanceError, "authorization failed"):
                runtime.require_capture_authority()
        self.assertEqual(runner.call_args.kwargs["input_bytes"], b"fixture-authorization\n")
        self.assertNotIn("fixture-authorization", repr(runner.call_args.args))
        self.assertNotIn("fixture-authorization", repr(runner.call_args.kwargs["environment"]))
        self.assertEqual(credential, bytearray())

    def test_capture_refuses_root_or_changed_effective_identity(self) -> None:
        for uid, effective in ((0, 0), (501, 0)):
            with self.subTest(uid=uid), patch.object(ga_runtime.os, "getuid", return_value=uid), patch.object(ga_runtime.os, "geteuid", return_value=effective):
                with self.assertRaisesRegex(GARuntimeAcceptanceError, "ordinary release account"):
                    ga_runtime._capture_command_argv("utun6", ())

    def test_sender_failure_or_expired_budget_stops_before_later_markers(self) -> None:
        for sender_seconds, exit_code, message in (
            (0, 1, "start collection sender"),
            (46, 0, "complete bounded deadline"),
        ):
            with self.subTest(sender_seconds=sender_seconds, exit_code=exit_code):
                runtime = self._capture_runtime()
                process = self._CaptureProcess(None, self._CapturePipe(22))
                process.poll = lambda: None
                def communicate(timeout):
                    process.returncode = 0
                    return None, b""
                process.communicate = communicate
                def spawn(argv, **options):
                    # tcpdump wrote these bytes into its pcap file before it
                    # was stopped.
                    options["stdout"].write(b"failed fixture packet")
                    options["stdout"].flush()
                    return process
                selector = MagicMock()
                selector.select.return_value = [(SimpleNamespace(fd=22), 0)]
                elapsed = [0.0]
                sent = []
                interpreters = []
                def send(argv, *, timeout):
                    sent.append((argv[argv.index("--stage") + 1], timeout))
                    interpreters.append(argv[0])
                    elapsed[0] += sender_seconds
                    return command(argv, exit_code=exit_code, stderr="resolver failed" if exit_code else "")
                with patch.object(runtime, "_tunnel_interface", return_value="utun6"), \
                     patch.object(runtime, "run", side_effect=send), \
                     patch.object(runtime, "_terminate_capture") as terminate, \
                     patch.object(ga_runtime.subprocess, "Popen", side_effect=spawn) as popen, \
                     patch.object(ga_runtime.selectors, "DefaultSelector", return_value=selector), \
                     patch.object(ga_runtime.os, "set_blocking"), \
                     patch.object(ga_runtime.os, "read", side_effect=[b"listening on utun6\n", b""]), \
                     patch.object(ga_runtime.time, "monotonic", side_effect=lambda: elapsed[0]), \
                     patch.object(ga_runtime.time, "sleep"), \
                     patch.object(ga_runtime, "parse_packet_capture", return_value=SimpleNamespace(interfaces=[SimpleNamespace(link_type=0)])):
                    with self.assertRaisesRegex(GARuntimeAcceptanceError, message) as failure:
                        runtime._capture_traffic_bytes(
                            "dns_traffic",
                            RuntimeFixture._traffic_tokens("dns_traffic"),
                            interpreter=OTHER_COLLECTOR["python"]["executable"],
                        )
                self.assertEqual([stage for stage, _ in sent], ["start"])
                # Senders run with the collection's recorded Python.
                self.assertEqual(interpreters, [OTHER_COLLECTOR["python"]["executable"]])
                self.assertLessEqual(sent[0][1], 35)
                terminate.assert_called_once_with(process)
                self.assertTrue(popen.call_args.kwargs["stdout"].closed)
                self.assertTrue(process.stderr.closed)
                retained = failure.exception.packet_capture_failure
                self.assertEqual(retained.packet_bytes, b"failed fixture packet")
                self.assertEqual(retained.stderr_bytes, b"listening on utun6\n")
                self.assertTrue(retained.outputs_complete)
                self.assertIs(retained.command["acceptance_valid"], False)
                self.assertEqual(len(retained.send_commands), 1)
                self.assertEqual(retained.retention_errors, ())
                # The failed capture's text diagnostics reach the operator as
                # notes; its packet bytes are counted, never shown.
                notes = getattr(failure.exception, "__notes__", [])
                self.assertEqual(
                    notes[-2:],
                    [
                        "dns_traffic tcpdump ran under sudo pid 525252; exit status "
                        "unavailable; 21 packet bytes retained, not shown; outputs complete",
                        "dns_traffic tcpdump stderr (19 bytes) ends "
                        "with:\nlistening on utun6\n",
                    ],
                )
                self.assertNotIn("failed fixture packet", "\n".join(notes))
                if exit_code:
                    # The rejected sender keeps its own diagnosis first.
                    self.assertEqual(
                        notes[0],
                        "dns_traffic start collection sender failed its exit check: exit "
                        "status 1, expected 0; duration 7.000 s, bound 35 s",
                    )

    def test_dns_collection_captures_the_tunnel_leg(self) -> None:
        # The real decoder, endpoint derivation and marker window run on a
        # RAW utun capture; only the processes and the clock's sleeps are
        # faked. The observed collection used the IPv6 leg for every stage;
        # the marker window reads the start and end stages, so the second
        # shape moves the end marker to the IPv4 leg.
        tokens = RuntimeFixture._traffic_tokens("dns_traffic")
        observed_packets = _tunnel_dns_packets(tokens)
        client, resolver = IPV4_DNS_LEG
        ipv4_start = _tunnel_dns_query(0x5A11, f"{tokens['start']}.evidence.test")
        # The start query goes unanswered on the IPv6 leg and is asked again,
        # and answered, on the IPv4 leg; the target query is repeated.
        start_failover = (
            observed_packets[:1]
            + observed_packets[2:]
            + [
                _tunnel_dns_retransmission(observed_packets, 2, 1.20),
                (0.21, client, 53101, resolver, 53, ipv4_start),
                (0.31, resolver, 53, client, 53101, _tunnel_dns_response(ipv4_start)),
            ]
        )
        for packets, families in (
            (observed_packets, OBSERVED_DNS_FAMILIES),
            (
                _tunnel_dns_packets(
                    tokens, families={"start": "ipv6", "target": "ipv4", "end": "ipv4"}
                ),
                {"start": "ipv6", "target": "ipv4", "end": "ipv4"},
            ),
            (start_failover, {"start": "ipv4", "target": "ipv6", "end": "ipv6"}),
        ):
            with self.subTest(families=families):
                capture = _utun_udp_pcap(packets)
                traffic, observed, expected_argv = self._collect_dns_capture(
                    tokens, capture
                )
                self.assertEqual(traffic["capture_command"]["argv"], expected_argv)
                self.assertEqual(observed, capture)
                self.assertEqual(
                    traffic["endpoint"],
                    {
                        "interface_name": "utun6",
                        "link_type": 101,
                        "remote_port": 53,
                        "stage_families": families,
                    },
                )
                self.assertEqual(traffic["observation_ms"], DNS_OBSERVATION_MS)

    def _collect_dns_capture(
        self, tokens: dict[str, str], capture: bytes
    ) -> tuple[dict[str, Any], bytes, list[str]]:
        self.assertEqual(tokens, RuntimeFixture._traffic_tokens("dns_traffic"))
        result = self._run_fake_tcpdump(capture, self._statistics(capture))
        if result.error is not None:
            raise result.error
        expected_argv = ga_runtime._capture_command_argv(
            "utun6", _expected_tunnel_dns_filter(tokens)
        )
        result.terminate.assert_not_called()
        self.assertEqual(
            [event[1] for event in result.events if event[0] == "send"], list(DNS_STAGES)
        )
        self.assertEqual(result.argv, expected_argv)
        self.assertTrue(result.process.stderr.closed)
        return result.traffic, result.capture, expected_argv

    TCPDUMP_READY = (
        b"tcpdump: listening on utun6, link-type RAW (Raw IP), snapshot length "
        b"262144 bytes\n"
    )
    # _CaptureProcess is sudo; the tcpdump it forks runs as the operator.
    SUDO_PID = 525_252
    TCPDUMP_PID = 525_253

    @staticmethod
    def _process_row(
        pid: int,
        parent: int,
        uid: int,
        name: str,
        *,
        real_uid: int | None = None,
        saved_uid: int | None = None,
        state: str = "S",
    ) -> str:
        """One capture_process_argv row as ps pads it.

        The real and saved IDs default to uid.
        """

        real = uid if real_uid is None else real_uid
        saved = uid if saved_uid is None else saved_uid
        return f"{pid:>6} {parent:>6} {real:>5} {uid:>5} {saved:>5} {state:<4} {name:<16}"

    @classmethod
    def _capture_processes(cls, *rows: str) -> str:
        """capture_process_argv's output: sudo, which leads the group, and rows.

        Without rows, sudo forked tcpdump, which now runs as the operator.
        """

        tcpdump = cls._process_row(cls.TCPDUMP_PID, cls.SUDO_PID, os.getuid(), "tcpdump")
        return "".join(
            f"{line}\n"
            for line in (
                cls._process_row(cls.SUDO_PID, 4000, 0, "sudo", state="Ss"),
                *(rows or (tcpdump,)),
            )
        )

    @staticmethod
    def _receipt_clock() -> Any:
        """_utc_now for a capture receipt around the fixture's sender receipts."""

        times = iter(["2026-07-27T11:59:59.000000Z"])
        return lambda: next(times, "2026-07-27T12:00:06.000000Z")

    @staticmethod
    def _statistics(capture: bytes) -> bytes:
        """tcpdump's statistics when it wrote every record of capture."""

        count = len(_pcap_records(capture))
        return (
            b"%d packets captured\n%d packets received by filter\n"
            b"0 packets dropped by kernel\n" % (count, count)
        )

    def _run_fake_tcpdump(
        self,
        capture: bytes,
        statistics: bytes,
        *,
        check_id: str = "dns_traffic",
        returncode: int = 0,
        stops_itself: bool = False,
        stops_while_observed: bool = False,
        survives_interrupt: bool = False,
        interrupt_error: BaseException | None = None,
        stderr_stays_open: bool = False,
        stderr_read_error: BaseException | None = None,
        stderr_close_error: bool = False,
        selector_close_error: bool = False,
        cleanup_failure: BaseException | None = None,
        processes: str | None = None,
    ) -> SimpleNamespace:
        """Run a check's exercise against a fake sudo and tcpdump.

        The fake writes capture as its pcap into the output Popen hands it
        and reports readiness. Once interrupted, or after the end sender when
        stops_itself, as at its packet cap, it exits with returncode and
        statistics on stderr; stops_while_observed makes it exit while the
        collector reads the process table. When survives_interrupt it keeps
        running, and waiting for it times out after it wrote "partial" to
        stderr; interrupt_error is what the kernel answers the interrupt
        with. With stderr_stays_open its stderr has nothing more to read but
        stays open; stderr_read_error is what reading it after readiness
        raises instead; with stderr_close_error closing it fails, as closing the
        output selector does with selector_close_error. processes is
        the process group listing the collector reads to find tcpdump
        (_capture_processes by default), and cleanup_failure what cleaning up
        a failed capture raises. Only the collector's sleeps and waits for
        output advance its clock. The capture receipt spans the fixture's
        sender receipts. The result keeps the exercise's events in order, the
        output file and its status, the timeouts the collector observed and
        waited on tcpdump with, the traffic or the failure, and the cleanup
        and group-signal mocks.
        """

        runtime = self._capture_runtime()
        receipts = dict(
            zip(
                DNS_STAGES,
                self.fixture.documents[f"{check_id.replace('_', '-')}.json"][
                    "send_commands"
                ],
                strict=True,
            )
        )
        process = self._CaptureProcess(
            None, self._CapturePipe(22, close_error=stderr_close_error)
        )
        result = SimpleNamespace(
            events=[],
            argv=None,
            output_file=None,
            output=None,
            observation_timeouts=[],
            stop_timeouts=[],
            traffic=None,
            capture=None,
            error=None,
        )

        def spawn(argv, **options):
            result.argv = list(argv)
            result.output_file = options["stdout"]
            result.output = os.fstat(options["stdout"].fileno())
            snaplen = struct.pack("<I", _tcpdump_snapshot_length(result.argv))
            options["stdout"].write(capture[:16] + snaplen + capture[20:])
            options["stdout"].flush()
            return process

        def poll():
            sends = [event for event in result.events if event[0] == "send"]
            interrupted = any(event[0] == "interrupt" for event in result.events)
            observed = ("observe processes",) in result.events
            if (
                (interrupted and not survives_interrupt and interrupt_error is None)
                or (stops_itself and len(sends) == 3)
                or (stops_while_observed and observed)
            ):
                process.returncode = returncode
            return process.returncode

        def communicate(timeout):
            result.stop_timeouts.append(timeout)
            if survives_interrupt:
                raise subprocess.TimeoutExpired(result.argv, timeout, stderr=b"partial")
            process.returncode = returncode
            return None, statistics

        def send(argv, *, timeout):
            if argv == capture_process_argv(self.SUDO_PID):
                result.events.append(("observe processes",))
                result.observation_timeouts.append(timeout)
                # ps lists the group within a tenth of a second.
                return command(
                    argv,
                    stdout=self._capture_processes() if processes is None else processes,
                    started_at="2026-07-27T12:00:05.600000Z",
                    finished_at="2026-07-27T12:00:05.700000Z",
                )
            stage = argv[argv.index("--stage") + 1]
            result.events.append(("send", stage))
            return copy.deepcopy(receipts[stage])

        clock = [0.0]

        def sleep(seconds):
            result.events.append(("sleep", seconds))
            clock[0] += seconds

        def select(timeout):
            clock[0] += timeout
            return [(SimpleNamespace(fd=22), 0)]

        def kill(pid, number):
            result.events.append(("interrupt", pid, number))
            if interrupt_error is not None:
                raise interrupt_error

        def read(_descriptor, _size):
            chunk = next(reads, b"")
            if isinstance(chunk, BaseException):
                raise chunk
            return chunk

        process.pid = self.SUDO_PID
        process.poll = poll
        process.communicate = communicate
        reads = iter(
            [self.TCPDUMP_READY, BlockingIOError()]
            if stderr_stays_open
            else [self.TCPDUMP_READY, stderr_read_error]
            if stderr_read_error is not None
            else [self.TCPDUMP_READY, statistics]
        )
        selector = MagicMock()
        selector.select.side_effect = select
        if selector_close_error:
            selector.close.side_effect = OSError("fixture selector close failure")
        with patch.object(runtime, "_tunnel_interface", return_value="utun6"), \
             patch.object(runtime, "run", side_effect=send), \
             patch.object(
                 runtime, "_terminate_capture", side_effect=cleanup_failure
             ) as terminate, \
             patch.object(ga_runtime.subprocess, "Popen", side_effect=spawn), \
             patch.object(ga_runtime.selectors, "DefaultSelector", return_value=selector), \
             patch.object(ga_runtime.os, "set_blocking"), \
             patch.object(ga_runtime.os, "read", side_effect=read), \
             patch.object(ga_runtime.os, "kill", side_effect=kill), \
             patch.object(ga_runtime.os, "killpg") as killpg, \
             patch.object(
                 ga_runtime, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep)
             ), \
             patch.object(ga_runtime, "_utc_now", side_effect=self._receipt_clock()):
            try:
                result.traffic, result.capture = runtime._capture_traffic_bytes(
                    check_id,
                    RuntimeFixture._traffic_tokens(check_id),
                    interpreter=sys.executable,
                )
            except GARuntimeAcceptanceError as error:
                result.error = error
        result.process = process
        result.terminate = terminate
        result.killpg = killpg
        return result

    def test_capture_stops_tcpdump_with_one_interrupt_after_the_settle(self) -> None:
        tokens = RuntimeFixture._traffic_tokens("dns_traffic")
        capture = _utun_udp_pcap(_tunnel_dns_packets(tokens))
        statistics = self._statistics(capture)
        result = self._run_fake_tcpdump(capture, statistics)
        self.assertIsNone(result.error)
        # tcpdump keeps capturing through the senders and the settle; then its
        # own process, which -Z made the operator's, gets the only signal.
        # sudo, which may run as root, gets none and so relays none, and no
        # group signal could reach tcpdump a second time.
        self.assertEqual(ga_runtime.CAPTURE_SETTLE_SECONDS, 1.5)
        self.assertEqual(
            result.events,
            [
                ("send", "start"),
                ("sleep", 1.1),
                ("send", "target"),
                ("sleep", 1.1),
                ("send", "end"),
                ("sleep", 1.5),
                ("observe processes",),
                ("interrupt", self.TCPDUMP_PID, signal.SIGINT),
            ],
        )
        result.killpg.assert_not_called()
        result.terminate.assert_not_called()
        # The process observation is bounded at ten seconds, and the wait for
        # tcpdump to exit by what remains of the exercise after readiness,
        # the two marker gaps and the settle.
        self.assertEqual(result.observation_timeouts, [10])
        self.assertEqual(result.stop_timeouts, [ga_runtime.PACKET_EXERCISE_SECONDS - 4])
        self.assertEqual(result.argv[result.argv.index("-c") + 1], "32")
        self.assertEqual(result.argv[-1], _expected_tunnel_dns_filter(tokens)[0])
        self.assertEqual(result.capture, capture)
        self.assertEqual(
            result.traffic["capture_command"]["stderr"],
            (self.TCPDUMP_READY + statistics).decode("ascii"),
        )
        self.assertEqual(result.traffic["capture_command"]["exit_code"], 0)
        self.assertEqual(result.traffic["observation_ms"], DNS_OBSERVATION_MS)
        # tcpdump writes into an unlinked regular file, never a pipe, which
        # the collector closes once it has read it.
        self.assertTrue(stat.S_ISREG(result.output.st_mode))
        self.assertEqual(result.output.st_nlink, 0)
        self.assertEqual(stat.S_IMODE(result.output.st_mode), 0o600)
        self.assertTrue(result.output_file.closed)

    def test_capture_that_ignores_its_interrupt_fails_with_its_partial_output(
        self,
    ) -> None:
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        result = self._run_fake_tcpdump(capture, b"", survives_interrupt=True)
        self.assertEqual(
            str(result.error), "tcpdump did not stop after the collector interrupted it"
        )
        self.assertIsInstance(result.error.__cause__, subprocess.TimeoutExpired)
        self.assertEqual(
            [event for event in result.events if event[0] == "interrupt"],
            [("interrupt", self.TCPDUMP_PID, signal.SIGINT)],
        )
        result.killpg.assert_not_called()
        result.terminate.assert_called_once_with(result.process)
        retained = result.error.packet_capture_failure
        self.assertEqual(retained.packet_bytes, capture)
        self.assertEqual(retained.stderr_bytes, self.TCPDUMP_READY + b"partial")
        self.assertIsNone(retained.command["exit_code"])
        self.assertTrue(result.output_file.closed)

    def test_capture_refuses_a_settle_the_exercise_has_no_time_for(self) -> None:
        # The settle is the last packet time before the stop; a settle that
        # leaves the stop less than its time is refused before it starts, so
        # tcpdump is never killed without its statistics after the settle.
        # The readiness wait and the two marker gaps take 2.3 s, so 32.7 s of
        # the exercise remain after the end marker's sender.
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        remaining = ga_runtime.PACKET_EXERCISE_SECONDS - (0.1 + 1.1 + 1.1)
        stop = ga_runtime.CAPTURE_STOP_SECONDS
        for label, settle in (
            ("settle and stop a quarter second short", remaining - stop + 0.25),
            ("half a second left after the settle", remaining - 0.5),
            ("settle as long as the exercise", ga_runtime.PACKET_EXERCISE_SECONDS),
        ):
            with self.subTest(label), patch.object(
                ga_runtime, "CAPTURE_SETTLE_SECONDS", settle
            ):
                result = self._run_fake_tcpdump(capture, b"")
                self.assertEqual(
                    str(result.error),
                    "packet exercise has no time for the capture settle and stop",
                )
                self.assertEqual(
                    result.events,
                    [
                        ("send", "start"),
                        ("sleep", 1.1),
                        ("send", "target"),
                        ("sleep", 1.1),
                        ("send", "end"),
                    ],
                )
                result.terminate.assert_called_once_with(result.process)
                self.assertEqual(
                    result.error.packet_capture_failure.stderr_bytes, self.TCPDUMP_READY
                )
        # Exactly the stop's time left after the settle suffices: the process
        # observation and the wait for tcpdump get two seconds each.
        with patch.object(ga_runtime, "CAPTURE_SETTLE_SECONDS", remaining - stop):
            result = self._run_fake_tcpdump(capture, self._statistics(capture))
        self.assertIsNone(result.error)
        self.assertEqual(
            result.events[-3:],
            [
                ("sleep", remaining - stop),
                ("observe processes",),
                ("interrupt", self.TCPDUMP_PID, signal.SIGINT),
            ],
        )
        self.assertEqual((result.observation_timeouts, result.stop_timeouts), ([2], [2]))

    def test_capture_observation_and_stop_share_what_remains_of_the_exercise(
        self,
    ) -> None:
        # A settle of 25 s leaves 7.7 s after readiness, the marker gaps and
        # the settle: the observation and the wait for tcpdump get 7 s each.
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        with patch.object(ga_runtime, "CAPTURE_SETTLE_SECONDS", 25):
            result = self._run_fake_tcpdump(capture, self._statistics(capture))
        self.assertIsNone(result.error)
        self.assertEqual(result.observation_timeouts, [7])
        self.assertEqual(result.stop_timeouts, [7])

    def test_capture_interrupts_only_the_tcpdump_its_sudo_runs(self) -> None:
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        op = os.getuid()
        row = self._process_row
        tcpdump = row(self.TCPDUMP_PID, self.SUDO_PID, op, "tcpdump")
        not_one = "tcpdump is not one process under its sudo"
        other_user = "tcpdump still runs as a user other than the operator"
        sudo = f"{self.SUDO_PID} 4000 0/0/0 Ss sudo"
        child = f"{self.TCPDUMP_PID} {self.SUDO_PID}"
        nine = [row(self.TCPDUMP_PID + index, self.SUDO_PID, op, "tcpdump") for index in range(9)]
        cases = (
            ("sudo forked tcpdump", None, self.TCPDUMP_PID, None, None),
            # sudo executes tcpdump in place when its policy has no close
            # function, so sudo's own process is tcpdump and leads the group.
            (
                "sudo executed tcpdump in place",
                row(self.SUDO_PID, 4000, op, "tcpdump") + "\n",
                self.SUDO_PID,
                None,
                None,
            ),
            # A process of the group that sudo does not run, as an orphan; the
            # note shows every row of the group.
            (
                "no tcpdump under sudo",
                self._capture_processes(row(4100, 1, op, "tcpdump")),
                None,
                not_one,
                f"{sudo}; 4100 1 {op}/{op}/{op} S tcpdump",
            ),
            (
                "two tcpdumps under sudo",
                self._capture_processes(
                    tcpdump, row(self.TCPDUMP_PID + 1, self.SUDO_PID, op, "tcpdump")
                ),
                None,
                not_one,
                f"{sudo}; {child} {op}/{op}/{op} S tcpdump; "
                f"{self.TCPDUMP_PID + 1} {self.SUDO_PID} {op}/{op}/{op} S tcpdump",
            ),
            (
                "nine tcpdumps under sudo",
                self._capture_processes(*nine),
                None,
                not_one,
                "; ".join(
                    [
                        sudo,
                        *(
                            f"{self.TCPDUMP_PID + index} {self.SUDO_PID} {op}/{op}/{op} S tcpdump"
                            for index in range(7)
                        ),
                        "2 more",
                    ]
                ),
            ),
            # The accounting name is the executable's; argv[0], which any
            # process may set, is not read. A name is noted inert.
            (
                "only another program under sudo",
                self._capture_processes(row(self.TCPDUMP_PID, self.SUDO_PID, op, "sleep")),
                None,
                not_one,
                f"{sudo}; {child} {op}/{op}/{op} S sleep",
            ),
            (
                "only a program with a control byte in its name",
                self._capture_processes(row(self.TCPDUMP_PID, self.SUDO_PID, op, "tcp\x1bdump")),
                None,
                not_one,
                f'{sudo}; {child} {op}/{op}/{op} S "tcp\\u001bdump"',
            ),
            (
                "tcpdump still root",
                self._capture_processes(row(self.TCPDUMP_PID, self.SUDO_PID, 0, "tcpdump")),
                None,
                other_user,
                f"{sudo}; {child} 0/0/0 S tcpdump",
            ),
            (
                "tcpdump of another account",
                self._capture_processes(row(self.TCPDUMP_PID, self.SUDO_PID, op + 1, "tcpdump")),
                None,
                other_user,
                f"{sudo}; {child} {op + 1}/{op + 1}/{op + 1} S tcpdump",
            ),
            # The kernel delivers the operator's signal only to a process whose
            # real or saved user ID is the operator's; -Z sets all three, and
            # each is checked.
            (
                "tcpdump with a root real user ID",
                self._capture_processes(
                    row(self.TCPDUMP_PID, self.SUDO_PID, op, "tcpdump", real_uid=0)
                ),
                None,
                other_user,
                f"{sudo}; {child} 0/{op}/{op} S tcpdump",
            ),
            (
                "tcpdump with a root effective user ID",
                self._capture_processes(
                    row(self.TCPDUMP_PID, self.SUDO_PID, 0, "tcpdump", real_uid=op, saved_uid=op)
                ),
                None,
                other_user,
                f"{sudo}; {child} {op}/0/{op} S tcpdump",
            ),
            (
                "tcpdump with a root saved user ID",
                self._capture_processes(
                    row(self.TCPDUMP_PID, self.SUDO_PID, op, "tcpdump", saved_uid=0)
                ),
                None,
                other_user,
                f"{sudo}; {child} {op}/{op}/0 S tcpdump",
            ),
            (
                "malformed process listing",
                self._capture_processes(tcpdump, "4200 not-a-parent 501 501 501 S zsh"),
                None,
                "tcpdump process observation is malformed",
                None,
            ),
        )
        for label, processes, interrupted, message, note in cases:
            with self.subTest(label):
                result = self._run_fake_tcpdump(
                    capture, self._statistics(capture), processes=processes
                )
                interrupts = [event for event in result.events if event[0] == "interrupt"]
                result.killpg.assert_not_called()
                if message is None:
                    self.assertIsNone(result.error)
                    self.assertEqual(interrupts, [("interrupt", interrupted, signal.SIGINT)])
                else:
                    self.assertEqual(str(result.error), message)
                    self.assertEqual(interrupts, [])
                    result.terminate.assert_called_once_with(result.process)
                if note is not None:
                    # The refusal keeps the rows of sudo's process group.
                    self.assertEqual(
                        result.error.__notes__[0],
                        f"processes in the group of this capture's sudo: {note}",
                    )

    def test_capture_process_rows_are_read_as_ps_prints_them(self) -> None:
        # ps pads each accounting name to 16 columns, prints nobody's IDs as
        # -2 and keeps spaces in a name.
        listing = "".join(
            f"{line}\n"
            for line in (
                "525252   4000     0     0     0 Ss   sudo            ",
                "525253 525252   501   501   501 S    tcpdump         ",
                "525254 525252    -2    -2    -2 S    Google Chrome He",
                "   600      1   501   501   501 S    tcpdump         ",
            )
        )
        self.assertEqual(
            ga_runtime._capture_process_rows(listing),
            [
                ga_runtime._CaptureProcessRow(525_252, 4000, (0, 0, 0), "Ss", "sudo"),
                ga_runtime._CaptureProcessRow(525_253, 525_252, (501, 501, 501), "S", "tcpdump"),
                ga_runtime._CaptureProcessRow(
                    525_254, 525_252, (-2, -2, -2), "S", "Google Chrome He"
                ),
                ga_runtime._CaptureProcessRow(600, 1, (501, 501, 501), "S", "tcpdump"),
            ],
        )
        # A note escapes every field ps prints as text.
        self.assertEqual(
            ga_runtime._CaptureProcessRow(1, 2, (3, 4, 5), "S\x1b", "x y").note(),
            '1 2 3/4/5 "S\\u001b" "x y"',
        )

    # The former row pattern, whose lazy name `(.+?)\s*` to the end of the
    # row took quadratic time over a run of whitespace inside the name. It is
    # the oracle for which rows are accepted and the fields read from them.
    FORMER_CAPTURE_PROCESS_ROW_RE = re.compile(
        r"\s*([1-9][0-9]*)\s+([0-9]+)\s+(-?[0-9]+)\s+(-?[0-9]+)\s+(-?[0-9]+)\s+(\S+)\s+(.+?)\s*"
    )

    def test_capture_process_rows_read_as_the_former_pattern_read_them(self) -> None:
        # Every name of up to five characters from whitespace, including a
        # tab and a no-break space, and other characters, after each prefix.
        prefixes = (
            "525253 525252   501   501   501 S",
            "   600      1    -2    -2    -2 Ss",
            "1 2 3 4 5",
            "1 2 3 4 5 S\t",
        )
        alphabet = (" ", "\t", "\xa0", "t", "-")
        lines = [
            prefix + "".join(name)
            for prefix in prefixes
            for length in range(6)
            for name in itertools.product(alphabet, repeat=length)
        ]
        for line in lines:
            former = self.FORMER_CAPTURE_PROCESS_ROW_RE.fullmatch(line)
            if former is None:
                with self.assertRaisesRegex(
                    GARuntimeAcceptanceError, "^tcpdump process observation is malformed$"
                ):
                    ga_runtime._capture_process_rows(line)
                continue
            pid, parent, real, effective, saved, state, name = former.groups()
            self.assertEqual(
                ga_runtime._capture_process_rows(line),
                [
                    ga_runtime._CaptureProcessRow(
                        int(pid),
                        int(parent),
                        (int(real), int(effective), int(saved)),
                        state,
                        name,
                    )
                ],
                repr(line),
            )

    def test_capture_process_row_with_a_long_name_is_read_in_linear_time(self) -> None:
        # The former pattern took about nine seconds for this row.
        name = "t" + " " * 50_000 + "cpdump"
        started = time.perf_counter()
        rows = ga_runtime._capture_process_rows(f"525253 525252 501 501 501 S {name} \n")
        elapsed = time.perf_counter() - started
        self.assertEqual(
            rows, [ga_runtime._CaptureProcessRow(525_253, 525_252, (501, 501, 501), "S", name)]
        )
        self.assertLess(elapsed, 1.0)

    def test_capture_that_stops_while_the_collector_stops_it_fails_as_stopped(
        self,
    ) -> None:
        # tcpdump can reach its cap after the collector saw sudo running and
        # before its interrupt arrives; each way that shows fails as the
        # capture that stopped itself, never as a malformed observation.
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        op = os.getuid()
        stopped = "tcpdump stopped before the collector stopped it"
        sudo = f"{self.SUDO_PID} 4000 0/0/0 Ss sudo"
        cases = (
            (
                "tcpdump exited and awaits sudo",
                {
                    "processes": self._capture_processes(
                        self._process_row(
                            self.TCPDUMP_PID, self.SUDO_PID, op, "tcpdump", state="Z"
                        )
                    )
                },
                stopped,
                type(None),
                f"processes in the group of this capture's sudo: {sudo}; "
                f"{self.TCPDUMP_PID} {self.SUDO_PID} {op}/{op}/{op} Z tcpdump",
                False,
            ),
            (
                "sudo exited while observed",
                {
                    "processes": self._process_row(self.SUDO_PID, 4000, 0, "sudo", state="Z")
                    + "\n",
                    "stops_while_observed": True,
                },
                stopped,
                type(None),
                "processes in the group of this capture's sudo: "
                f"{self.SUDO_PID} 4000 0/0/0 Z sudo",
                False,
            ),
            (
                "tcpdump gone when interrupted",
                {"interrupt_error": ProcessLookupError(3, "No such process")},
                stopped,
                ProcessLookupError,
                None,
                True,
            ),
            (
                "interrupt refused",
                {"interrupt_error": PermissionError(1, "Operation not permitted")},
                "tcpdump refused the operator's interrupt",
                PermissionError,
                None,
                True,
            ),
        )
        for label, options, message, cause, note, interrupted in cases:
            with self.subTest(label):
                result = self._run_fake_tcpdump(capture, b"", **options)
                self.assertEqual(str(result.error), message)
                self.assertIsInstance(result.error.__cause__, cause)
                if note is not None:
                    self.assertEqual(result.error.__notes__[0], note)
                self.assertEqual(
                    [event for event in result.events if event[0] == "interrupt"],
                    [("interrupt", self.TCPDUMP_PID, signal.SIGINT)] if interrupted else [],
                )
                result.terminate.assert_called_once_with(result.process)
                self.assertEqual(result.stop_timeouts, [])

    def test_capture_failures_that_can_leave_root_processes_name_the_sudo_pid(
        self,
    ) -> None:
        # RELEASE.md: after either failure a root sudo or a tcpdump that never
        # dropped to the operator may still run; the operator lists sudo's
        # process group by the pid these failures show.
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        summary = (
            f"dns_traffic tcpdump ran under sudo pid {self.SUDO_PID}; exit status "
            f"unavailable; {len(capture)} packet bytes retained, not shown; outputs "
            "complete"
        )
        refused = self._run_fake_tcpdump(
            capture, b"", interrupt_error=PermissionError(1, "Operation not permitted")
        )
        self.assertEqual(str(refused.error), "tcpdump refused the operator's interrupt")
        self.assertEqual(refused.error.__notes__[-2], summary)
        cleanup = GARuntimeAcceptanceError(
            "tcpdump capture process group could not be cleaned up"
        )
        stranded = self._run_fake_tcpdump(
            capture,
            b"",
            interrupt_error=PermissionError(1, "Operation not permitted"),
            cleanup_failure=cleanup,
        )
        self.assertIs(stranded.error, cleanup)
        self.assertIn(
            f"\n  {summary}\n",
            common.failure_diagnostic("error: fixture headline", stranded.error) + "\n",
        )

    def test_capture_that_stops_before_the_collector_fails_as_extra_traffic(
        self,
    ) -> None:
        # tcpdump stops by itself only at its packet cap or on an error, so
        # the collector refuses a capture it did not stop, and sends nothing.
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        statistics = (
            b"32 packets captured\n32 packets received by filter\n"
            b"0 packets dropped by kernel\n"
        )
        result = self._run_fake_tcpdump(capture, statistics, stops_itself=True)
        self.assertEqual(str(result.error), "tcpdump stopped before the collector stopped it")
        self.assertNotIn("interrupt", [event[0] for event in result.events])
        result.killpg.assert_not_called()
        result.terminate.assert_called_once_with(result.process)
        retained = result.error.packet_capture_failure
        self.assertEqual(retained.stderr_bytes, self.TCPDUMP_READY + statistics)
        self.assertEqual(retained.packet_bytes, capture)
        self.assertTrue(retained.outputs_complete)

    def test_capture_exit_and_statistics_are_checked_when_tcpdump_stops(self) -> None:
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        dropped = b"0 packets dropped by kernel\n"
        invalid = "tcpdump capture exit or output is invalid"
        cases = (
            # tcpdump reached its cap between the collector's check and its
            # interrupt.
            (
                "cap reached",
                b"32 packets captured\n" + dropped,
                0,
                "dns_traffic tcpdump reached its 32-packet cap: extra traffic",
            ),
            (
                "statistic differs from the pcap",
                b"7 packets captured\n" + dropped,
                0,
                "dns_traffic tcpdump captured 7 packets but its pcap holds 6 records",
            ),
            (
                "matching packet dropped by the kernel",
                b"6 packets captured\n1 packet dropped by kernel\n",
                0,
                "dns_traffic tcpdump reports 1 matching packets dropped by the kernel",
            ),
            (
                "no statistic",
                b"tcpdump: pcap_loop: Device not configured\n",
                0,
                "dns_traffic tcpdump output lacks a capture receipt",
            ),
            ("exit status 1", b"6 packets captured\n" + dropped, 1, invalid),
            # A second SIGINT ends tcpdump without statistics; sudo then ends
            # itself with the signal that ended tcpdump.
            ("ended by a signal", b"", -signal.SIGINT, invalid),
        )
        for label, statistics, returncode, message in cases:
            with self.subTest(label):
                result = self._run_fake_tcpdump(capture, statistics, returncode=returncode)
                self.assertEqual(str(result.error), message)
                self.assertIn(("interrupt", self.TCPDUMP_PID, signal.SIGINT), result.events)
                result.terminate.assert_called_once_with(result.process)
                retained = result.error.packet_capture_failure
                self.assertEqual(retained.packet_bytes, capture)
                self.assertEqual(retained.stderr_bytes, self.TCPDUMP_READY + statistics)
                self.assertTrue(retained.outputs_complete)

    def test_capture_proves_its_traffic_before_the_collector_keeps_it(self) -> None:
        # Collection applies verification's proof while the traffic step still
        # holds the capture, so an unacceptable one fails there, with its
        # bytes retained, rather than after the whole run.
        udp = self.fixture.pcaps["udp-traffic.pcap"]
        udp_records = _pcap_records(udp)
        udp_seconds, _micros, udp_target = udp_records[1]
        tcp = self.fixture.pcaps["tcp-traffic.pcap"]
        tcp_records = _pcap_records(tcp)
        tcp_seconds, _micros, tcp_start = tcp_records[0]
        # The start token in another flow: no marker window reads it.
        other_flow = bytearray(tcp_start)
        other_flow[34:36] = struct.pack("!H", 41001)
        dns_packets = _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        cases = (
            (
                "udp_traffic",
                _pcap_with_records(udp, [*udp_records, (udp_seconds, 200_000, udp_target)]),
                "udp_traffic packet proof is partial or has extra traffic",
            ),
            (
                "tcp_traffic",
                _pcap_with_records(
                    tcp, [*tcp_records, (tcp_seconds, 300_000, bytes(other_flow))]
                ),
                "tcp_traffic packet bytes do not prove the required traffic",
            ),
            (
                "dns_traffic",
                _utun_udp_pcap(
                    dns_packets + [_tunnel_dns_retransmission(dns_packets, 5, 6.20)]
                ),
                "dns_traffic end packets lie outside its sender's start and the "
                "capture's end",
            ),
        )
        for check_id, capture, message in cases:
            with self.subTest(check_id=check_id):
                result = self._run_fake_tcpdump(
                    capture, self._statistics(capture), check_id=check_id
                )
                self.assertEqual(str(result.error), message)
                result.terminate.assert_called_once_with(result.process)
                retained = result.error.packet_capture_failure
                self.assertEqual(retained.packet_bytes[24:], capture[24:])
                self.assertTrue(retained.outputs_complete)

    def test_capture_names_its_check_in_every_packet_failure(self) -> None:
        # Collection derives the DNS endpoints and the marker window before
        # the shared proof and labels their failures as verification does.
        # tcpdump's own receipt is judged before any packet it wrote.
        dns_packets = _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        client, resolver = IPV6_DNS_LEG
        foreign = _utun_udp_pcap(
            dns_packets
            + [(0.50, client, 53100, resolver, 53, _tunnel_dns_query(0x7B01, "www.apple.com"))]
        )
        tcp = self.fixture.pcaps["tcp-traffic.pcap"]
        no_start = _pcap_with_records(tcp, _pcap_records(tcp)[1:])
        cases = (
            (
                "dns_traffic",
                foreign,
                self._statistics(foreign),
                "dns_traffic DNS capture endpoints are invalid",
                "names no evidence token",
            ),
            (
                "dns_traffic",
                foreign,
                b"32 packets captured\n0 packets dropped by kernel\n",
                "dns_traffic tcpdump reached its 32-packet cap: extra traffic",
                None,
            ),
            (
                "tcp_traffic",
                no_start,
                self._statistics(no_start),
                "tcp_traffic packet bytes do not prove the required traffic",
                "markers are absent, repeated, or reversed",
            ),
        )
        for check_id, capture, statistics, message, cause in cases:
            with self.subTest(message):
                result = self._run_fake_tcpdump(capture, statistics, check_id=check_id)
                self.assertEqual(str(result.error), message)
                if cause is None:
                    self.assertIsNone(result.error.__cause__)
                else:
                    self.assertIsInstance(result.error.__cause__, PacketCaptureError)
                    self.assertRegex(str(result.error.__cause__), cause)
                result.terminate.assert_called_once_with(result.process)
                retained = result.error.packet_capture_failure
                self.assertEqual(retained.packet_bytes[24:], capture[24:])
                self.assertTrue(retained.outputs_complete)

    def test_capture_cleanup_failure_keeps_its_own_cause(self) -> None:
        # The capture's own failure becomes the cleanup failure's cause, so a
        # refused group signal behind a cleanup timeout stays as a note.
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        cleanup = GARuntimeAcceptanceError(
            "tcpdump capture process group could not be cleaned up"
        )
        cleanup.__cause__ = PermissionError(1, "Operation not permitted")
        result = self._run_fake_tcpdump(
            capture, b"", stops_itself=True, cleanup_failure=cleanup
        )
        self.assertIs(result.error, cleanup)
        self.assertEqual(
            str(result.error.__cause__), "tcpdump stopped before the collector stopped it"
        )
        self.assertEqual(
            result.error.__notes__,
            [
                "tcpdump capture process group could not be cleaned up: "
                "PermissionError(1, 'Operation not permitted')"
            ],
        )
        # A cleanup failure without a cause of its own gets no note.
        causeless = GARuntimeAcceptanceError("tcpdump capture process exit could not be observed")
        result = self._run_fake_tcpdump(
            capture, b"", stops_itself=True, cleanup_failure=causeless
        )
        self.assertIs(result.error, causeless)
        self.assertEqual(getattr(result.error, "__notes__", []), [])
        interrupt = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as raised:
            self._run_fake_tcpdump(
                capture,
                b"",
                interrupt_error=interrupt,
                cleanup_failure=GARuntimeAcceptanceError(
                    "tcpdump capture process exit could not be observed"
                ),
            )
        self.assertIs(raised.exception, interrupt)
        self.assertEqual(
            raised.exception.__notes__, ["tcpdump capture process exit could not be observed"]
        )

    def test_capture_that_cannot_close_its_pipes_keeps_no_traffic(self) -> None:
        # Without a failure of its own, the capture fails as its cleanup.
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        result = self._run_fake_tcpdump(
            capture, self._statistics(capture), stderr_close_error=True
        )
        self.assertEqual(str(result.error), "tcpdump capture pipes could not be closed")
        self.assertEqual(str(result.error.__cause__), "fixture capture pipe close failure")
        self.assertEqual(getattr(result.error, "__notes__", []), [])
        self.assertIsNone(result.traffic)
        self.assertTrue(result.output_file.closed)
        result.terminate.assert_not_called()

    def test_capture_selector_close_failure_comes_first_and_keeps_the_rest(self) -> None:
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        result = self._run_fake_tcpdump(
            capture,
            self._statistics(capture),
            selector_close_error=True,
            stderr_close_error=True,
        )
        self.assertEqual(str(result.error), "tcpdump output selector could not be closed")
        self.assertEqual(str(result.error.__cause__), "fixture selector close failure")
        self.assertEqual(
            result.error.__notes__,
            [
                "tcpdump capture pipes could not be closed: "
                "OSError('fixture capture pipe close failure')"
            ],
        )
        self.assertIsNone(result.traffic)
        self.assertTrue(result.process.stderr.closed)
        self.assertTrue(result.output_file.closed)

    def test_capture_cleanup_waits_for_a_sudo_it_may_not_signal(self) -> None:
        # Once tcpdump, which -Z made the operator's, has exited, the group
        # holds only sudo, which may keep root; the operator's SIGKILL to the
        # group is then refused, and sudo's own exit within the bound decides.
        refused = PermissionError(1, "Operation not permitted")

        def killpg(_group: int, number: int) -> None:
            # The group refuses the operator's SIGKILL; once sudo has exited,
            # nothing is left in it.
            if number == signal.SIGKILL:
                raise refused
            raise ProcessLookupError(3, "No such process")

        for label, wait_error, message in (
            ("sudo exits by itself", None, None),
            (
                "sudo outlives the bound",
                subprocess.TimeoutExpired(["sudo"], 5),
                "tcpdump capture process group could not be cleaned up",
            ),
        ):
            with self.subTest(label):
                process = MagicMock()
                process.pid = self.SUDO_PID
                process.poll.return_value = None
                process.wait.side_effect = wait_error
                with patch.object(ga_runtime.os, "killpg", side_effect=killpg) as signals:
                    if message is None:
                        ga_runtime.ProductionCollectorRuntime._terminate_capture(process)
                    else:
                        with self.assertRaises(GARuntimeAcceptanceError) as raised:
                            ga_runtime.ProductionCollectorRuntime._terminate_capture(process)
                        self.assertEqual(str(raised.exception), message)
                        self.assertIs(raised.exception.__cause__, refused)
                # Only once sudo has exited is its group probed for what is left.
                self.assertEqual(
                    signals.call_args_list,
                    [call(self.SUDO_PID, 9)]
                    + ([call(self.SUDO_PID, 0)] if message is None else []),
                )
                process.wait.assert_called_once_with(timeout=5)

    def test_capture_cleanup_ends_only_once_the_group_of_its_sudo_is_gone(self) -> None:
        # sudo's exit is not tcpdump's: a tcpdump still root when sudo ended,
        # which the operator's SIGKILL could not reach, or one sudo left
        # behind stays in sudo's process group. Cleanup ends only once that
        # group is gone, within the same five seconds as sudo's exit.
        gone = ProcessLookupError(3, "No such process")
        root_member = PermissionError(1, "Operation not permitted")
        unprobed = OSError(22, "Invalid argument")
        not_cleaned = "tcpdump capture process group could not be cleaned up"
        cases = (
            ("group gone once sudo exits", None, 0.0, [], gone, None),
            # macOS can refuse a probe of a group it is still removing.
            ("group retiring for a moment", None, 0.0, [root_member, None], gone, None),
            ("root tcpdump left in the group", None, 0.0, [], root_member, not_cleaned),
            # sudo's four seconds leave the group one second of the bound.
            ("root tcpdump left by a slow sudo", None, 4.0, [], root_member, not_cleaned),
            ("tcpdump left by a sudo that already exited", 1, 0.0, [], None, not_cleaned),
            # A probe that fails shows nothing of the group: it is the cleanup's
            # own failure, with its cause, never waited for.
            (
                "group probe that fails",
                None,
                0.0,
                [],
                unprobed,
                "tcpdump capture process group could not be observed",
            ),
        )
        for label, sudo_exit, sudo_seconds, first_probes, then, message in cases:
            with self.subTest(label):
                process = MagicMock()
                process.pid = self.SUDO_PID
                process.poll.return_value = sudo_exit
                probes = itertools.chain(first_probes, itertools.repeat(then))

                def killpg(_group: int, number: int) -> None:
                    if number == signal.SIGKILL:
                        return None
                    outcome = next(probes)
                    if outcome is not None:
                        raise outcome
                    return None

                clock, sleeps, clock_patches = self._fake_clock()

                def sudo_exits(*, timeout: float) -> int:
                    clock[0] += sudo_seconds
                    return 0

                process.wait.side_effect = sudo_exits
                with clock_patches[0], clock_patches[1], patch.object(
                    ga_runtime.os, "killpg", side_effect=killpg
                ) as signals:
                    if message is None:
                        ga_runtime.ProductionCollectorRuntime._terminate_capture(process)
                    else:
                        with self.assertRaises(GARuntimeAcceptanceError) as raised:
                            ga_runtime.ProductionCollectorRuntime._terminate_capture(process)
                        self.assertEqual(str(raised.exception), message)
                        self.assertIs(
                            raised.exception.__cause__, unprobed if then is unprobed else None
                        )
                process.wait.assert_called_once_with(timeout=5)
                kills = [entry for entry in signals.call_args_list if entry.args[1] != 0]
                # A sudo that already exited gets no signal; its group is only probed.
                self.assertEqual(kills, [] if sudo_exit is not None else [call(self.SUDO_PID, 9)])
                if message == not_cleaned:
                    # The group is probed until the one bound that began with
                    # the wait for sudo, never after it.
                    self.assertAlmostEqual(clock[0], 5.0)
                    self.assertLessEqual(max(sleeps), 0.01)
                else:
                    self.assertEqual(len(sleeps), len(first_probes))

    def test_capture_file_read_stops_one_byte_past_its_bound(self) -> None:
        with tempfile.TemporaryFile(buffering=0) as capture:
            capture.write(b"\x00" * 70_000)
            for maximum, expected in ((65_536, 65_537), (69_999, 70_000), (70_000, 70_000)):
                with self.subTest(maximum=maximum):
                    self.assertEqual(
                        len(ga_runtime._capture_file_bytes(capture, maximum)), expected
                    )

    def test_failed_capture_marks_outputs_it_could_not_retain_incomplete(self) -> None:
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        with self.subTest("stderr still open"):
            result = self._run_fake_tcpdump(
                capture, b"", stops_itself=True, stderr_stays_open=True
            )
            retained = result.error.packet_capture_failure
            self.assertEqual(retained.stderr_bytes, self.TCPDUMP_READY)
            self.assertEqual(retained.packet_bytes, capture)
            self.assertEqual(retained.retention_errors, ())
            self.assertFalse(retained.outputs_complete)
            self.assertIn("outputs incomplete", result.error.__notes__[-2])
        with self.subTest("pcap file unreadable"):
            with patch.object(
                ga_runtime.os, "pread", side_effect=OSError("fixture pread failure")
            ):
                result = self._run_fake_tcpdump(capture, b"", stops_itself=True)
            retained = result.error.packet_capture_failure
            self.assertEqual(retained.packet_bytes, b"")
            self.assertEqual(retained.retention_errors, ("pcap: OSError",))
            self.assertFalse(retained.outputs_complete)
            self.assertIn(
                "outputs incomplete; retention errors: pcap: OSError",
                result.error.__notes__[-2],
            )
        with self.subTest("stderr pipe unavailable"):
            runtime = self._capture_runtime()
            process = self._CaptureProcess(None, None)
            with patch.object(runtime, "_tunnel_interface", return_value="utun6"), patch.object(
                ga_runtime.subprocess, "Popen", return_value=process
            ), patch.object(runtime, "_terminate_capture") as terminate, self.assertRaises(
                GARuntimeAcceptanceError
            ) as raised:
                runtime._capture_traffic_bytes(
                    "dns_traffic",
                    RuntimeFixture._traffic_tokens("dns_traffic"),
                    interpreter=sys.executable,
                )
            self.assertEqual(str(raised.exception), "fixed tcpdump capture pipes are unavailable")
            terminate.assert_called_once_with(process)
            retained = raised.exception.packet_capture_failure
            self.assertEqual(retained.retention_errors, ("stderr: pipe unavailable",))
            self.assertFalse(retained.outputs_complete)

    def test_failed_capture_stderr_that_cannot_be_read_keeps_what_was_read(self) -> None:
        # Reading the rest of a failed capture's stderr can fail too. The
        # capture's own failure stands, with the stderr read before it and the
        # retention failure named by its type, never raised in its place.
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        for failure in (
            OSError(5, "Input/output error"),
            ValueError("I/O operation on closed file"),
        ):
            with self.subTest(type(failure).__name__):
                result = self._run_fake_tcpdump(
                    capture, b"", stops_itself=True, stderr_read_error=failure
                )
                self.assertEqual(
                    str(result.error), "tcpdump stopped before the collector stopped it"
                )
                result.terminate.assert_called_once_with(result.process)
                retained = result.error.packet_capture_failure
                self.assertEqual(retained.stderr_bytes, self.TCPDUMP_READY)
                self.assertEqual(retained.packet_bytes, capture)
                self.assertEqual(
                    retained.retention_errors, (f"stderr: {type(failure).__name__}",)
                )
                self.assertFalse(retained.outputs_complete)
                self.assertIn(
                    "outputs incomplete; retention errors: "
                    f"stderr: {type(failure).__name__}",
                    result.error.__notes__[-2],
                )

    def test_capture_file_is_read_without_moving_the_offset_tcpdump_shares(
        self,
    ) -> None:
        # tcpdump writes through a duplicate of this file's descriptor, so
        # both share one offset; moving it would let a tcpdump that is still
        # running write over its own pcap.
        with tempfile.TemporaryFile(buffering=0) as capture:
            capture.write(b"0123456789")
            capture.seek(4)
            self.assertEqual(ga_runtime._capture_file_bytes(capture, 8), b"012345678")
            self.assertEqual(capture.tell(), 4)
            self.assertEqual(ga_runtime._capture_file_bytes(capture, 32), b"0123456789")
            self.assertEqual(capture.tell(), 4)

    def _run_capture_process(
        self, pcap: bytes, count: int, *, written_before_stop: int
    ) -> SimpleNamespace:
        """Run the dns_traffic exercise against FAKE_TCPDUMP in a real child.

        The child writes the first written_before_stop bytes of pcap before it
        reports readiness and the rest once interrupted. Only the collector's
        own time binding is faked: subprocess still waits on the real clock.
        """

        runtime = self._capture_runtime()
        receipts = dict(
            zip(
                DNS_STAGES,
                self.fixture.documents["dns-traffic.json"]["send_commands"],
                strict=True,
            )
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / "capture.pcap"
        source.write_bytes(pcap)
        real_popen = subprocess.Popen
        result = SimpleNamespace(
            processes=[], sleeps=[], traffic=None, capture=None, error=None
        )

        def spawn(argv, **options):
            process = real_popen(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    FAKE_TCPDUMP,
                    str(source),
                    str(count),
                    str(written_before_stop),
                ],
                **options,
            )
            result.processes.append(process)

            def reap() -> None:
                # A collector that failed to stop the child leaves it in
                # sigwait in a session of its own.
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

            self.addCleanup(reap)
            return process

        def send(argv, *, timeout):
            (process,) = result.processes
            if argv == capture_process_argv(process.pid):
                # As if sudo executed tcpdump in place: the child is tcpdump.
                return command(
                    argv,
                    stdout=self._process_row(process.pid, os.getpid(), os.getuid(), "tcpdump")
                    + "\n",
                )
            return copy.deepcopy(receipts[argv[argv.index("--stage") + 1]])

        with patch.object(runtime, "_tunnel_interface", return_value="utun6"), \
             patch.object(runtime, "run", side_effect=send), \
             patch.object(ga_runtime.subprocess, "Popen", side_effect=spawn), \
             patch.object(ga_runtime.os, "kill", wraps=os.kill) as kill, \
             patch.object(ga_runtime.os, "killpg", wraps=os.killpg) as killpg, \
             patch.object(
                 ga_runtime,
                 "time",
                 SimpleNamespace(monotonic=time.monotonic, sleep=result.sleeps.append),
             ), \
             patch.object(ga_runtime, "_utc_now", side_effect=self._receipt_clock()):
            try:
                result.traffic, result.capture = runtime._capture_traffic_bytes(
                    "dns_traffic",
                    RuntimeFixture._traffic_tokens("dns_traffic"),
                    interpreter=sys.executable,
                )
            except GARuntimeAcceptanceError as error:
                result.error = error
        result.kill = kill
        result.killpg = killpg
        return result

    def test_capture_interrupts_a_real_capture_process_and_reads_its_file(self) -> None:
        capture = _utun_udp_pcap(
            _tunnel_dns_packets(RuntimeFixture._traffic_tokens("dns_traffic"))
        )
        # The child writes the end answer only once interrupted, so the
        # collector must read its file after tcpdump exits.
        _seconds, _micros, end_answer = _pcap_records(capture)[-1]
        result = self._run_capture_process(
            capture, 6, written_before_stop=len(capture) - 16 - len(end_answer)
        )
        self.assertIsNone(result.error)
        (process,) = result.processes
        result.kill.assert_called_once_with(process.pid, signal.SIGINT)
        result.killpg.assert_not_called()
        self.assertEqual(process.returncode, 0)
        self.assertEqual(result.sleeps, [1.1, 1.1, 1.5])
        self.assertEqual(result.capture, capture)
        self.assertEqual(
            result.traffic["capture_command"]["stderr"],
            "tcpdump: listening on utun6, link-type RAW (Raw IP), snapshot length 262144 "
            "bytes\n6 packets captured\n6 packets received by filter\n"
            "0 packets dropped by kernel\n",
        )

    def test_capture_output_never_blocks_tcpdump_before_the_stop(self) -> None:
        # While a sender runs the collector reads nothing from tcpdump. Its
        # pcap goes to an unlinked private file, so tcpdump never waits on a
        # full pipe: here it writes 1 MiB, far more than a macOS pipe holds,
        # before it reports readiness, and the collector keeps every byte.
        written = b"\x00" * (1024 * 1024)
        result = self._run_capture_process(written, 1, written_before_stop=len(written))
        self.assertEqual(
            str(result.error), "dns_traffic packet bytes do not prove the required traffic"
        )
        self.assertEqual(str(result.error.__cause__), "pcap magic is unsupported")
        (process,) = result.processes
        result.kill.assert_called_once_with(process.pid, signal.SIGINT)
        retained = result.error.packet_capture_failure
        self.assertEqual(retained.packet_bytes, written)
        self.assertTrue(retained.outputs_complete)

    def test_interface_discovery_is_inside_complete_exercise_deadline(self) -> None:
        runtime = self._capture_runtime()
        elapsed = [0.0]
        def interface():
            elapsed[0] = 46.0
            return "utun6"
        with patch.object(runtime, "_tunnel_interface", side_effect=interface), \
             patch.object(ga_runtime.time, "monotonic", side_effect=lambda: elapsed[0]), \
             patch.object(ga_runtime.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(GARuntimeAcceptanceError, "complete bounded deadline"):
                runtime._capture_traffic_bytes("dns_traffic", RuntimeFixture._traffic_tokens("dns_traffic"), interpreter=sys.executable)
        spawn.assert_not_called()

    def test_failed_capture_pipe_retention_is_bounded_and_distinguishes_eof(self) -> None:
        for maximum, close_writer, expected, complete in (
            (8, True, b"prefix12", False),
            (32, True, b"prefix12345", True),
            (32, False, b"prefix12345", False),
        ):
            with self.subTest(maximum=maximum, close_writer=close_writer):
                read_fd, write_fd = os.pipe()
                try:
                    os.write(write_fd, b"12345")
                    if close_writer:
                        os.close(write_fd)
                        write_fd = None
                    with os.fdopen(read_fd, "rb", buffering=0) as stream:
                        read_fd = None
                        result = ga_runtime._failed_capture_pipe_snapshot(
                            stream, b"prefix", maximum, ga_runtime.time.monotonic() + 1)
                        self.assertEqual(result, (expected, complete))
                finally:
                    if read_fd is not None:
                        os.close(read_fd)
                    if write_fd is not None:
                        os.close(write_fd)

    class _CaptureFile:
        """tcpdump's unlinked pcap file, whose close can fail."""

        def __init__(self, *, close_error: bool = False) -> None:
            self.file = tempfile.TemporaryFile(buffering=0)
            self.close_error = close_error

        def fileno(self) -> int:
            return self.file.fileno()

        @property
        def closed(self) -> bool:
            return self.file.closed

        def close(self) -> None:
            self.file.close()
            if self.close_error:
                raise OSError("fixture capture file close failure")

    def test_capture_start_failure_closes_its_capture_file(self) -> None:
        cases = (
            (
                "capture file unavailable",
                OSError("fixture temporary directory full"),
                None,
                False,
                "tcpdump capture file could not be created",
                "fixture temporary directory full",
            ),
            (
                "tcpdump cannot start",
                None,
                OSError("fixture sudo missing"),
                False,
                "fixed tcpdump capture could not start",
                "fixture sudo missing",
            ),
            # The close failure keeps the start failure as its cause.
            (
                "tcpdump cannot start and its file cannot be closed",
                None,
                OSError("fixture sudo missing"),
                True,
                "tcpdump capture file could not be closed",
                "fixed tcpdump capture could not start",
            ),
            (
                "Popen refuses its arguments and the file cannot be closed",
                None,
                ValueError("fixture invalid Popen argument"),
                True,
                "tcpdump capture file could not be closed",
                "fixture invalid Popen argument",
            ),
        )
        for label, file_error, start_error, close_error, message, cause in cases:
            with self.subTest(label):
                runtime = self._capture_runtime()
                capture_file = self._CaptureFile(close_error=close_error)
                self.addCleanup(capture_file.file.close)
                with patch.object(
                    runtime, "_tunnel_interface", return_value="utun6"
                ), patch.object(
                    ga_runtime.tempfile,
                    "TemporaryFile",
                    side_effect=file_error,
                    return_value=capture_file,
                ), patch.object(
                    ga_runtime.subprocess, "Popen", side_effect=start_error
                ) as popen, self.assertRaises(GARuntimeAcceptanceError) as raised:
                    runtime._capture_traffic_bytes(
                        "tcp_traffic",
                        RuntimeFixture._traffic_tokens("tcp_traffic"),
                        interpreter=sys.executable,
                    )
                self.assertEqual(str(raised.exception), message)
                self.assertEqual(str(raised.exception.__cause__), cause)
                if close_error:
                    # The cause is the start failure; the close error is kept
                    # as a note.
                    self.assertEqual(
                        raised.exception.__notes__,
                        [
                            "tcpdump capture file could not be closed: "
                            "OSError('fixture capture file close failure')"
                        ],
                    )
                if file_error is not None:
                    popen.assert_not_called()
                else:
                    self.assertIs(popen.call_args.kwargs["stdout"], capture_file)
                    self.assertTrue(capture_file.closed)

    def test_capture_start_stopped_otherwise_still_closes_its_capture_file(
        self,
    ) -> None:
        # Only an OSError is the start's own failure; anything else that stops
        # Popen propagates unchanged, and the file is closed either way. An
        # interrupt stays an interrupt even when the file cannot be closed.
        for failure, close_error in (
            (KeyboardInterrupt(), False),
            (ValueError("fixture invalid Popen argument"), False),
            (KeyboardInterrupt(), True),
        ):
            with self.subTest(failure=type(failure).__name__, close_error=close_error):
                runtime = self._capture_runtime()
                capture_file = self._CaptureFile(close_error=close_error)
                self.addCleanup(capture_file.file.close)
                with patch.object(
                    runtime, "_tunnel_interface", return_value="utun6"
                ), patch.object(
                    ga_runtime.tempfile, "TemporaryFile", return_value=capture_file
                ), patch.object(
                    ga_runtime.subprocess, "Popen", side_effect=failure
                ) as popen, self.assertRaises(type(failure)) as raised:
                    runtime._capture_traffic_bytes(
                        "tcp_traffic",
                        RuntimeFixture._traffic_tokens("tcp_traffic"),
                        interpreter=sys.executable,
                    )
                self.assertIs(raised.exception, failure)
                self.assertIs(popen.call_args.kwargs["stdout"], capture_file)
                self.assertTrue(capture_file.closed)
                self.assertEqual(
                    getattr(raised.exception, "__notes__", []),
                    [
                        "tcpdump capture file could not be closed: "
                        "OSError('fixture capture file close failure')"
                    ]
                    if close_error
                    else [],
                )
                if close_error:
                    # The close error is a note, not the interrupt's context.
                    self.assertIsNone(raised.exception.__cause__)
                    self.assertIs(raised.exception.__suppress_context__, True)

    def test_capture_selector_initialization_failure_cleans_all_resources(
        self,
    ) -> None:
        file_error = "tcpdump capture file could not be closed: " + (
            "OSError('fixture capture file close failure')"
        )
        pipe_error = "tcpdump capture pipes could not be closed: " + (
            "OSError('fixture capture pipe close failure')"
        )
        # The selector failure becomes the cause of a cleanup failure, so each
        # cleanup failure stays visible as a note with its own cause.
        for close_error, message, notes in (
            (None, "selector is unavailable", None),
            ("stderr", "pipes could not be closed", [pipe_error]),
            ("capture file", "capture file could not be closed", [file_error]),
            ("stderr and capture file", "pipes could not be closed", [file_error, pipe_error]),
        ):
            with self.subTest(close_error=close_error):
                runtime = self._capture_runtime()
                stderr = self._CapturePipe(
                    22, close_error=close_error in ("stderr", "stderr and capture file")
                )
                capture_file = self._CaptureFile(
                    close_error=close_error in ("capture file", "stderr and capture file")
                )
                process = self._CaptureProcess(None, stderr)
                with patch.object(
                    runtime,
                    "_tunnel_interface",
                    return_value="utun6",
                ), patch(
                    "scripts.ga_runtime_acceptance.packet_capture_filter_argv",
                    return_value=(),
                ), patch(
                    "scripts.ga_runtime_acceptance.tempfile.TemporaryFile",
                    return_value=capture_file,
                ), patch(
                    "scripts.ga_runtime_acceptance.subprocess.Popen",
                    return_value=process,
                ) as popen, patch(
                    "scripts.ga_runtime_acceptance.selectors.DefaultSelector",
                    side_effect=OSError("fixture selector exhaustion"),
                ), patch.object(
                    runtime,
                    "_terminate_capture",
                ) as terminate, patch.object(
                    ga_runtime, "_failed_capture_pipe_snapshot", return_value=(b"", False),
                ), self.assertRaises(
                    GARuntimeAcceptanceError
                ) as captured:
                    runtime._capture_traffic_bytes(
                        "tcp_traffic",
                        RuntimeFixture._traffic_tokens("tcp_traffic"),
                        interpreter=sys.executable,
                    )
                self.assertIn(message, str(captured.exception))
                if notes is not None:
                    self.assertEqual(
                        str(captured.exception.__cause__), "tcpdump output selector is unavailable"
                    )
                    self.assertEqual(getattr(captured.exception, "__notes__", []), notes)
                terminate.assert_called_once_with(process)
                self.assertIs(popen.call_args.kwargs["stdout"], capture_file)
                self.assertTrue(capture_file.closed)
                self.assertTrue(stderr.closed)

    def test_capture_post_selector_io_failure_is_typed_and_interrupt_cleans(
        self,
    ) -> None:
        pipe_note = (
            "tcpdump capture pipes could not be closed: "
            "OSError('fixture capture pipe close failure')"
        )
        file_note = (
            "tcpdump capture file could not be closed: "
            "OSError('fixture capture file close failure')"
        )
        # An interrupt whose cleanup fails stays an interrupt; the cleanup
        # failure, with its cause, and any later cleanup failure become notes.
        for failure, close_errors, notes in (
            (OSError("fixture descriptor exhaustion"), (), None),
            (KeyboardInterrupt(), (), []),
            (KeyboardInterrupt(), ("stderr",), [pipe_note]),
            (KeyboardInterrupt(), ("stderr", "capture file"), [pipe_note, file_note]),
        ):
            with self.subTest(failure=type(failure).__name__, close_errors=close_errors):
                runtime = self._capture_runtime()
                stderr = self._CapturePipe(22, close_error="stderr" in close_errors)
                capture_file = self._CaptureFile(close_error="capture file" in close_errors)
                self.addCleanup(capture_file.file.close)
                process = self._CaptureProcess(None, stderr)
                expected = (
                    GARuntimeAcceptanceError
                    if isinstance(failure, OSError)
                    else KeyboardInterrupt
                )
                with patch.object(
                    runtime,
                    "_tunnel_interface",
                    return_value="utun6",
                ), patch(
                    "scripts.ga_runtime_acceptance.packet_capture_filter_argv",
                    return_value=(),
                ), patch(
                    "scripts.ga_runtime_acceptance.tempfile.TemporaryFile",
                    return_value=capture_file,
                ), patch(
                    "scripts.ga_runtime_acceptance.subprocess.Popen",
                    return_value=process,
                ) as popen, patch(
                    "scripts.ga_runtime_acceptance.os.set_blocking",
                    side_effect=failure,
                ), patch.object(
                    runtime,
                    "_terminate_capture",
                ) as terminate, self.assertRaises(expected) as captured:
                    runtime._capture_traffic_bytes(
                        "tcp_traffic",
                        RuntimeFixture._traffic_tokens("tcp_traffic"),
                        interpreter=sys.executable,
                    )
                if notes is None:
                    self.assertIn("process I/O failed", str(captured.exception))
                else:
                    self.assertIs(captured.exception, failure)
                    self.assertIsNone(captured.exception.__cause__)
                    self.assertEqual(getattr(captured.exception, "__notes__", []), notes)
                terminate.assert_called_once_with(process)
                self.assertIs(popen.call_args.kwargs["stdout"], capture_file)
                self.assertTrue(capture_file.closed)
                self.assertTrue(stderr.closed)

    def _create_recoverable_collection(
        self, baseline: dict[str, object] | None = None
    ) -> None:
        failing = FakeCollectorRuntime(self.fixture, fail_launch=True)
        if baseline is not None:
            failing.guards = [copy.deepcopy(baseline), copy.deepcopy(baseline)]
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GACollectionRecoveryRequired
        ):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=failing,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )

    def _absent_host_recovery_runtime(
        self,
        environments: list[dict[str, object]],
    ) -> FakeCollectorRuntime:
        runtime = FakeCollectorRuntime(self.fixture, environments=environments)
        shutdown = self.fixture.documents["shutdown-restore.json"]
        runtime.receipts = {
            tuple(PROCESS_OBSERVATION_COMMAND): [
                copy.deepcopy(shutdown["process_observation"]),
                copy.deepcopy(shutdown["host_process_observation"]),
                copy.deepcopy(shutdown["process_observation"]),
            ],
            tuple(OFF_PROOF_COMMAND): [copy.deepcopy(shutdown["off_proof_command"])],
        }
        runtime.guards = [guard()]
        return runtime

    @staticmethod
    def _collect(
        fixture: RuntimeFixture, runtime: FakeCollectorRuntime
    ) -> dict[str, dict[str, str]]:
        return collect_ga_runtime_acceptance(
            repository=fixture.repository,
            expected=fixture.expected,
            prepackage_stage_verifier=prepackage_stage_verifier,
            runtime=runtime,
            challenge_bytes=b"C" * 32,
            session_id=SESSION_ID,
        )

    def _assert_recovery_refused(self, *, runtime: FakeCollectorRuntime) -> None:
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), self.assertRaisesRegex(GARuntimeAcceptanceError, "would orphan"):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=runtime,
            )
        self.assertEqual(runtime.calls, [])
        self.assertTrue(self.fixture.collection_root.is_dir())
        self.assertFalse(
            any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
        )

    def test_seal_failure_after_raw_publication_requires_only_seal_retry(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        transient = GARuntimeAcceptanceError(
            f"installed {TO_BUILD} application tree cannot be identified"
        )
        transient.__cause__ = ValueError("artifact entry changed while revalidating: .")
        publish = ga_runtime._publish_collected_raw
        published: list[Path] = []

        def publish_raw(repository: Path, files: dict[str, bytes]) -> Path:
            published.append(publish(repository, files))
            return published[-1]

        def installed_tree(_repository: Path, _expected: dict[str, Any]) -> str:
            # The seal re-identifies the installed app after the raw tree is
            # durable; macOS metadata churn can make that fail transiently.
            if published:
                raise transient
            return APP_TREE

        with patch.object(
            ga_runtime, "_publish_collected_raw", side_effect=publish_raw
        ), patch.object(
            ga_runtime, "_installed_candidate_tree", side_effect=installed_tree
        ), patch.object(
            ga_runtime, "_dmg_contained_candidate_tree", return_value=APP_TREE
        ), patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), self.assertRaises(GARuntimeAcceptanceError) as captured:
            self._collect(self.fixture, runtime)

        failure = captured.exception
        self.assertNotIsInstance(failure, GACollectionRecoveryRequired)
        self.assertIsInstance(failure, ga_runtime.GASealRetryRequired)
        self.assertIs(failure.__cause__, transient)
        self.assertIn(SEAL_RETRY_COMMAND, str(failure))
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )
        self.assertEqual(set(os.listdir(self.fixture.raw_root)), set(RAW_FILE_NAMES))
        self.assertFalse(self.fixture.acceptance.exists())

        recovery = FakeCollectorRuntime(self.fixture)
        self._assert_recovery_refused(runtime=recovery)
        self.assertEqual(len(recovery.environments), 3)

        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )

    def test_raw_tree_published_then_readback_failure_needs_seal_retry(self) -> None:
        publish = ga_runtime.publish_private_directory_locked
        for renamed in (True, False):
            with self.subTest(renamed=renamed):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                fixture.remove_unsealed_raw_tree()

                def publish_then_fail(descriptor, parent, name, files):
                    if name != RAW_ROOT_RELATIVE.name:
                        return publish(descriptor, parent, name, files)
                    if renamed:
                        publish(descriptor, parent, name, files)
                    raise PublicationError("simulated raw publication failure")

                source_patches = self._patch_evidence_sources()
                with patch.object(
                    ga_runtime,
                    "publish_private_directory_locked",
                    side_effect=publish_then_fail,
                ), source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
                    GARuntimeAcceptanceError
                ) as captured:
                    self._collect(fixture, FakeCollectorRuntime(fixture))

                events = collection_events(fixture.repository)
                if renamed:
                    self.assertNotIsInstance(captured.exception, GACollectionRecoveryRequired)
                    self.assertIsInstance(captured.exception, ga_runtime.GASealRetryRequired)
                    self.assertEqual(events, STEP_EVENTS)
                    self.assertTrue(fixture.raw_root.is_dir())
                    self.assertEqual(fixture.resume_seal(), fixture.validate())
                    self.assertEqual(
                        collection_events(fixture.repository),
                        [*STEP_EVENTS, RAW_PUBLISHED_EVENT],
                    )
                else:
                    # Nothing was published, so the closed runtime boundary
                    # still goes through fixed recovery.
                    self.assertIsInstance(captured.exception, GACollectionRecoveryRequired)
                    self.assertEqual(
                        events, [*STEP_EVENTS, ("recovery_required", "collection")]
                    )
                    self.assertFalse(fixture.raw_root.exists())

    def test_unobservable_raw_publication_state_appends_no_event(self) -> None:
        publish = ga_runtime.publish_private_directory_locked
        lstat = Path.lstat
        attempted: list[str] = []

        def fail_raw_publication(descriptor, parent, name, files):
            if name != RAW_ROOT_RELATIVE.name:
                return publish(descriptor, parent, name, files)
            attempted.append(name)
            raise PublicationError("simulated raw publication failure")

        def unreadable_raw_root(path: Path, *arguments: Any, **values: Any):
            if attempted and path == self.fixture.raw_root:
                raise PermissionError("fixture raw-evidence probe denied")
            return lstat(path, *arguments, **values)

        source_patches = self._patch_evidence_sources()
        with patch.object(
            ga_runtime,
            "publish_private_directory_locked",
            side_effect=fail_raw_publication,
        ), patch.object(
            Path, "lstat", autospec=True, side_effect=unreadable_raw_root
        ), source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            DurabilityOutcomeUnknown
        ) as captured:
            self._collect(self.fixture, FakeCollectorRuntime(self.fixture))

        self.assertIn("unobservable", str(captured.exception))
        self.assertIn(
            "raw-evidence observation failed: PermissionError: fixture raw-evidence probe denied",
            getattr(captured.exception, "__notes__", []),
        )
        self.assertIsInstance(captured.exception.__cause__, PublicationError)
        # Neither a recovery nor a publication marker may claim a state that
        # could not be observed.
        self.assertEqual(collection_events(self.fixture.repository), STEP_EVENTS)

    def test_raw_tree_publication_outcome_unknown_points_to_resume_seal(self) -> None:
        publish = ga_runtime.publish_private_directory_locked

        def publish_then_lose_barrier(descriptor, parent, name, files):
            publish(descriptor, parent, name, files)
            if name == RAW_ROOT_RELATIVE.name:
                raise DurabilityOutcomeUnknown("simulated raw publication barrier loss")

        source_patches = self._patch_evidence_sources()
        with patch.object(
            ga_runtime,
            "publish_private_directory_locked",
            side_effect=publish_then_lose_barrier,
        ), source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            DurabilityOutcomeUnknown
        ) as captured:
            self._collect(self.fixture, FakeCollectorRuntime(self.fixture))

        notes = getattr(captured.exception, "__notes__", [])
        self.assertTrue(
            any(SEAL_RETRY_COMMAND in note and RECOVERY_COMMAND in note for note in notes),
            notes,
        )
        self.assertEqual(collection_events(self.fixture.repository), STEP_EVENTS)
        self.assertTrue(self.fixture.raw_root.is_dir())
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )

    def test_raw_published_marker_failure_needs_seal_retry(self) -> None:
        append = ga_runtime._append_collection_event

        def append_except_marker(*arguments: Any, **values: Any) -> None:
            if values["phase"] == "raw_published":
                raise PublicationError("simulated marker write failure")
            append(*arguments, **values)

        source_patches = self._patch_evidence_sources()
        with patch.object(
            ga_runtime, "_append_collection_event", side_effect=append_except_marker
        ), source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GARuntimeAcceptanceError
        ) as captured:
            self._collect(self.fixture, FakeCollectorRuntime(self.fixture))

        self.assertNotIsInstance(captured.exception, GACollectionRecoveryRequired)
        self.assertIsInstance(captured.exception, ga_runtime.GASealRetryRequired)
        self.assertEqual(collection_events(self.fixture.repository), STEP_EVENTS)
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )

    def test_collect_marker_cannot_duplicate_a_concurrent_resume_marker(self) -> None:
        publish = ga_runtime._publish_collected_raw
        marker = self.fixture.collection_root / "event-038.json"

        def publish_then_resume_wins(repository: Path, files: dict[str, bytes]) -> Path:
            published = publish(repository, files)
            marker.write_bytes(collection_event(38, *RAW_PUBLISHED_EVENT))
            marker.chmod(0o600)
            return published

        source_patches = self._patch_evidence_sources()
        with patch.object(
            ga_runtime, "_publish_collected_raw", side_effect=publish_then_resume_wins
        ), source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GARuntimeAcceptanceError
        ) as captured:
            self._collect(self.fixture, FakeCollectorRuntime(self.fixture))

        self.assertIsInstance(captured.exception, ga_runtime.GASealRetryRequired)
        self.assertIn("requires sequence 38", str(captured.exception.__cause__))
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())

    def test_adapter_promotion_reply_loss_during_collect_resumes_without_rewrite(self) -> None:
        publish = ga_runtime.publish_private_file_locked

        def publish_then_lose_adapter_reply(**arguments: Any) -> None:
            publish(**arguments)
            if arguments["name"] == self.fixture.acceptance.name:
                raise DurabilityOutcomeUnknown("simulated adapter rename reply loss")

        source_patches = self._patch_evidence_sources()
        with patch.object(
            ga_runtime,
            "publish_private_file_locked",
            side_effect=publish_then_lose_adapter_reply,
        ), source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            DurabilityOutcomeUnknown
        ) as captured:
            self._collect(self.fixture, FakeCollectorRuntime(self.fixture))

        notes = getattr(captured.exception, "__notes__", [])
        self.assertTrue(any(SEAL_RETRY_COMMAND in note for note in notes), notes)
        self.assertTrue(self.fixture.acceptance.is_file())
        self.assertEqual(
            collection_events(self.fixture.repository), [*STEP_EVENTS, RAW_PUBLISHED_EVENT]
        )
        before = self.fixture.acceptance.stat()
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        after = self.fixture.acceptance.stat()
        self.assertEqual(
            (after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns)
        )

    def test_collect_refuses_published_outputs_before_runtime_commands(self) -> None:
        # Admission shares recovery's predicate: a stale adapter left without
        # a raw tree must not admit a collection that recover refuses.
        parent = self.fixture.acceptance.parent
        for name, create in (
            ("runtime-evidence", lambda path: path.mkdir(mode=0o700)),
            ("runtime-acceptance.json", lambda path: path.write_bytes(b"{}\n")),
        ):
            with self.subTest(published=name):
                path = parent / name
                create(path)
                try:
                    # Launch fails, so a wrongly admitted collection stops at
                    # the first mutation instead of publishing raw evidence.
                    runtime = FakeCollectorRuntime(self.fixture, fail_launch=True)
                    sources = self._patch_evidence_sources()
                    with sources[0], sources[1], sources[2], self.assertRaises(
                        GARuntimeAcceptanceError
                    ) as raised:
                        self._collect(self.fixture, runtime)
                    self.assertEqual(
                        str(raised.exception),
                        f"GA runtime acceptance or raw evidence already exists ({name})",
                    )
                    self.assertEqual(runtime.calls, [])
                    self.assertEqual(len(runtime.environments), 3)
                    self.assertEqual(runtime.guards, [guard(), guard(), guard()])
                    self.assertFalse(self.fixture.collection_root.exists())
                finally:
                    if path.is_dir():
                        path.rmdir()
                    else:
                        path.unlink()

    def test_collect_treats_an_unobservable_adapter_as_an_error(self) -> None:
        adapter = self.fixture.acceptance
        lstat = Path.lstat

        def unreadable_adapter(path: Path, *arguments: Any, **values: Any):
            if path == adapter:
                raise PermissionError("fixture adapter probe denied")
            return lstat(path, *arguments, **values)

        runtime = FakeCollectorRuntime(self.fixture, fail_launch=True)
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], patch.object(
            Path, "lstat", autospec=True, side_effect=unreadable_adapter
        ), self.assertRaisesRegex(PermissionError, "fixture adapter probe denied"):
            self._collect(self.fixture, runtime)
        self.assertEqual(runtime.calls, [])
        self.assertEqual(len(runtime.environments), 3)
        self.assertFalse(self.fixture.collection_root.exists())

    def test_recovery_refuses_published_evidence_before_runtime_commands(self) -> None:
        self._create_recoverable_collection()
        events = collection_events(self.fixture.repository)
        parent = self.fixture.acceptance.parent
        for name, create in (
            ("runtime-evidence", lambda path: path.mkdir(mode=0o700)),
            ("runtime-acceptance.json", lambda path: path.write_bytes(b"{}\n")),
        ):
            with self.subTest(published=name):
                path = parent / name
                create(path)
                recovery = FakeCollectorRuntime(self.fixture)
                self._assert_recovery_refused(runtime=recovery)
                self.assertEqual(len(recovery.environments), 3)
                self.assertEqual(recovery.guards, [guard(), guard(), guard()])
                self.assertEqual(collection_events(self.fixture.repository), events)
                if path.is_dir():
                    path.rmdir()
                else:
                    path.unlink()

    def test_recovery_treats_an_unobservable_raw_tree_as_an_error(self) -> None:
        self._create_recoverable_collection()
        lstat = Path.lstat

        def unreadable_raw_root(path: Path, *arguments: Any, **values: Any):
            if path == self.fixture.raw_root:
                raise PermissionError("fixture raw-evidence probe denied")
            return lstat(path, *arguments, **values)

        recovery = FakeCollectorRuntime(self.fixture)
        with patch.object(Path, "lstat", autospec=True, side_effect=unreadable_raw_root), patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), self.assertRaisesRegex(PermissionError, "fixture raw-evidence probe denied"):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertEqual(recovery.calls, [])
        self.assertTrue(self.fixture.collection_root.is_dir())

    def test_recovery_archive_rechecks_publication_under_the_parent_lock(self) -> None:
        self._create_recoverable_collection()
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        capture = recovery.capture_guard

        def publish_during_recovery() -> dict[str, object]:
            self.fixture.raw_root.mkdir(mode=0o700)
            return capture()

        with patch.object(
            recovery, "capture_guard", side_effect=publish_during_recovery
        ), patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), self.assertRaisesRegex(GARuntimeAcceptanceError, "would orphan"):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertTrue(self.fixture.collection_root.is_dir())
        self.assertFalse(
            any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
        )

    def test_resume_seal_requires_published_raw_evidence(self) -> None:
        self._create_recoverable_collection()
        before = {
            path.name: path.read_bytes() for path in self.fixture.collection_root.iterdir()
        }
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError, "no published GA runtime raw evidence"
        ):
            self.fixture.resume_seal()
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.fixture.collection_root.iterdir()},
            before,
        )
        self.assertFalse(self.fixture.acceptance.exists())

    def test_production_capture_is_inside_authenticated_host_test_stage(self) -> None:
        runtime = object.__new__(ProductionCollectorRuntime)
        tokens = RuntimeFixture._traffic_tokens("tcp_traffic")
        expected_capture = b"pcap-bytes"
        expected_traffic = {
            "capture_command": {},
            "endpoint": {},
            "observation_ms": 5000,
            "send_commands": [],
        }
        order: list[str] = []

        def transaction(*, case_id, begin_capture, exercise_test, finish_capture):
            self.assertEqual(case_id, "tcp-ipv4")
            order.append("host-begin")
            begin_capture(object())
            order.append("host-test")
            exercise_test(object())
            order.append("host-restore")
            finish_capture(object())
            return typed_host_receipt("tcp-ipv4")

        with patch.object(
            runtime,
            "_capture_traffic_bytes",
            return_value=(copy.deepcopy(expected_traffic), expected_capture),
        ) as capture_bytes, patch(
            "scripts.ga_runtime_acceptance.run_fixed_host_transaction",
            side_effect=transaction,
        ):
            traffic, capture = runtime.capture_traffic(
                "tcp_traffic", tokens, interpreter=sys.executable
            )
        self.assertEqual(order, ["host-begin", "host-test", "host-restore"])
        capture_bytes.assert_called_once_with(
            "tcp_traffic", tokens, interpreter=sys.executable
        )
        self.assertEqual(capture, expected_capture)
        self.assertEqual(traffic["host_observation"]["case_id"], "tcp-ipv4")

    def test_operator_approval_wait_expires_fail_closed(self) -> None:
        unavailable = PacketHostError("tunnel_unavailable", "Tunnel is not ready")

        def complete(_stage: object) -> PacketCaptureDisposition:
            return PacketCaptureDisposition.COMPLETE

        with patch(
            "scripts.ga_runtime_acceptance.run_fixed_host_transaction",
            side_effect=unavailable,
        ), patch(
            "scripts.ga_runtime_acceptance.time.monotonic",
            side_effect=(0.0, 601.0),
        ), self.assertRaisesRegex(Exception, "Tunnel is not ready"):
            ProductionCollectorRuntime._run_packet_host_transaction(
                case_id="tcp-ipv4",
                begin_capture=complete,
                exercise_test=complete,
                finish_capture=complete,
            )

    def test_host_readiness_never_retries_when_process_cleanup_is_unproven(self) -> None:
        for code in ("baseline_mismatch", "baseline_unavailable", "maintenance_busy", "tunnel_unavailable", "app_control_unavailable"):
            with self.subTest(code=code):
                failure = PacketHostError(code, "initial transaction was not admitted")
                failure.attach_cleanup_context(PacketHostError("host_cleanup_unproven", "owned group remains"))
                def complete(_stage: object) -> PacketCaptureDisposition:
                    self.fail("a failed readiness transaction cannot reach capture callbacks")
                with patch("scripts.ga_runtime_acceptance.run_fixed_host_transaction", side_effect=[failure, typed_host_receipt("tcp-ipv4")]) as transaction, \
                     patch("scripts.ga_runtime_acceptance.time.monotonic", return_value=0.0), \
                     patch("scripts.ga_runtime_acceptance.time.sleep") as sleep, \
                     patch("scripts.ga_runtime_acceptance.sys.stderr", new_callable=io.StringIO) as diagnostic:
                    with self.assertRaises(PacketHostError) as raised:
                        ProductionCollectorRuntime._run_packet_host_transaction(
                            case_id="tcp-ipv4", begin_capture=complete,
                            exercise_test=complete, finish_capture=complete)
                self.assertIs(raised.exception, failure)
                self.assertEqual(raised.exception.cleanup_code, "host_cleanup_unproven")
                transaction.assert_called_once_with(case_id="tcp-ipv4", begin_capture=complete,
                                                    exercise_test=complete, finish_capture=complete)
                sleep.assert_not_called()
                self.assertEqual(diagnostic.getvalue(), "")

    def test_host_readiness_still_retries_clean_app_control_failure(self) -> None:
        unavailable = PacketHostError("app_control_unavailable", "Host is starting")
        expected = typed_host_receipt("tcp-ipv4")
        def complete(_stage: object) -> PacketCaptureDisposition:
            return PacketCaptureDisposition.COMPLETE
        with patch("scripts.ga_runtime_acceptance.run_fixed_host_transaction", side_effect=[unavailable, expected]) as transaction, \
             patch("scripts.ga_runtime_acceptance.time.monotonic", return_value=0.0), \
             patch("scripts.ga_runtime_acceptance.time.sleep") as sleep:
            receipt = ProductionCollectorRuntime._run_packet_host_transaction(
                case_id="tcp-ipv4", begin_capture=complete,
                exercise_test=complete, finish_capture=complete)
        self.assertIs(receipt, expected)
        self.assertEqual(transaction.call_count, 2)
        sleep.assert_called_once_with(0.25)

    def test_host_readiness_waits_through_a_dashboard_mode_change(self) -> None:
        # Selecting Tunnel in the dashboard holds the Host's maintenance lease
        # for the whole start; the Host refuses before any baseline or test.
        expected = typed_host_receipt("tcp-ipv4")
        refusals = [
            PacketHostError("baseline_unavailable", "Tunnel is not ready"),
            PacketHostError("maintenance_busy", "a network mode change is already in progress"),
        ]

        def complete(_stage: object) -> PacketCaptureDisposition:
            return PacketCaptureDisposition.COMPLETE

        with patch(
            "scripts.ga_runtime_acceptance.run_fixed_host_transaction",
            side_effect=[*refusals, expected],
        ) as transaction, patch(
            "scripts.ga_runtime_acceptance.time.monotonic", return_value=0.0
        ), patch("scripts.ga_runtime_acceptance.time.sleep") as sleep, patch(
            "scripts.ga_runtime_acceptance.sys.stderr", new_callable=io.StringIO
        ) as diagnostic:
            receipt = ProductionCollectorRuntime._run_packet_host_transaction(
                case_id="tcp-ipv4",
                begin_capture=complete,
                exercise_test=complete,
                finish_capture=complete,
            )
        self.assertIs(receipt, expected)
        self.assertEqual(transaction.call_count, 3)
        self.assertEqual(
            [call.args for call in sleep.call_args_list],
            [(ga_runtime.PACKET_HOST_TICKET_RETRY_SECONDS,)] * 2,
        )
        self.assertEqual(diagnostic.getvalue().count("waiting for macOS approval"), 1)

    def test_operator_wait_never_exhausts_the_host_launcher_tickets(self) -> None:
        # The signed Host consumes one launcher ticket for every admitted
        # attempt, keeps at most 64 for 305 seconds, and the dns, tcp, udp and
        # stop-cleanup transactions after the wait each need one more.
        capacity, lifetime, attempt_seconds = 64, 305.0, 0.25
        clock = [0.0]
        live: list[float] = []
        peak = [0]

        def monotonic() -> float:
            return clock[0]

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        def transaction(**_arguments: object) -> PacketHostReceipt:
            clock[0] += attempt_seconds
            live[:] = [issued for issued in live if clock[0] - issued < lifetime]
            if len(live) >= capacity:
                raise PacketHostError(
                    "launcher_ticket_capacity_exhausted", "launcher tickets are exhausted"
                )
            live.append(clock[0])
            peak[0] = max(peak[0], len(live))
            raise PacketHostError("baseline_unavailable", "Tunnel is not ready")

        def complete(_stage: object) -> PacketCaptureDisposition:
            return PacketCaptureDisposition.COMPLETE

        with patch(
            "scripts.ga_runtime_acceptance.run_fixed_host_transaction",
            side_effect=transaction,
        ), patch(
            "scripts.ga_runtime_acceptance.time.monotonic", side_effect=monotonic
        ), patch(
            "scripts.ga_runtime_acceptance.time.sleep", side_effect=sleep
        ), patch(
            "scripts.ga_runtime_acceptance.sys.stderr", new_callable=io.StringIO
        ), self.assertRaises(PacketHostError) as raised:
            ProductionCollectorRuntime._run_packet_host_transaction(
                case_id="tcp-ipv4",
                begin_capture=complete,
                exercise_test=complete,
                finish_capture=complete,
            )
        self.assertEqual(raised.exception.code, "baseline_unavailable")
        self.assertGreaterEqual(clock[0], ga_runtime.PACKET_HOST_READY_SECONDS)
        self.assertLessEqual(peak[0], capacity - 4)

    def test_collect_observes_extension_after_first_operator_approval(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        capture_runtime = self._capture_runtime()
        run_command = runtime.run
        capture_fixture_traffic = runtime.capture_traffic
        extension_enabled = False
        extension_observations: list[bool] = []

        def observe(argv: list[str], *, timeout: int = 900) -> dict[str, object]:
            receipt = run_command(argv, timeout=timeout)
            if argv == ["/usr/bin/systemextensionsctl", "list"]:
                extension_observations.append(extension_enabled)
                if not extension_enabled:
                    receipt["stdout"] = "0 extension(s)\n"
            return receipt

        def approve_extension(_delay: float) -> None:
            nonlocal extension_enabled
            extension_enabled = True

        def transaction(*, case_id, begin_capture, exercise_test, finish_capture):
            if not extension_enabled:
                raise PacketHostError("tunnel_unavailable", "Tunnel is not ready")
            begin_capture(object())
            exercise_test(object())
            finish_capture(object())
            return typed_host_receipt(case_id)

        source_patches = self._patch_evidence_sources()
        diagnostics = io.StringIO()
        with source_patches[0], source_patches[1], source_patches[2], patch.object(
            runtime, "run", side_effect=observe
        ), patch.object(
            runtime, "capture_traffic", side_effect=capture_runtime.capture_traffic
        ), patch.object(
            capture_runtime, "_capture_traffic_bytes", side_effect=capture_fixture_traffic
        ), patch(
            "scripts.ga_runtime_acceptance.run_fixed_host_transaction",
            side_effect=transaction,
        ), patch(
            "scripts.ga_runtime_acceptance.time.sleep", side_effect=approve_extension
        ) as approval_wait, patch(
            "scripts.ga_runtime_acceptance.sys.stderr", diagnostics
        ):
            result = collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )

        approval_wait.assert_called_once_with(ga_runtime.PACKET_HOST_TICKET_RETRY_SECONDS)
        self.assertIn("waiting for macOS approval", diagnostics.getvalue())
        self.assertEqual(extension_observations, [True])
        self.assertEqual(result["adapter"]["path"], ACCEPTANCE_RELATIVE.as_posix())
        extension = json.loads(
            (self.fixture.raw_root / "system-extension.json").read_text(encoding="utf-8")
        )
        self.assertEqual(extension["command"]["stdout"], system_extension_output())
        self.assertEqual(extension["collection"]["session_id"], SESSION_ID)
        self.assertEqual(extension["collection"]["challenge"], CHALLENGE)

    def test_collect_rejects_unapproved_extension_after_traffic(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        extension_argv = ("/usr/bin/systemextensionsctl", "list")
        runtime.receipts[extension_argv][0]["stdout"] = system_extension_output().replace(
            "[activated enabled]", "[activated waiting for user]"
        )
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GACollectionRecoveryRequired
        ) as captured:
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )

        self.assertIn(
            "fixed system extension is not both activated and enabled",
            str(captured.exception.__cause__),
        )
        self.assertFalse(self.fixture.acceptance.exists())
        self.assertFalse(self.fixture.raw_root.exists())

    def test_collect_accepts_extensions_retained_until_reboot(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        extension_argv = ("/usr/bin/systemextensionsctl", "list")
        runtime.receipts[extension_argv][0]["stdout"] = observed_replacement_output()
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2]:
            result = collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )

        self.assertEqual(result["adapter"]["path"], ACCEPTANCE_RELATIVE.as_posix())
        extension = json.loads(
            (self.fixture.raw_root / "system-extension.json").read_text(encoding="utf-8")
        )
        self.assertEqual(extension["command"]["stdout"], observed_replacement_output())

    def test_collect_owns_fixed_commands_tokens_raw_bytes_and_atomic_publication(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2]:
            result = collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        self.assertEqual(result["adapter"]["path"], ACCEPTANCE_RELATIVE.as_posix())
        self.assertEqual(set(os.listdir(self.fixture.raw_root)), set(RAW_FILE_NAMES))
        commands = [argv for argv, _timeout in runtime.calls]
        timeouts = {tuple(argv): timeout for argv, timeout in runtime.calls}
        self.assertIn(["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"], commands)
        self.assertIn(["/usr/bin/systemextensionsctl", "list"], commands)
        self.assertNotIn("CFWLifecycleProbe", repr(commands))
        self.assertEqual(
            timeouts[
                tuple(
                    ga_runtime._dmg_verifier_command(
                        REPOSITORY, self.fixture.repository
                    )
                )
            ],
            DMG_BYTE_PROOF_TIMEOUT_SECONDS,
        )
        self.assertTrue(
            all(
                argv[0]
                == "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"
                and list(argv) in commands
                for _probe_id, argv, _exit_code, _stderr in HIGH_RISK_PROBES
            )
        )
        self.assertTrue(all("run_current_service_transaction.sh" not in argv for argv in commands))
        self.assertTrue(all("run_dormant_app_install.sh" not in argv for argv in commands))
        self.assertEqual(runtime.guards, [])
        self.assertEqual(runtime.environments, [])

    def test_collect_waits_for_the_operator_menu_quit_without_an_apple_event(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        wait_for_quit = runtime.await_operator_quit
        at_wait: list[tuple[str, str]] = []

        def operator_quits() -> dict[str, object]:
            last = json.loads(
                sorted(self.fixture.collection_root.glob("event-*.json"))[-1].read_bytes()
            )
            at_wait.append((last["phase"], last["step"]))
            return wait_for_quit()

        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], patch.object(
            runtime, "await_operator_quit", side_effect=operator_quits
        ), patch(
            "scripts.ga_runtime_acceptance.sys.stderr", new_callable=io.StringIO
        ) as diagnostic:
            self._collect(self.fixture, runtime)
        # The runtime's one wait issues the instruction; the collector itself
        # writes nothing. The wait follows the durable started event and ends
        # before the step completes.
        self.assertEqual(diagnostic.getvalue(), "")
        self.assertEqual(at_wait, [("started", "shutdown-request")])
        self.assertEqual(runtime.operator_quit_waits, 1)
        commands = [argv for argv, _timeout in runtime.calls]
        self.assertFalse(
            any(
                argv[0] == LEGACY_APPLE_EVENT_QUIT[0]
                or any("to quit" in argument for argument in argv)
                for argv in commands
            )
        )
        ps = list(PROCESS_OBSERVATION_COMMAND)
        self.assertEqual(
            commands[commands.index(["/usr/bin/systemextensionsctl", "list"]) + 1:],
            [ps, ps, list(OFF_PROOF_COMMAND), ps],
        )
        raw = json.loads((self.fixture.raw_root / "shutdown-restore.json").read_bytes())
        self.assertEqual(raw["shutdown_request"], OPERATOR_QUIT_REQUEST)
        self.assertNotIn("shutdown_command", raw)
        events = [
            json.loads(path.read_bytes())
            for path in sorted(self.fixture.collection_root.glob("event-*.json"))
        ]
        self.assertEqual(
            [(event["phase"], event["step"]) for event in events],
            [*STEP_EVENTS, RAW_PUBLISHED_EVENT],
        )
        self.assertEqual(
            [
                event["command_sha256"]
                for event in events
                if event["step"] == "shutdown-request"
            ],
            [None, None],
        )

    def test_collect_fails_closed_when_the_operator_quit_wait_expires(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        expired = GARuntimeAcceptanceError(
            "installed Host did not exit within the 10-minute operator quit bound"
        )
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], patch.object(
            runtime, "await_operator_quit", side_effect=expired
        ), patch(
            "scripts.ga_runtime_acceptance.sys.stderr", new_callable=io.StringIO
        ) as diagnostic, self.assertRaises(GACollectionRecoveryRequired) as raised:
            self._collect(self.fixture, runtime)
        self.assertIs(raised.exception.__cause__, expired)
        self.assertEqual(diagnostic.getvalue(), "")
        # Nothing runs after the expired wait: no Off proof, no guard, no publication.
        self.assertEqual(runtime.calls[-1][0], ["/usr/bin/systemextensionsctl", "list"])
        self.assertEqual(runtime.guards, [guard()])
        self.assertFalse(self.fixture.raw_root.exists())
        self.assertFalse(self.fixture.acceptance.exists())
        events = [
            json.loads(path.read_bytes())
            for path in sorted(self.fixture.collection_root.glob("event-*.json"))
        ]
        self.assertEqual(
            [(event["phase"], event["step"]) for event in events[-2:]],
            [("started", "shutdown-request"), ("recovery_required", "collection")],
        )

    def test_collect_rejects_an_operator_quit_wait_that_still_sees_the_host(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        running = copy.deepcopy(self.fixture.documents["launch.json"]["process_observation"])
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], patch.object(
            runtime, "await_operator_quit", return_value=running
        ), patch(
            "scripts.ga_runtime_acceptance.sys.stderr", new_callable=io.StringIO
        ), self.assertRaises(GACollectionRecoveryRequired) as raised:
            self._collect(self.fixture, runtime)
        self.assertRegex(
            str(raised.exception.__cause__), f"still contains the installed {TO_BUILD} Host"
        )
        self.assertNotIn(list(OFF_PROOF_COMMAND), [argv for argv, _ in runtime.calls])
        self.assertFalse(self.fixture.raw_root.exists())

    def test_collect_runs_one_off_proof_after_the_operator_quit(self) -> None:
        # A Dock or AppleScript quit leaves the restored Tunnel connected, so
        # the Off proof after the wait is busy. collect reports it and never
        # retries: a retry would reach the passing receipt queued behind it.
        runtime = FakeCollectorRuntime(self.fixture)
        proven = runtime.receipts[tuple(OFF_PROOF_COMMAND)][0]
        busy = copy.deepcopy(proven)
        busy.update(
            exit_code=1,
            stdout="",
            stderr="Packet Tunnel is not at the stable Off barrier\n",
        )
        runtime.receipts[tuple(OFF_PROOF_COMMAND)] = [busy, proven]
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GACollectionRecoveryRequired
        ) as raised:
            self._collect(self.fixture, runtime)
        self.assertEqual(
            str(raised.exception.__cause__),
            "GA collection shutdown-off-proof command identity, exit, or duration is invalid",
        )
        self.assertEqual(runtime.operator_quit_waits, 1)
        commands = [argv for argv, _timeout in runtime.calls]
        self.assertEqual(commands.count(list(OFF_PROOF_COMMAND)), 1)
        self.assertEqual(commands[-1], list(OFF_PROOF_COMMAND))
        self.assertEqual(runtime.receipts[tuple(OFF_PROOF_COMMAND)], [proven])
        # No final process observation or restored guard follows the failure.
        self.assertEqual(runtime.guards, [guard()])
        events = [
            json.loads(path.read_bytes())
            for path in sorted(self.fixture.collection_root.glob("event-*.json"))
        ]
        self.assertEqual(
            [(event["phase"], event["step"]) for event in events[-2:]],
            [("started", "shutdown-off-proof"), ("recovery_required", "collection")],
        )
        self.assertFalse(self.fixture.raw_root.exists())
        self.assertFalse(self.fixture.acceptance.exists())

    def _host_absence_clock(
        self, runtime: ProductionCollectorRuntime, *, exits_at: float | None
    ):
        """Fake the process table, stderr and a clock advanced only by sleeps.

        Each observation also records what the runtime had written to stderr.
        """

        clock = [0.0]
        observed: list[tuple[float, list[str], int]] = []
        notices: list[str] = []
        diagnostic = io.StringIO()
        running = command(
            list(PROCESS_OBSERVATION_COMMAND), stdout=process_table(running=True)
        )
        absent = command(
            list(PROCESS_OBSERVATION_COMMAND), stdout=process_table(running=False)
        )

        def observe(argv: list[str], *, timeout: int) -> dict[str, object]:
            observed.append((clock[0], list(argv), timeout))
            notices.append(diagnostic.getvalue())
            host_exited = exits_at is not None and clock[0] >= exits_at
            return copy.deepcopy(absent if host_exited else running)

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        patches = (
            patch.object(runtime, "run", side_effect=observe),
            patch.object(ga_runtime.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(ga_runtime.time, "sleep", side_effect=sleep),
            patch.object(ga_runtime.sys, "stderr", diagnostic),
        )
        return patches, observed, absent, notices

    def test_operator_quit_wait_polls_until_the_host_exits(self) -> None:
        runtime = self._capture_runtime()
        patches, observed, absent, notices = self._host_absence_clock(
            runtime, exits_at=599.75
        )
        with patches[0], patches[1], patches[2] as slept, patches[3] as diagnostic:
            receipt = runtime.await_operator_quit()
        self.assertEqual(receipt, absent)
        self.assertEqual(observed[-1][0], 599.75)
        self.assertEqual(len(observed), 2400)
        self.assertEqual(
            {(tuple(argv), timeout) for _time, argv, timeout in observed},
            {(PROCESS_OBSERVATION_COMMAND, 10)},
        )
        self.assertEqual({call.args for call in slept.call_args_list}, {(0.25,)})
        # The instruction is issued once, before the first poll.
        self.assertEqual(set(notices), {OPERATOR_QUIT_INSTRUCTION + "\n"})
        self.assertEqual(diagnostic.getvalue(), OPERATOR_QUIT_INSTRUCTION + "\n")

    def test_operator_quit_wait_expires_fail_closed_at_its_ten_minute_bound(self) -> None:
        runtime = self._capture_runtime()
        patches, observed, _absent, notices = self._host_absence_clock(
            runtime, exits_at=None
        )
        with patches[0], patches[1], patches[2], patches[3] as diagnostic, (
            self.assertRaisesRegex(
                GARuntimeAcceptanceError,
                "^installed Host did not exit within the 10-minute operator quit bound$",
            )
        ) as raised:
            runtime.await_operator_quit()
        self.assertIs(type(raised.exception), GARuntimeAcceptanceError)
        # The last observation is at the bound itself; nothing polls past it.
        self.assertEqual(observed[-1][0], 600.0)
        self.assertEqual(len(observed), 2401)
        self.assertEqual(set(notices), {OPERATOR_QUIT_INSTRUCTION + "\n"})
        self.assertEqual(diagnostic.getvalue(), OPERATOR_QUIT_INSTRUCTION + "\n")

    def test_other_host_absence_waits_keep_their_bounds(self) -> None:
        runtime = self._capture_runtime()
        patches, observed, _absent, _notices = self._host_absence_clock(
            runtime, exits_at=None
        )
        with patches[0], patches[1], patches[2], patches[3] as diagnostic:
            with self.assertRaisesRegex(
                GARuntimeAcceptanceError, "outside 1..120 seconds"
            ):
                runtime.await_host_absence(timeout=10 * 60)
            self.assertEqual(observed, [])
            with self.assertRaisesRegex(
                GARuntimeAcceptanceError,
                "^installed Host was still running when its 60-second absence "
                "observation ended$",
            ):
                runtime.await_host_absence(timeout=60)
        self.assertEqual(observed[-1][0], 60.0)
        self.assertEqual(len(observed), 241)
        # Only the operator-quit wait asks the operator for anything.
        self.assertEqual(diagnostic.getvalue(), "")

    def test_environment_digest_propagates_without_private_identity_material(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2]:
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )

        expected_collection = {
            "challenge": CHALLENGE,
            "ga_environment_sha256": GA_ENVIRONMENT_SHA256,
            "session_id": SESSION_ID,
        }
        collection_root = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts)
        collection_documents = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(collection_root.glob("*.json"))
        ]
        raw_documents = [
            json.loads((self.fixture.raw_root / name).read_text(encoding="utf-8"))
            for name in sorted(RAW_FILE_NAMES - PCAP_FILES)
        ]
        adapter = json.loads(self.fixture.acceptance.read_text(encoding="utf-8"))
        self.assertTrue(collection_documents)
        self.assertTrue(raw_documents)
        self.assertTrue(
            all(document["collection"] == expected_collection for document in collection_documents)
        )
        self.assertTrue(
            all(document["collection"] == expected_collection for document in raw_documents)
        )
        self.assertEqual(adapter["collection"], expected_collection)
        self.assertEqual(
            adapter["bindings"]["ga_environment_sha256"],
            GA_ENVIRONMENT_SHA256,
        )

        persisted = b"".join(
            path.read_bytes()
            for path in (
                *sorted(collection_root.glob("*.json")),
                *sorted(self.fixture.raw_root.iterdir()),
                self.fixture.acceptance,
            )
        )
        for forbidden in (
            b"boot_session",
            b"machine_sha256",
            b"boot_environment_sha256",
            RAW_MACHINE_UUID.encode("ascii"),
            RAW_BOOT_UUID.encode("ascii"),
            GA_ENVIRONMENT["machine_sha256"].encode("ascii"),
            GA_ENVIRONMENT["boot_environment_sha256"].encode("ascii"),
        ):
            self.assertNotIn(forbidden, persisted)

    def test_environment_drift_before_intent_is_rejected_without_side_effects(self) -> None:
        drifted = {**GA_ENVIRONMENT, "machine_sha256": "9" * 64}
        runtime = FakeCollectorRuntime(self.fixture, environments=[drifted])
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "collection admission environment",
        ):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        self.assertFalse(
            self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).exists()
        )
        self.assertFalse(self.fixture.raw_root.exists())
        self.assertEqual(runtime.calls, [])

    def test_restarted_cfw_is_bound_before_commands_and_reopens_against_its_run(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        baseline = restarted_guard()
        runtime.guards = [copy.deepcopy(baseline) for _ in range(3)]
        intent_path = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts) / "intent.json"
        run = runtime.run

        def run_after_durable_baseline(argv, *, timeout):
            intent = json.loads(intent_path.read_text(encoding="utf-8"))
            self.assertEqual(intent["cfw_guard_baseline"], baseline)
            self.assertEqual(intent["schema_version"], 4)
            self.assertEqual(intent["document"], "cfm-ga-runtime-collection-intent-v4")
            self.assertEqual(intent["collector"], COLLECTOR)
            self.assertEqual(intent_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                intent["journal_bindings"],
                {key: DIGESTS[key] for key in (
                    "install_journal_sha256", "service_journal_tree_sha256"
                )},
            )
            return run(argv, timeout=timeout)

        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2] as history, patch.object(
            runtime, "run", side_effect=run_after_durable_baseline
        ):
            result = collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
            self.assertGreaterEqual(history.call_count, 2)
            for call in history.call_args_list:
                self.assertEqual(call.args, (self.fixture.repository, self.fixture.expected))
            self.assertEqual(history.return_value, guard())
        self.assertEqual(runtime.guards, [])
        self.assertEqual(result, self.fixture.validate())
        for name in ("legacy-cfw-preserved.json", "shutdown-restore.json"):
            document = json.loads((self.fixture.raw_root / name).read_text(encoding="utf-8"))
            self.assertEqual(document["before_guard"], baseline)
            self.assertEqual(document["after_guard"], baseline)

    def test_collection_guard_drift_never_publishes_acceptance(self) -> None:
        changes = [
            ("cfw_processes", field, value)
            for field, value in (
                ("pid", 9_999),
                ("started_at", "Mon Jul 27 11:45:00 2026"),
                ("binary_sha256", "f" * 64),
                ("uid", 502),
                ("path", "/tmp/Clash for Windows"),
            )
        ] + [
            (field, None, "f" * 64)
            for field in ("dns_sha256", "proxy_sha256", "routes_ipv4_sha256", "routes_ipv6_sha256", "tun_sha256")
        ]
        for section, field, value in changes:
            with self.subTest(section=section, field=field):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                fixture.remove_unsealed_raw_tree()
                runtime = FakeCollectorRuntime(fixture)
                before = restarted_guard()
                after = copy.deepcopy(before)
                if field is None:
                    after[section] = value
                else:
                    after[section][0][field] = value
                # After the same guard before launch, the drift persists
                # through the restored guard's whole 30-second settle,
                # observed once a second.
                runtime.guards = [
                    before,
                    copy.deepcopy(before),
                    *(copy.deepcopy(after) for _ in range(31)),
                ]
                _clock, _sleeps, clock_patches = self._fake_clock()
                source_patches = self._patch_evidence_sources()
                with source_patches[0], source_patches[1], source_patches[2], clock_patches[
                    0
                ], clock_patches[1], self.assertRaises(GACollectionRecoveryRequired) as captured:
                    collect_ga_runtime_acceptance(
                        repository=fixture.repository,
                        expected=fixture.expected,
                        prepackage_stage_verifier=prepackage_stage_verifier,
                        runtime=runtime,
                        challenge_bytes=b"C" * 32,
                        session_id=SESSION_ID,
                    )
                self.assertIsInstance(captured.exception.__cause__, GARuntimeAcceptanceError)
                if field == "path":
                    # A foreign CFW path is a malformed observation, which no
                    # settle can repair: it fails at the first restored guard.
                    self.assertEqual(
                        str(captured.exception.__cause__),
                        "collection restored CFW guard is malformed",
                    )
                    self.assertEqual(len(runtime.guards), 30)
                else:
                    self.assertEqual(
                        str(captured.exception.__cause__),
                        "collection did not restore the exact pre-run CFW state",
                    )
                    self.assertEqual(runtime.guards, [])
                self.assertFalse(fixture.raw_root.exists())
                self.assertFalse(fixture.acceptance.exists())

    def test_baseline_observation_errors_do_not_create_intent_or_run_commands(self) -> None:
        for failure in (PermissionError("guard permission denied"), GARuntimeAcceptanceError("guard unavailable")):
            with self.subTest(error=type(failure).__name__):
                runtime = FakeCollectorRuntime(self.fixture)
                with patch.object(
                    runtime, "capture_guard", side_effect=failure
                ), patch.object(
                    ga_runtime, "_installed_guard_baseline", return_value=guard()
                ), self.assertRaises(type(failure)) as captured:
                    collect_ga_runtime_acceptance(
                        repository=self.fixture.repository,
                        expected=self.fixture.expected,
                        prepackage_stage_verifier=prepackage_stage_verifier,
                        runtime=runtime,
                        challenge_bytes=b"C" * 32,
                        session_id=SESSION_ID,
                    )
                self.assertIs(captured.exception, failure)
                self.assertEqual(runtime.calls, [])
                self.assertFalse(self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).exists())

    def test_invalid_install_history_still_blocks_collection_before_observation(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        with patch.object(
            ga_runtime, "_installed_guard_baseline",
            side_effect=GARuntimeAcceptanceError("install guard lineage drifted"),
        ), self.assertRaisesRegex(GARuntimeAcceptanceError, "install guard lineage drifted"):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        self.assertEqual(runtime.guards, [guard(), guard(), guard()])
        self.assertEqual(runtime.calls, [])
        self.assertFalse(self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).exists())

    def test_environment_symlink_is_rejected_before_collection_intent(self) -> None:
        original = self.fixture.environment_path.parent / "environment-original.json"
        self.fixture.environment_path.rename(original)
        self.fixture.environment_path.symlink_to(original.name)
        runtime = FakeCollectorRuntime(self.fixture)
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "cannot be reopened safely",
        ):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        self.assertFalse(
            self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).exists()
        )
        self.assertEqual(runtime.calls, [])

    def test_environment_drift_before_first_mutation_aborts_collection(self) -> None:
        drifted = {**GA_ENVIRONMENT, "boot_environment_sha256": "9" * 64}
        runtime = FakeCollectorRuntime(
            self.fixture,
            environments=[GA_ENVIRONMENT, drifted],
        )
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "pre-mutation environment",
        ):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        commands = [argv for argv, _timeout in runtime.calls]
        self.assertNotIn(
            ["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"],
            commands,
        )
        collection_root = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts)
        final_event = json.loads(
            sorted(collection_root.glob("event-*.json"))[-1].read_text(encoding="utf-8")
        )
        self.assertEqual(final_event["phase"], "aborted_before_mutation")
        self.assertFalse(self.fixture.raw_root.exists())

    def test_environment_drift_after_restore_requires_recovery(self) -> None:
        drifted = {**GA_ENVIRONMENT, "macos_build_version": "26A5389a"}
        runtime = FakeCollectorRuntime(
            self.fixture,
            environments=[GA_ENVIRONMENT, GA_ENVIRONMENT, drifted],
        )
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GACollectionRecoveryRequired
        ) as captured:
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        self.assertIsInstance(captured.exception.__cause__, GARuntimeAcceptanceError)
        self.assertIn("post-restore environment", str(captured.exception.__cause__))
        collection_root = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts)
        final_event = json.loads(
            sorted(collection_root.glob("event-*.json"))[-1].read_text(encoding="utf-8")
        )
        self.assertEqual(final_event["phase"], "recovery_required")
        self.assertFalse(self.fixture.raw_root.exists())

    def test_cli_exposes_fixed_collect_and_recover_without_input_paths(self) -> None:
        self.assertEqual(_arguments(["collect"]).command, "collect")
        self.assertEqual(_arguments(["recover"]).command, "recover")
        self.assertEqual(_arguments(["resume-seal"]).command, "resume-seal")
        for rejected in (
            ["collect", "--input", "/tmp/untrusted"],
            ["resume-seal", "--input", "/tmp/untrusted"],
            ["seal"],
        ):
            with self.subTest(arguments=rejected), patch(
                "sys.stderr", new_callable=io.StringIO
            ), self.assertRaises(SystemExit):
                _arguments(rejected)
        runner = REPOSITORY / "scripts/run_ga_runtime_acceptance.sh"
        source = runner.read_text(encoding="utf-8")
        self.assertTrue(os.access(runner, os.X_OK))
        self.assertIn("cfw_seal_release_tool_environment production", source)
        self.assertIn("cfw_run_release_python_script", source)
        self.assertIn('"$repo_root/scripts/ga_runtime_acceptance_cli.py"', source)

    def test_collect_refuses_to_start_before_authoritative_journals_close(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        with self.assertRaisesRegex(PublicationError, "expected bindings"):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected={},
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=runtime,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        self.assertFalse(
            self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).exists()
        )
        self.assertEqual(runtime.calls, [])

    def test_runtime_failure_requires_only_fixed_cleanup_recovery(self) -> None:
        failing = FakeCollectorRuntime(self.fixture, fail_launch=True)
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GACollectionRecoveryRequired
        ):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=failing,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )
        recovery = FakeCollectorRuntime(self.fixture)
        # A failed open has no dashboard to quit; recovery observes absence,
        # proves global Off through the signed Host, then checks the final guard.
        process_receipt = copy.deepcopy(
            self.fixture.documents["shutdown-restore.json"]["process_observation"]
        )
        recovery.receipts = {
            tuple(PROCESS_OBSERVATION_COMMAND): [
                copy.deepcopy(process_receipt),
                copy.deepcopy(process_receipt),
                copy.deepcopy(process_receipt),
            ],
            tuple(OFF_PROOF_COMMAND): [
                copy.deepcopy(
                    self.fixture.documents["shutdown-restore.json"]["off_proof_command"]
                )
            ],
        }
        recovery.guards = [guard()]
        with patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ):
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertTrue(archived.is_dir())
        recovered_commands = [argv for argv, _timeout in recovery.calls]
        self.assertEqual(
            recovered_commands,
            [
                list(PROCESS_OBSERVATION_COMMAND),
                list(PROCESS_OBSERVATION_COMMAND),
                list(OFF_PROOF_COMMAND),
                list(PROCESS_OBSERVATION_COMMAND),
            ],
        )

    def test_interrupted_event_before_raw_publication_keeps_a_whole_sequence(
        self,
    ) -> None:
        # An interrupt inside an event write before raw publication once left
        # a torn event that recovery appended after and archived.
        launch_started = self.fixture.collection_root / "event-004.json"
        runtime = FakeCollectorRuntime(self.fixture)
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], interrupted_write(
            b'"sequence":4,"step":"launch"}', launch_started
        ) as final_present, self.assertRaises(GACollectionRecoveryRequired) as raised:
            self._collect(self.fixture, runtime)
        self.assertIsInstance(raised.exception.__cause__, _SimulatedTermination)
        self.assertEqual(final_present, [False, False])
        self.assertEqual(
            collection_events(self.fixture.repository),
            [*STEP_EVENTS[:4], ("recovery_required", "collection")],
        )
        self.assertNotIn(
            ["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"],
            [argv for argv, _timeout in runtime.calls],
        )
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        with patch.object(ga_runtime, "_installed_guard_baseline", return_value=guard()):
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        archived_events = [
            json.loads(path.read_bytes()) for path in sorted(archived.glob("event-*.json"))
        ]
        self.assertEqual(
            [event["sequence"] for event in archived_events],
            list(range(len(archived_events))),
        )
        self.assertEqual(
            (archived_events[4]["phase"], archived_events[-1]["phase"]),
            ("recovery_required", "recovered"),
        )
        self.assertFalse(self.fixture.collection_root.exists())

    def test_unknown_event_durability_mid_collection_points_to_recover(self) -> None:
        # The launch "started" event is renamed into place but its directory
        # barrier fails: the outcome is unknown, no recovery_required event is
        # appended in-process, and recover handles the attempt.
        collection_target: list[tuple[int, int]] = []
        real_rename = durable_file._renameatx_np
        real_full_fsync = durable_file.full_fsync

        def rename(source, source_name, destination, destination_name, flags):
            real_rename(source, source_name, destination, destination_name, flags)
            if destination_name == "event-004.json":
                metadata = os.fstat(destination)
                collection_target.append((metadata.st_dev, metadata.st_ino))

        def fail_collection_barrier(descriptor: int) -> None:
            metadata = os.fstat(descriptor)
            if collection_target and (metadata.st_dev, metadata.st_ino) == collection_target[0]:
                raise OSError(5, "injected collection directory full-fsync failure")
            real_full_fsync(descriptor)

        runtime = FakeCollectorRuntime(self.fixture)
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], patch.object(
            durable_file, "_renameatx_np", side_effect=rename
        ), patch.object(
            durable_file, "full_fsync", side_effect=fail_collection_barrier
        ), self.assertRaises(DurabilityOutcomeUnknown) as raised:
            self._collect(self.fixture, runtime)
        notes = getattr(raised.exception, "__notes__", [])
        self.assertTrue(any(RECOVERY_COMMAND in note for note in notes), notes)
        self.assertEqual(
            collection_events(self.fixture.repository),
            [*STEP_EVENTS[:4], ("started", "launch")],
        )
        self.assertNotIn(
            ["/usr/bin/open", "-a", "/Applications/Clash for Mac.app"],
            [argv for argv, _timeout in runtime.calls],
        )
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        with patch.object(ga_runtime, "_installed_guard_baseline", return_value=guard()):
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        archived_events = [
            json.loads(path.read_bytes()) for path in sorted(archived.glob("event-*.json"))
        ]
        self.assertEqual(
            [event["sequence"] for event in archived_events],
            list(range(len(archived_events))),
        )
        self.assertEqual(archived_events[-1]["phase"], "recovered")

    def test_staging_left_before_raw_publication_blocks_neither_recover_nor_collect(
        self,
    ) -> None:
        # A crash before raw publication can leave a staged event beside the
        # collection; recovery archives the attempt and a fresh collect seals.
        self._create_recoverable_collection()
        leftover = self.fixture.acceptance.parent / (
            f"{durable_file.FILE_STAGING_PREFIX}{'0' * 32}"
        )
        leftover.write_bytes(b'{"phase":')
        leftover.chmod(0o600)
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        with patch.object(ga_runtime, "_installed_guard_baseline", return_value=guard()):
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertTrue(archived.is_dir())
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2]:
            result = self._collect(self.fixture, FakeCollectorRuntime(self.fixture))
        self.assertEqual(result, self.fixture.validate())
        self.assertEqual(leftover.read_bytes(), b'{"phase":')

    def test_recovery_restores_the_recorded_run_baseline_without_resampling_it(self) -> None:
        baseline = restarted_guard()
        self._create_recoverable_collection(baseline)
        intent_path = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts) / "intent.json"
        intent_bytes = intent_path.read_bytes()
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        recovery.guards = [copy.deepcopy(baseline)]
        capture = recovery.capture_guard

        def observe_after_cleanup():
            self.assertEqual(
                [argv for argv, _timeout in recovery.calls],
                [list(PROCESS_OBSERVATION_COMMAND), list(PROCESS_OBSERVATION_COMMAND),
                 list(OFF_PROOF_COMMAND), list(PROCESS_OBSERVATION_COMMAND)],
            )
            return capture()

        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ) as history, patch.object(
            recovery, "capture_guard", side_effect=observe_after_cleanup
        ) as observer:
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        history.assert_called_once_with(self.fixture.repository, self.fixture.expected)
        observer.assert_called_once_with()
        self.assertEqual((archived / "intent.json").read_bytes(), intent_bytes)
        self.assertEqual(recovery.guards, [])
        self.assertFalse(intent_path.exists())
        self.assertFalse(self.fixture.acceptance.exists())

    def test_recovery_cannot_substitute_the_historical_install_guard(self) -> None:
        self._create_recoverable_collection(restarted_guard())
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        # The historical guard persists through the whole 30-second settle.
        recovery.guards = [guard() for _ in range(31)]
        _clock, _sleeps, clock_patches = self._fake_clock()
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), clock_patches[0], clock_patches[1], self.assertRaisesRegex(
            GARuntimeAcceptanceError, "collection's fixed CFW guard"
        ):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertEqual(recovery.guards, [])
        self.assertTrue(self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).is_dir())
        self.assertFalse(any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*")))
        self.assertFalse(self.fixture.acceptance.exists())

    def test_recovery_rejects_invalid_or_legacy_intent_before_commands(self) -> None:
        self._create_recoverable_collection(restarted_guard())
        collection = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts)
        path = collection / "intent.json"
        original = json.loads(path.read_text(encoding="utf-8"))
        malformed_guard = {**original, "cfw_guard_baseline": {}}
        missing_guard = dict(original)
        del missing_guard["cfw_guard_baseline"]
        missing_journals = dict(original)
        del missing_journals["journal_bindings"]
        wrong_journals = copy.deepcopy(original)
        wrong_journals["journal_bindings"]["service_journal_tree_sha256"] = "e" * 64
        wrong_package = copy.deepcopy(original)
        wrong_package["package_bindings"]["dmg_sha256"] = "e" * 64
        legacy = {key: value for key, value in original.items()
                  if key not in {"cfw_guard_baseline", "journal_bindings"}}
        legacy.update(document="cfm-ga-runtime-collection-intent-v2", schema_version=2)
        wrong_version = {**original, "schema_version": 2}
        events = {item.name: item.read_bytes() for item in collection.glob("event-*.json")}
        for label, intent, error_type in (
            ("malformed guard", malformed_guard, GARuntimeAcceptanceError),
            ("missing guard", missing_guard, PublicationError),
            ("missing journals", missing_journals, PublicationError),
            ("wrong journals", wrong_journals, GARuntimeAcceptanceError),
            ("wrong package", wrong_package, GARuntimeAcceptanceError),
            ("legacy", legacy, PublicationError),
            ("wrong version", wrong_version, GARuntimeAcceptanceError),
        ):
            with self.subTest(case=label):
                data = canonical_json(intent)
                path.write_bytes(data)
                recovery = FakeCollectorRuntime(self.fixture)
                with patch.object(
                    ga_runtime, "_installed_guard_baseline", return_value=guard()
                ), self.assertRaises(error_type):
                    recover_ga_runtime_collection(
                        repository=self.fixture.repository,
                        expected=self.fixture.expected,
                        runtime=recovery,
                    )
                self.assertEqual(recovery.calls, [])
                self.assertEqual(recovery.guards, [guard(), guard(), guard()])
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(
                    {item.name: item.read_bytes() for item in collection.glob("event-*.json")},
                    events,
                )

    def test_recovery_still_rejects_invalid_historical_install_lineage(self) -> None:
        self._create_recoverable_collection(restarted_guard())
        recovery = FakeCollectorRuntime(self.fixture)
        with patch.object(
            ga_runtime, "_installed_guard_baseline",
            side_effect=GARuntimeAcceptanceError("install guard lineage drifted"),
        ), self.assertRaisesRegex(GARuntimeAcceptanceError, "install guard lineage drifted"):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertEqual(recovery.calls, [])
        self.assertEqual(recovery.guards, [guard(), guard(), guard()])
        self.assertTrue(self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).is_dir())

    def test_recovery_rejects_environment_drift_before_runtime_mutation(self) -> None:
        self._create_recoverable_collection()
        drifted = {**GA_ENVIRONMENT, "machine_sha256": "9" * 64}
        recovery = FakeCollectorRuntime(self.fixture, environments=[drifted])
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "recovery admission environment",
        ):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertEqual(recovery.calls, [])
        self.assertTrue(
            self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).is_dir()
        )

    def test_recovery_rejects_environment_drift_after_restore(self) -> None:
        self._create_recoverable_collection()
        drifted = {**GA_ENVIRONMENT, "macos_build_version": "26A5389a"}
        recovery = self._absent_host_recovery_runtime(
            [GA_ENVIRONMENT, drifted]
        )
        with patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ), self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "recovery post-restore environment",
        ):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertTrue(
            self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts).is_dir()
        )
        self.assertFalse(
            any(
                path.name.startswith("runtime-collection-aborted-")
                for path in self.fixture.acceptance.parent.iterdir()
            )
        )

    def test_recovery_waits_for_the_operator_menu_quit_when_the_host_is_running(
        self,
    ) -> None:
        failing = FakeCollectorRuntime(self.fixture)
        system_command = self.fixture.documents["system-extension.json"]["command"]
        failing.receipts[tuple(system_command["argv"])] = []
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
            GACollectionRecoveryRequired
        ):
            collect_ga_runtime_acceptance(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
                runtime=failing,
                challenge_bytes=b"C" * 32,
                session_id=SESSION_ID,
            )

        recovery = FakeCollectorRuntime(self.fixture)
        shutdown = self.fixture.documents["shutdown-restore.json"]
        recovery.receipts = {
            tuple(PROCESS_OBSERVATION_COMMAND): [
                copy.deepcopy(self.fixture.documents["launch.json"]["process_observation"]),
                copy.deepcopy(shutdown["host_process_observation"]),
                copy.deepcopy(shutdown["host_process_observation"]),
                copy.deepcopy(shutdown["process_observation"]),
            ],
            tuple(OFF_PROOF_COMMAND): [copy.deepcopy(shutdown["off_proof_command"])],
        }
        recovery.guards = [guard()]
        with patch(
            "scripts.ga_runtime_acceptance._installed_guard_baseline",
            return_value=guard(),
        ), patch(
            "scripts.ga_runtime_acceptance.sys.stderr", new_callable=io.StringIO
        ) as diagnostic:
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertTrue(archived.is_dir())
        # The runtime's one wait issues the instruction; recovery writes nothing.
        self.assertEqual(diagnostic.getvalue(), "")
        self.assertEqual(recovery.operator_quit_waits, 1)
        # The operator-quit wait observes the process table; no quit is sent.
        self.assertEqual(
            [argv for argv, _timeout in recovery.calls],
            [
                list(PROCESS_OBSERVATION_COMMAND),
                list(PROCESS_OBSERVATION_COMMAND),
                list(PROCESS_OBSERVATION_COMMAND),
                list(OFF_PROOF_COMMAND),
                list(PROCESS_OBSERVATION_COMMAND),
            ],
        )
        events = [
            json.loads(path.read_bytes()) for path in sorted(archived.glob("event-*.json"))
        ]
        recovery_events = [
            (event["phase"], event["step"], event["command_sha256"])
            for event in events
            if event["step"].startswith("runtime-")
        ]
        self.assertEqual(
            recovery_events[:2],
            [
                ("started", "runtime-recovery-shutdown-request", None),
                ("completed", "runtime-recovery-shutdown-request", None),
            ],
        )

    def test_recovery_guides_the_operator_when_the_off_proof_fails_without_a_host(
        self,
    ) -> None:
        self._create_recoverable_collection()
        shutdown = self.fixture.documents["shutdown-restore.json"]
        busy = copy.deepcopy(shutdown["off_proof_command"])
        busy.update(
            exit_code=1,
            stdout="",
            stderr="Packet Tunnel is not at the stable Off barrier\n",
        )
        unproven = copy.deepcopy(shutdown["off_proof_command"])
        unproven["stdout"] = ""
        rejected = "GA collection runtime-recovery-off-proof"
        # A receipt the command boundary rejects keeps its own diagnosis
        # ahead of the guidance; an unproven Off receipt has none.
        busy_diagnosis = [
            f"{rejected} failed its exit check: exit status 1, expected 0; duration "
            "1.000 s, bound 60 s",
            f"{rejected} stdout is empty",
            f"{rejected} stderr (47 bytes) ends with:\n"
            "Packet Tunnel is not at the stable Off barrier\n",
        ]
        for label, off_proof, diagnosis in (
            ("busy", busy, busy_diagnosis),
            ("unproven", unproven, []),
        ):
            with self.subTest(label):
                # The Host is already gone, so recovery goes straight to the one
                # signed Off proof; a failure is reported, never retried.
                recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT])
                recovery.receipts[tuple(OFF_PROOF_COMMAND)] = [off_proof]
                with patch.object(
                    ga_runtime, "_installed_guard_baseline", return_value=guard()
                ), patch(
                    "scripts.ga_runtime_acceptance.sys.stderr",
                    new_callable=io.StringIO,
                ) as diagnostic, self.assertRaises(GARuntimeAcceptanceError) as raised:
                    recover_ga_runtime_collection(
                        repository=self.fixture.repository,
                        expected=self.fixture.expected,
                        runtime=recovery,
                    )
                self.assertEqual(
                    getattr(raised.exception, "__notes__", []),
                    [*diagnosis, RECOVERY_OFF_PROOF_GUIDANCE],
                )
                self.assertIn(
                    f"\n  {RECOVERY_OFF_PROOF_GUIDANCE}\n",
                    common.failure_diagnostic("error: fixture headline", raised.exception)
                    + "\n",
                )
                self.assertEqual(diagnostic.getvalue(), "")
                self.assertEqual(recovery.operator_quit_waits, 0)
                self.assertEqual(
                    [argv for argv, _timeout in recovery.calls],
                    [
                        list(PROCESS_OBSERVATION_COMMAND),
                        list(PROCESS_OBSERVATION_COMMAND),
                        list(OFF_PROOF_COMMAND),
                    ],
                )
                self.assertEqual(recovery.guards, [guard()])
                self.assertEqual(
                    collection_events(self.fixture.repository)[-1],
                    ("started", "runtime-recovery-off-proof"),
                )
                self.assertTrue(self.fixture.collection_root.is_dir())
                self.assertFalse(
                    any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
                )

    def test_recovery_guides_the_operator_when_its_quit_wait_expires(self) -> None:
        self._create_recoverable_collection()
        recovery = FakeCollectorRuntime(self.fixture)
        recovery.receipts = {
            tuple(PROCESS_OBSERVATION_COMMAND): [
                copy.deepcopy(self.fixture.documents["launch.json"]["process_observation"])
            ],
        }
        recovery.guards = [guard()]
        expired = GARuntimeAcceptanceError(
            "installed Host did not exit within the 10-minute operator quit bound"
        )
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), patch.object(
            recovery, "await_operator_quit", side_effect=expired
        ), self.assertRaises(GARuntimeAcceptanceError) as raised:
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertIs(raised.exception, expired)
        self.assertEqual(raised.exception.__notes__, [RECOVERY_OPERATOR_QUIT_GUIDANCE])
        self.assertIn(
            f"\n  {RECOVERY_OPERATOR_QUIT_GUIDANCE}\n",
            common.failure_diagnostic("error: fixture headline", raised.exception) + "\n",
        )
        # Nothing runs after the expired wait: no Off proof, guard or archive.
        self.assertEqual(
            [argv for argv, _timeout in recovery.calls], [list(PROCESS_OBSERVATION_COMMAND)]
        )
        self.assertEqual(recovery.guards, [guard()])
        self.assertEqual(
            collection_events(self.fixture.repository)[-1],
            ("started", "runtime-recovery-shutdown-request"),
        )
        self.assertFalse(
            any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
        )

    def _write_fresh_collection(
        self,
        events: list[tuple[str, str]],
        *,
        baseline: dict[str, object] | None = None,
    ) -> Path:
        # Each subtest starts without a collection or archive from the last.
        parent = self.fixture.acceptance.parent
        for stale in (self.fixture.collection_root, *parent.glob("runtime-collection-aborted-*")):
            if stale.exists():
                shutil.rmtree(stale)
        self.fixture.write_collection_receipt(events=events, baseline=baseline)
        return self.fixture.collection_root

    @staticmethod
    def _archived_events(archived: Path) -> list[dict[str, Any]]:
        return [
            json.loads(path.read_bytes()) for path in sorted(archived.glob("event-*.json"))
        ]

    def _assert_archived_log(
        self, archived: Path, events: list[tuple[str, str]], intent: bytes
    ) -> None:
        # The archive is still one whole collection: its intent and an
        # unbroken event sequence, nothing else.
        documents = self._archived_events(archived)
        self.assertEqual([(event["phase"], event["step"]) for event in documents], events)
        self.assertEqual(
            [event["sequence"] for event in documents], list(range(len(documents)))
        )
        self.assertEqual(
            sorted(path.name for path in archived.iterdir()),
            sorted(
                ["intent.json", *(f"event-{index:03d}.json" for index in range(len(events)))]
            ),
        )
        self.assertEqual((archived / "intent.json").read_bytes(), intent)

    def _aborted_collection(
        self, prepare: Any, steps: list[tuple[str, str]]
    ) -> RuntimeFixture:
        fixture = RuntimeFixture()
        self.addCleanup(fixture.cleanup)
        fixture.remove_unsealed_raw_tree()
        failing = FakeCollectorRuntime(fixture)
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], prepare(failing), self.assertRaises(
            GARuntimeAcceptanceError
        ) as raised:
            self._collect(fixture, failing)
        self.assertNotIsInstance(raised.exception, GACollectionRecoveryRequired)
        self.assertEqual(
            getattr(raised.exception, "__notes__", [])[-1:], [PRE_MUTATION_ABORT_GUIDANCE]
        )
        self.assertEqual(collection_events(fixture.repository), [*steps, ABORTED_EVENT])
        return fixture

    @staticmethod
    def _failed_install_command(name: str, exit_code: int) -> Any:
        def prepare(runtime: FakeCollectorRuntime) -> Any:
            argv = runtime.fixture.documents["exact-dmg-install.json"]["commands"][name]["argv"]
            runtime.receipts[tuple(argv)][0]["exit_code"] = exit_code
            return nullcontext()

        return prepare

    def test_recovery_archives_an_attempt_aborted_before_mutation_without_runtime_work(
        self,
    ) -> None:
        # collect records aborted_before_mutation only before it launches the
        # Host, so nothing it owns has changed. A later environment or
        # whole-system network change must not strand the attempt: recover
        # archives it without observing the environment, the guard or any
        # process, and a fresh collect can start.
        drifted = {**GA_ENVIRONMENT, "macos_build_version": "26A5389a"}

        def drift_before_launch(runtime: FakeCollectorRuntime) -> Any:
            runtime.environments = [copy.deepcopy(GA_ENVIRONMENT), copy.deepcopy(drifted)]
            return nullcontext()

        def fail_before_the_first_step(runtime: FakeCollectorRuntime) -> Any:
            # A failure between the intent and the first step's started
            # event, as an interrupted append of that event, records only
            # the abort.
            append = ga_runtime._append_collection_event
            phases: list[str] = []

            def first_append_fails(*arguments: Any, **options: Any) -> None:
                phases.append(options["phase"])
                if len(phases) == 1:
                    raise GARuntimeAcceptanceError("fixture failure before the first step")
                append(*arguments, **options)

            return patch.object(
                ga_runtime, "_append_collection_event", side_effect=first_append_fails
            )

        def guard_drift_before_launch(runtime: FakeCollectorRuntime) -> Any:
            # The guard still differs through the whole pre-launch settle.
            runtime.guards = [guard(), *(self._configd_transient() for _ in range(31))]
            _clock, _sleeps, (monotonic, sleep) = self._fake_clock()

            @contextmanager
            def settle_without_waiting() -> Iterator[None]:
                with monotonic, sleep:
                    yield

            return settle_without_waiting()

        cases = (
            ("failure before the first step", fail_before_the_first_step, []),
            ("Gatekeeper refusal", self._failed_install_command("dmg_gatekeeper", 3), STEP_EVENTS[:1]),
            ("byte-proof failure", self._failed_install_command("dmg_set_verify", 19), STEP_EVENTS[:3]),
            ("pre-mutation environment drift", drift_before_launch, STEP_EVENTS[:4]),
            ("pre-launch guard drift", guard_drift_before_launch, STEP_EVENTS[:4]),
        )
        for label, prepare, steps in cases:
            with self.subTest(label):
                fixture = self._aborted_collection(prepare, steps)
                intent = (fixture.collection_root / "intent.json").read_bytes()
                recovery = FakeCollectorRuntime(fixture, environments=[drifted])
                recovery.receipts = {}
                recovery.guards = [restarted_guard()]
                with patch.object(
                    ga_runtime, "_installed_guard_baseline", return_value=guard()
                ):
                    archived = recover_ga_runtime_collection(
                        repository=fixture.repository,
                        expected=fixture.expected,
                        runtime=recovery,
                    )
                self.assertEqual(recovery.calls, [])
                self.assertEqual(recovery.environments, [drifted])
                self.assertEqual(recovery.guards, [restarted_guard()])
                self.assertEqual(
                    archived,
                    fixture.acceptance.parent / f"runtime-collection-aborted-{SESSION_ID}",
                )
                self.assertFalse(fixture.collection_root.exists())
                self._assert_archived_log(
                    archived, [*steps, ABORTED_EVENT, ARCHIVED_BEFORE_MUTATION_EVENT], intent
                )
                sources = self._patch_evidence_sources()
                with sources[0], sources[1], sources[2]:
                    collected = self._collect(fixture, FakeCollectorRuntime(fixture))
                self.assertEqual(collected, fixture.validate())

    def test_an_interrupted_archive_is_completed_without_a_second_marker(self) -> None:
        fixture = self._aborted_collection(
            self._failed_install_command("dmg_set_verify", 19), STEP_EVENTS[:3]
        )
        intent = (fixture.collection_root / "intent.json").read_bytes()
        rename = os.rename

        def fail_archive_rename(source: Any, destination: Any, **descriptors: Any) -> None:
            if str(destination).startswith("runtime-collection-aborted-"):
                raise OSError(5, "fixture archive rename failure")
            rename(source, destination, **descriptors)

        recovery = FakeCollectorRuntime(fixture)
        recovery.receipts = {}
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), patch.object(
            ga_runtime.os, "rename", side_effect=fail_archive_rename
        ), self.assertRaisesRegex(
            GARuntimeAcceptanceError, "^recovered collection could not be archived$"
        ):
            recover_ga_runtime_collection(
                repository=fixture.repository, expected=fixture.expected, runtime=recovery
            )
        recorded = [*STEP_EVENTS[:3], ABORTED_EVENT, ARCHIVED_BEFORE_MUTATION_EVENT]
        self.assertEqual(collection_events(fixture.repository), recorded)
        with patch.object(ga_runtime, "_installed_guard_baseline", return_value=guard()):
            archived = recover_ga_runtime_collection(
                repository=fixture.repository, expected=fixture.expected, runtime=recovery
            )
        self.assertEqual(recovery.calls, [])
        self.assertEqual(len(recovery.environments), 3)
        self.assertEqual(recovery.guards, [guard(), guard(), guard()])
        self._assert_archived_log(archived, recorded, intent)

    def test_a_concurrent_recover_never_appends_a_second_archive_marker(self) -> None:
        # Another recover can append the marker after this one read the log;
        # the marker's fixed sequence then refuses this one's append.
        root = self._write_fresh_collection([*STEP_EVENTS[:3], ABORTED_EVENT])

        def concurrent_marker(*_arguments: Any) -> dict[str, object]:
            marker = root / "event-004.json"
            marker.write_bytes(collection_event(4, *ARCHIVED_BEFORE_MUTATION_EVENT))
            marker.chmod(0o600)
            return guard()

        recovery = FakeCollectorRuntime(self.fixture)
        recovery.receipts = {}
        with patch.object(
            ga_runtime, "_installed_guard_baseline", side_effect=concurrent_marker
        ), self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "^GA runtime collection recovered event requires sequence 4, but the "
            "collection holds 5 events$",
        ):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertEqual(
            collection_events(self.fixture.repository),
            [*STEP_EVENTS[:3], ABORTED_EVENT, ARCHIVED_BEFORE_MUTATION_EVENT],
        )
        self.assertEqual(recovery.calls, [])
        self.assertFalse(
            any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
        )

    def test_an_aborted_attempt_is_archived_only_against_its_own_bindings(self) -> None:
        # Archiving needs no runtime observation, but the attempt must still
        # be this candidate's: its intent bindings and the closed install
        # history are checked exactly as before a full recovery.
        def wrong_package(intent: dict[str, Any]) -> None:
            intent["package_bindings"]["dmg_sha256"] = "e" * 64

        def wrong_journals(intent: dict[str, Any]) -> None:
            intent["journal_bindings"]["install_journal_sha256"] = "e" * 64

        lineage = GARuntimeAcceptanceError("install guard lineage drifted")
        cases = (
            ("package", wrong_package, {"return_value": guard()}, "binds different package evidence"),
            ("journals", wrong_journals, {"return_value": guard()}, "binds different migration journals"),
            ("install history", lambda _intent: None, {"side_effect": lineage}, "^install guard lineage drifted$"),
        )
        for label, change, history, message in cases:
            with self.subTest(label):
                fixture = self._aborted_collection(
                    self._failed_install_command("dmg_set_verify", 19), STEP_EVENTS[:3]
                )
                path = fixture.collection_root / "intent.json"
                intent = json.loads(path.read_text(encoding="utf-8"))
                change(intent)
                path.write_bytes(canonical_json(intent))
                before = {
                    item.name: item.read_bytes() for item in fixture.collection_root.iterdir()
                }
                recovery = FakeCollectorRuntime(fixture)
                with patch.object(
                    ga_runtime, "_installed_guard_baseline", **history
                ), self.assertRaisesRegex(GARuntimeAcceptanceError, message):
                    recover_ga_runtime_collection(
                        repository=fixture.repository,
                        expected=fixture.expected,
                        runtime=recovery,
                    )
                self.assertEqual(recovery.calls, [])
                self.assertEqual(
                    {item.name: item.read_bytes() for item in fixture.collection_root.iterdir()},
                    before,
                )
                self.assertFalse(
                    any(fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
                )

    def test_recovery_of_a_collection_that_may_have_crossed_runs_the_full_path(
        self,
    ) -> None:
        # A started launch, a recovery_required terminal event or a log with
        # no terminal event may follow a runtime change, so recovery proves
        # Host absence, Off and the exact guard before it archives.
        ps, off = list(PROCESS_OBSERVATION_COMMAND), list(OFF_PROOF_COMMAND)
        cases = (
            ("launch started, recovery required", [*STEP_EVENTS[:5], RECOVERY_REQUIRED_EVENT]),
            ("launch started, unterminated", STEP_EVENTS[:5]),
            ("recovery required before the launch event", [*STEP_EVENTS[:4], RECOVERY_REQUIRED_EVENT]),
            ("unterminated before launch", STEP_EVENTS[:3]),
            # collect never writes these logs: its mutation boundary precedes
            # the launch event. A log that shows a started launch is never
            # archived unproven, and never refused before the runtime proof.
            ("abort after a started launch", [*STEP_EVENTS[:5], ABORTED_EVENT]),
            (
                "repeated abort after a started launch",
                [*STEP_EVENTS[:5], ABORTED_EVENT, ABORTED_EVENT],
            ),
            (
                "archive marker after a started launch",
                [*STEP_EVENTS[:5], ABORTED_EVENT, ARCHIVED_BEFORE_MUTATION_EVENT],
            ),
        )
        for label, events in cases:
            with self.subTest(label):
                root = self._write_fresh_collection(list(events))
                intent = (root / "intent.json").read_bytes()
                recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
                with patch.object(
                    ga_runtime, "_installed_guard_baseline", return_value=guard()
                ):
                    archived = recover_ga_runtime_collection(
                        repository=self.fixture.repository,
                        expected=self.fixture.expected,
                        runtime=recovery,
                    )
                self.assertEqual(
                    [argv for argv, _timeout in recovery.calls], [ps, ps, off, ps]
                )
                self.assertEqual((recovery.environments, recovery.guards), ([], []))
                self._assert_archived_log(
                    archived, [*events, *FULL_RECOVERY_EVENTS], intent
                )

    def test_crossed_collection_recovery_still_refuses_a_persistent_guard_mismatch(
        self,
    ) -> None:
        events = [*STEP_EVENTS[:5], RECOVERY_REQUIRED_EVENT]
        self.fixture.write_collection_receipt(events=events)
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        _clock, sleeps, clock_patches = self._fake_clock()
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), patch.object(
            recovery, "capture_guard", side_effect=restarted_guard
        ) as observed, clock_patches[0], clock_patches[1], self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "^runtime recovery did not restore the collection's fixed CFW guard$",
        ) as raised:
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        # One observation a second for the whole 30-second settle.
        self.assertEqual(observed.call_count, 31)
        self.assertEqual(sleeps, [1.0] * 30)
        self.assertEqual(
            getattr(raised.exception, "__notes__", []),
            [
                "runtime recovery guard still differs from its baseline in cfw_processes, "
                "tun_sha256 after 30 s"
            ],
        )
        self.assertEqual(
            collection_events(self.fixture.repository), [*events, *FULL_RECOVERY_EVENTS[:-1]]
        )
        self.assertFalse(
            any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
        )

    def test_recovery_refuses_an_event_log_collect_never_writes(self) -> None:
        refused = (
            ("abort before a step", [ABORTED_EVENT, STEP_EVENTS[0]]),
            ("abort of one step", [STEP_EVENTS[0], ("aborted_before_mutation", "dmg-gatekeeper")]),
            ("repeated abort", [ABORTED_EVENT, ABORTED_EVENT]),
            ("abort after reordered steps", [STEP_EVENTS[0], STEP_EVENTS[2], ABORTED_EVENT]),
            ("abort and recovery required", [*STEP_EVENTS[:2], ABORTED_EVENT, RECOVERY_REQUIRED_EVENT]),
            ("abort then runtime cleanup", [ABORTED_EVENT, RUNTIME_CLEANUP_EVENT]),
            (
                "abort then two archive markers",
                [ABORTED_EVENT, ARCHIVED_BEFORE_MUTATION_EVENT, ARCHIVED_BEFORE_MUTATION_EVENT],
            ),
        )

        def gap(root: Path) -> None:
            (root / "event-001.json").unlink()

        def foreign_files(root: Path) -> None:
            # Finder's view state, and a name that must not reach a terminal.
            for name in (".DS_Store", "notes\x1b[2J.json"):
                (root / name).write_bytes(b"{}\n")
                (root / name).chmod(0o600)

        def foreign_entries(count: int) -> Any:
            def damage(root: Path) -> None:
                for index in range(count):
                    (root / f"stray-{index}").write_bytes(b"")
                    (root / f"stray-{index}").chmod(0o600)

            return damage

        eight_foreign_files = foreign_entries(8)
        many_foreign_files = foreign_entries(10)

        # The operator learns which entries to remove, escaped and bounded.
        notes = {
            foreign_files: [
                "GA runtime collection holds unexpected entries: "
                '".DS_Store", "notes\\u001b[2J.json"'
            ],
            eight_foreign_files: [
                "GA runtime collection holds unexpected entries: "
                + ", ".join(f'"stray-{index}"' for index in range(8))
            ],
            many_foreign_files: [
                "GA runtime collection holds unexpected entries: "
                + ", ".join(f'"stray-{index}"' for index in range(8))
                + " and 2 more"
            ],
        }
        foreign = "^GA runtime collection contains an unexpected transaction file$"
        malformed = (
            (
                "sequence gap",
                [*STEP_EVENTS[:3], ABORTED_EVENT],
                gap,
                "^GA runtime collection event sequence has a gap$",
            ),
            ("foreign files", [*STEP_EVENTS[:3], ABORTED_EVENT], foreign_files, foreign),
            ("eight foreign files", [*STEP_EVENTS[:3], ABORTED_EVENT], eight_foreign_files, foreign),
            ("many foreign files", [*STEP_EVENTS[:3], ABORTED_EVENT], many_foreign_files, foreign),
            # A damaged log is refused before any runtime work even when the
            # collection crossed: the note names what is not the log's own.
            (
                "foreign files after a crossing",
                [*STEP_EVENTS[:5], RECOVERY_REQUIRED_EVENT],
                foreign_files,
                foreign,
            ),
        )
        cases = [
            (
                label,
                events,
                lambda _root: None,
                "^GA runtime collection event log is not one fixed collect attempt; "
                "retain runtime-collection for review$",
            )
            for label, events in refused
        ] + list(malformed)
        for label, events, damage, message in cases:
            with self.subTest(label):
                root = self._write_fresh_collection(events)
                damage(root)
                before = {path.name: path.read_bytes() for path in root.iterdir()}
                recovery = FakeCollectorRuntime(self.fixture)
                with patch.object(
                    ga_runtime, "_installed_guard_baseline", return_value=guard()
                ), self.assertRaisesRegex(GARuntimeAcceptanceError, message) as raised:
                    recover_ga_runtime_collection(
                        repository=self.fixture.repository,
                        expected=self.fixture.expected,
                        runtime=recovery,
                    )
                self.assertEqual(
                    getattr(raised.exception, "__notes__", []), notes.get(damage, [])
                )
                self.assertEqual(recovery.calls, [])
                self.assertEqual(len(recovery.environments), 3)
                self.assertEqual(recovery.guards, [guard(), guard(), guard()])
                self.assertEqual(
                    {path.name: path.read_bytes() for path in root.iterdir()}, before
                )
                self.assertFalse(
                    any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
                )

    def _whole_system_recovery(
        self,
        rounds: list[dict[str, str]],
        *,
        baseline: dict[str, object] | None = None,
    ) -> NetworkObservingRuntime:
        """A crossed collection whose baseline was taken without Clash for Windows."""

        self._write_fresh_collection(
            [*STEP_EVENTS[:5], RECOVERY_REQUIRED_EVENT],
            baseline=whole_system_guard() if baseline is None else baseline,
        )
        recovery = NetworkObservingRuntime(self.fixture, rounds)
        shutdown = self.fixture.documents["shutdown-restore.json"]
        recovery.receipts = {
            tuple(PROCESS_OBSERVATION_COMMAND): [
                copy.deepcopy(shutdown["process_observation"]),
                copy.deepcopy(shutdown["host_process_observation"]),
                copy.deepcopy(shutdown["process_observation"]),
            ],
            tuple(OFF_PROOF_COMMAND): [copy.deepcopy(shutdown["off_proof_command"])],
        }
        # No guard capture is expected: the fake refuses one.
        recovery.guards = []
        return recovery

    @contextmanager
    def _whole_system_clock(
        self, recovery: FakeCollectorRuntime, *, seconds_per_round: float = 0.0
    ) -> Iterator[list[float]]:
        """Patch the clock; each round of network observations takes its time."""

        clock, sleeps, clock_patches = self._fake_clock()
        run = recovery.run

        def timed(argv: list[str], *, timeout: int = 900) -> dict[str, object]:
            if argv == ["/sbin/ifconfig"]:
                clock[0] += seconds_per_round
            return run(argv, timeout=timeout)

        with clock_patches[0], clock_patches[1], patch.object(
            recovery, "run", side_effect=timed
        ):
            yield sleeps

    def _recover_whole_system(self, recovery: FakeCollectorRuntime) -> Path:
        with patch.object(ga_runtime, "_installed_guard_baseline", return_value=guard()):
            return recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )

    def test_whole_system_recovery_accepts_drift_without_clash_for_mac_remnants(
        self,
    ) -> None:
        # Without Clash for Windows the baseline digests the whole system,
        # which drifts for its own reasons: every digest differs here. After
        # the Host's absence and the signed Off proof, recovery needs only
        # that no Clash for Mac network state remains; it never compares the
        # guard.
        recovery = self._whole_system_recovery([{}])
        with self._whole_system_clock(recovery) as sleeps:
            archived = self._recover_whole_system(recovery)
        self.assertEqual(sleeps, [])
        ps, off = list(PROCESS_OBSERVATION_COMMAND), list(OFF_PROOF_COMMAND)
        self.assertEqual(
            [argv for argv, _timeout in recovery.calls],
            [ps, ps, off, ps, *(list(argv) for argv in NETWORK_OBSERVATION_COMMANDS.values())],
        )
        self.assertEqual(
            {timeout for argv, timeout in recovery.calls if tuple(argv) in NETWORK_OBSERVATION_COMMANDS.values()},
            {30},
        )
        self.assertEqual(
            [(event["phase"], event["step"]) for event in self._archived_events(archived)][-7:],
            FULL_RECOVERY_EVENTS,
        )

    def test_whole_system_recovery_names_each_clash_for_mac_remnant(self) -> None:
        with_utun = NETWORK_IFCONFIG + CFM_UTUN_BLOCK
        utun = [
            "utun10 carries the Clash for Mac tunnel address 198.18.64.1",
            "utun10 carries the Clash for Mac tunnel address 2001:2:0:64::1",
        ]
        cases = (
            ("tunnel interface", {"interface": with_utun}, utun),
            (
                "IPv4 resolver",
                {"DNS": NETWORK_DNS.replace("nameserver[0] : 10.255.0.1", "nameserver[0] : 198.18.64.2")},
                ["DNS resolver at the Clash for Mac tunnel address 198.18.64.2"],
            ),
            (
                "IPv6 resolver",
                {"DNS": NETWORK_DNS.replace("nameserver[1] : 10.255.0.2", "nameserver[1] : 2001:2:0:64::2")},
                ["DNS resolver at the Clash for Mac tunnel address 2001:2:0:64::2"],
            ),
            (
                "host route to a tunnel address",
                {"IPv4 route": NETWORK_ROUTES_IPV4 + "198.18.64.2/32     link#14            UHS                   en0       \n"},
                ["route 198.18.64.2/32 via link#14 on en0 to a Clash for Mac tunnel address"],
            ),
            (
                "route through the tunnel",
                {
                    "interface": with_utun,
                    "IPv4 route": NETWORK_ROUTES_IPV4 + "198.18.64/30       link#42            UCS                utun10       \n",
                },
                [*utun, "route 198.18.64/30 through utun10"],
            ),
            (
                "scoped IPv4 default",
                {
                    "interface": with_utun,
                    "IPv4 route": NETWORK_ROUTES_IPV4 + "default            link#42            UCSIg              utun10       \n",
                },
                [*utun, "scoped default route through utun10"],
            ),
            (
                "scoped IPv6 default",
                {
                    "interface": with_utun,
                    "IPv6 route": NETWORK_ROUTES_IPV6
                    + "default                                 fe80::%utun10                           "
                    "UGcIg              utun10       \n",
                },
                [*utun, "scoped default route through utun10"],
            ),
            (
                "the product's system proxy",
                {"system proxy": LOOPBACK_PROXY},
                [
                    f"{kind} system proxy on loopback host 127.0.0.1:7890"
                    for kind in ("HTTP", "HTTPS", "SOCKS")
                ],
            ),
            (
                "SOCKS alone",
                {
                    "system proxy": scutil_proxy(
                        "HTTPEnable : 0\nHTTPSEnable : 0\nSOCKSEnable : 1\n"
                        "SOCKSPort : 7890\nSOCKSProxy : 127.0.0.1\n"
                    )
                },
                ["SOCKS system proxy on loopback host 127.0.0.1:7890"],
            ),
            (
                "named and IPv6 loopback hosts",
                {
                    "system proxy": scutil_proxy(
                        "HTTPEnable : 1\nHTTPPort : 7890\nHTTPProxy : localhost\n"
                        "HTTPSEnable : 1\nHTTPSPort : 7890\nHTTPSProxy : ::1\n"
                        "SOCKSEnable : 0\n"
                    )
                },
                [
                    "HTTP system proxy on loopback host localhost:7890",
                    "HTTPS system proxy on loopback host [::1]:7890",
                ],
            ),
            (
                "scoped system proxy",
                {
                    "system proxy": scutil_proxy(
                        PROXY_OFF_FIELDS, scoped={"en0": CFM_PROXY_FIELDS}
                    )
                },
                [
                    f"{kind} system proxy for en0 on loopback host 127.0.0.1:7890"
                    for kind in ("HTTP", "HTTPS", "SOCKS")
                ],
            ),
            (
                "global and scoped system proxy",
                {
                    "system proxy": scutil_proxy(
                        CFM_PROXY_FIELDS, scoped={"en0": CFM_PROXY_FIELDS}
                    )
                },
                [
                    f"{kind} system proxy{scope} on loopback host 127.0.0.1:7890"
                    for scope in ("", " for en0")
                    for kind in ("HTTP", "HTTPS", "SOCKS")
                ],
            ),
            (
                "supplemental system proxy",
                {
                    "system proxy": scutil_proxy(
                        PROXY_OFF_FIELDS,
                        supplemental=(
                            "SOCKSEnable : 1\nSOCKSPort : 7890\nSOCKSProxy : 127.0.0.1\n",
                        ),
                    )
                },
                ["SOCKS system proxy in supplemental entry 0 on loopback host 127.0.0.1:7890"],
            ),
            (
                "unprintable proxy port",
                {
                    "system proxy": scutil_proxy(
                        "HTTPEnable : 1\nHTTPPort : 78\x1b[2J90\nHTTPProxy : 127.0.0.1\n"
                    )
                },
                ['HTTP system proxy on loopback host 127.0.0.1:"78\\u001b[2J90"'],
            ),
            (
                "unprintable route fields",
                {
                    "IPv4 route": NETWORK_ROUTES_IPV4
                    + "198.18.64.2/32     link#1\x1b[2J4      UHS                   en0       \n"
                },
                [
                    'route 198.18.64.2/32 via "link#1\\u001b[2J4" on en0 to a Clash for Mac '
                    "tunnel address"
                ],
            ),
        )
        for label, outputs, remnants in cases:
            with self.subTest(label):
                recovery = self._whole_system_recovery([outputs])
                with self._whole_system_clock(recovery) as sleeps, self.assertRaises(
                    GARuntimeAcceptanceError
                ) as raised:
                    self._recover_whole_system(recovery)
                self.assertEqual(
                    str(raised.exception),
                    "runtime recovery found possible Clash for Mac network state after "
                    f"the Off proof: {'; '.join(remnants)}",
                )
                # The remnants persisted through the whole 30-second settle.
                self.assertEqual(sleeps, [1.0] * 30)
                self.assertEqual(
                    [argv for argv, _timeout in recovery.calls].count(["/sbin/ifconfig"]), 31
                )
                self.assertEqual(
                    collection_events(self.fixture.repository)[-1],
                    ("completed", "runtime-recovery-process-observation"),
                )
                self.assertFalse(
                    any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
                )

    def test_whole_system_recovery_keeps_an_unchanged_loopback_proxy(self) -> None:
        # The intent keeps only the proxy's digest: a proxy byte-identical to
        # the baseline is restored even when it is itself a loopback proxy.
        proxy = scutil_proxy(CFM_PROXY_FIELDS, scoped={"en0": CFM_PROXY_FIELDS})
        recovery = self._whole_system_recovery(
            [{"system proxy": proxy}], baseline=whole_system_guard(proxy=proxy)
        )
        with self._whole_system_clock(recovery) as sleeps:
            self.assertTrue(self._recover_whole_system(recovery).is_dir())
        self.assertEqual(sleeps, [])

    def test_whole_system_recovery_accepts_a_system_proxy_off_loopback(self) -> None:
        # Another proxy, global, scoped or supplemental, is drift the release
        # owner's rule accepts: Clash for Mac's system proxy listens only on a
        # loopback host.
        corporate = (
            "HTTPEnable : 1\nHTTPPort : 3128\nHTTPProxy : proxy.example.org\n"
            "HTTPSEnable : 1\nHTTPSPort : 3128\nHTTPSProxy : 10.0.0.1\n"
            "SOCKSEnable : 1\nSOCKSPort : 1080\nSOCKSProxy : 2001:db8::5\n"
        )
        proxy = scutil_proxy(corporate, scoped={"en0": corporate}, supplemental=(corporate,))
        recovery = self._whole_system_recovery([{"system proxy": proxy}])
        with self._whole_system_clock(recovery) as sleeps:
            archived = self._recover_whole_system(recovery)
        self.assertTrue(archived.is_dir())
        self.assertEqual(sleeps, [])
        self.assertEqual(
            [argv for argv, _timeout in recovery.calls].count(["/usr/sbin/scutil", "--proxy"]),
            1,
        )

    def test_whole_system_recovery_waits_for_remnants_to_clear(self) -> None:
        recovery = self._whole_system_recovery(
            [{"interface": NETWORK_IFCONFIG + CFM_UTUN_BLOCK}, {}]
        )
        with self._whole_system_clock(recovery) as sleeps:
            archived = self._recover_whole_system(recovery)
        self.assertTrue(archived.is_dir())
        self.assertEqual(sleeps, [1.0])

    def test_whole_system_remnant_settle_is_bounded_in_wall_time(self) -> None:
        # Each round runs five commands: with 14.25-second rounds the third
        # starts exactly at the 30-second bound, after a pause cut to half a
        # second, and its remnants are final.
        recovery = self._whole_system_recovery(
            [{"interface": NETWORK_IFCONFIG + CFM_UTUN_BLOCK}]
        )
        with self._whole_system_clock(
            recovery, seconds_per_round=14.25
        ) as sleeps, self.assertRaises(GARuntimeAcceptanceError) as raised:
            self._recover_whole_system(recovery)
        self.assertTrue(str(raised.exception).startswith("runtime recovery found possible"))
        self.assertEqual(
            [argv for argv, _timeout in recovery.calls].count(["/sbin/ifconfig"]), 3
        )
        self.assertEqual(sleeps, [1.0, 0.5])

    def test_whole_system_recovery_refuses_malformed_network_observations(self) -> None:
        cases = (
            ("DNS", {"DNS": ""}, "runtime recovery network observation is malformed"),
            (
                "system proxy shape",
                {"system proxy": "HTTPEnable : 1\n"},
                "runtime recovery network observation is malformed",
            ),
            (
                "route table",
                {"IPv6 route": "Routing tables\n\nInternet6:\n"},
                "runtime recovery network observation is malformed",
            ),
            (
                "interface address",
                {"interface": NETWORK_IFCONFIG + "utun10: flags=8051<UP> mtu 1500\n\tinet 198.18.64 netmask 0xfffffffc\n"},
                "runtime recovery interface observation names a malformed address",
            ),
            (
                "nameserver",
                {"DNS": NETWORK_DNS.replace("nameserver[0] : 10.255.0.1", "nameserver[0] : resolver.invalid")},
                "runtime recovery DNS observation names a malformed address",
            ),
            (
                "enabled proxy without a host",
                {"system proxy": NETWORK_PROXY.replace("HTTPEnable : 0", "HTTPEnable : 1")},
                "runtime recovery system proxy observation enables HTTP without a host",
            ),
            (
                "enabled scoped proxy without a host",
                {
                    "system proxy": scutil_proxy(
                        PROXY_OFF_FIELDS, scoped={"en0": "SOCKSEnable : 1\nSOCKSPort : 7890\n"}
                    )
                },
                "runtime recovery system proxy observation enables SOCKS for en0 without a host",
            ),
            (
                "proxy switch neither 0 nor 1",
                {"system proxy": NETWORK_PROXY.replace("SOCKSEnable : 0", "SOCKSEnable : 2")},
                "runtime recovery network observation is malformed",
            ),
            (
                "repeated proxy field",
                {"system proxy": scutil_proxy("HTTPEnable : 0\nHTTPEnable : 1\n")},
                "runtime recovery network observation is malformed",
            ),
            (
                "scope inside a scope",
                {
                    "system proxy": scutil_proxy(
                        PROXY_OFF_FIELDS, scoped={"en0": PROXY_OFF_FIELDS}
                    ).replace(
                        "    en0 : <dictionary> {\n",
                        "    en0 : <dictionary> {\n"
                        "      __SCOPED__ : <dictionary> {\n"
                        "      }\n",
                    )
                },
                "runtime recovery network observation is malformed",
            ),
            (
                "scopes that are not dictionaries",
                {
                    "system proxy": scutil_proxy(
                        PROXY_OFF_FIELDS, scoped={"en0": PROXY_OFF_FIELDS}
                    ).replace("  __SCOPED__ : <dictionary> {\n", "  __SCOPED__ : <array> {\n")
                },
                "runtime recovery network observation is malformed",
            ),
            (
                "unclosed proxy dictionary",
                {
                    "system proxy": scutil_proxy(
                        PROXY_OFF_FIELDS, scoped={"en0": PROXY_OFF_FIELDS}
                    ).replace("    }\n  }\n}\n", "  }\n}\n")
                },
                "runtime recovery network observation is malformed",
            ),
            (
                "unprintable scope name",
                {
                    "system proxy": scutil_proxy(
                        PROXY_OFF_FIELDS, scoped={"en0\x1b[2J": PROXY_OFF_FIELDS}
                    )
                },
                "runtime recovery network observation is malformed",
            ),
            # Only the global proxy dictionary holds the supplemental list.
            (
                "supplemental list inside a scoped entry",
                {
                    "system proxy": scutil_proxy(
                        PROXY_OFF_FIELDS, scoped={"en0": PROXY_OFF_FIELDS}
                    ).replace(
                        "    en0 : <dictionary> {\n",
                        "    en0 : <dictionary> {\n"
                        "      __SUPPLEMENTAL__ : <array> {\n"
                        "        0 : *.example\n"
                        "      }\n",
                    )
                },
                "runtime recovery network observation is malformed",
            ),
            # An array holds only scalars, never another container.
            (
                "array in an exception list",
                {
                    "system proxy": scutil_proxy(PROXY_OFF_FIELDS).replace(
                        "    1 : 169.254/16\n",
                        "    1 : 169.254/16\n    2 : <array> {\n      0 : 127.0.0.1\n    }\n",
                    )
                },
                "runtime recovery network observation is malformed",
            ),
            (
                "address line without an address",
                {"interface": NETWORK_IFCONFIG + "utun10: flags=8051<UP> mtu 1500\n\tinet\n"},
                "runtime recovery network observation is malformed",
            ),
            (
                "partial nameserver line",
                {
                    "DNS": NETWORK_DNS.replace(
                        "nameserver[0] : 10.255.0.1", "nameserver[0] : 10.255.0.1 (scoped)"
                    )
                },
                "runtime recovery network observation is malformed",
            ),
        ) + tuple(
            # A loopback proxy where scutil nests no proxy dictionary is not read.
            (shape, {"system proxy": proxy}, "runtime recovery network observation is malformed")
            for shape, proxy in hidden_loopback_proxies().items()
        )
        for label, outputs, message in cases:
            with self.subTest(label):
                recovery = self._whole_system_recovery([outputs])
                with self._whole_system_clock(recovery) as sleeps, self.assertRaises(
                    GARuntimeAcceptanceError
                ) as raised:
                    self._recover_whole_system(recovery)
                self.assertEqual(str(raised.exception), message)
                # A malformed observation is never retried as a settle.
                self.assertEqual(sleeps, [])
                self.assertEqual(
                    [argv for argv, _timeout in recovery.calls].count(["/sbin/ifconfig"]), 1
                )
                self.assertFalse(
                    any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
                )

    def test_whole_system_recovery_refuses_a_failed_network_observation(self) -> None:
        # A failed observation shows no network state at all: it ends recovery
        # at once, never read as a round without remnants or settled again.
        recovery = self._whole_system_recovery([{}])
        run = recovery.run

        def failing_dns(argv: list[str], *, timeout: int = 900) -> dict[str, object]:
            receipt = run(argv, timeout=timeout)
            if argv == ["/usr/sbin/scutil", "--dns"]:
                receipt.update(exit_code=1, stdout="", stderr="scutil: fixture failure\n")
            return receipt

        with patch.object(recovery, "run", side_effect=failing_dns), self._whole_system_clock(
            recovery
        ) as sleeps, self.assertRaises(GARuntimeAcceptanceError) as raised:
            self._recover_whole_system(recovery)
        self.assertEqual(
            str(raised.exception),
            "runtime recovery DNS observation command identity, exit, or duration is invalid",
        )
        self.assertEqual(
            raised.exception.__notes__[0],
            "runtime recovery DNS observation failed its exit check: exit status 1, "
            "expected 0; duration 7.000 s, bound 30 s",
        )
        self.assertEqual(sleeps, [])
        # The round ends at the failed observation, before the system proxy.
        self.assertEqual(
            [tuple(argv) for argv, _timeout in recovery.calls][-4:],
            [
                NETWORK_OBSERVATION_COMMANDS[name]
                for name in ("interface", "IPv4 route", "IPv6 route", "DNS")
            ],
        )
        self.assertEqual(
            collection_events(self.fixture.repository)[-1],
            ("completed", "runtime-recovery-process-observation"),
        )
        self.assertFalse(
            any(self.fixture.acceptance.parent.glob("runtime-collection-aborted-*"))
        )

    def test_recovery_with_clash_for_windows_keeps_the_exact_guard(self) -> None:
        # With Clash for Windows running at the baseline the guard is its
        # own proxy, DNS, routes and utun, so only exact restoration counts;
        # no raw network observation replaces it.
        self._write_fresh_collection([*STEP_EVENTS[:5], RECOVERY_REQUIRED_EVENT])
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        recovery.guards = [restarted_guard() for _ in range(31)]
        _clock, _sleeps, clock_patches = self._fake_clock()
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), clock_patches[0], clock_patches[1], self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "^runtime recovery did not restore the collection's fixed CFW guard$",
        ):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        ps, off = list(PROCESS_OBSERVATION_COMMAND), list(OFF_PROOF_COMMAND)
        self.assertEqual([argv for argv, _timeout in recovery.calls], [ps, ps, off, ps])
        self.assertEqual(recovery.guards, [])


class PublicationEscapedTailTests(unittest.TestCase):
    """publication.common.escaped_tail, shared by release-tool diagnostics."""

    def test_text_and_newlines_pass_through(self) -> None:
        self.assertEqual(common.escaped_tail(b"line one\nline two\n"), "line one\nline two\n")
        self.assertEqual(common.escaped_tail(b""), "")

    def test_every_other_control_character_is_escaped(self) -> None:
        data = (
            b"\x00\x07\t\r\x1b[2J\x1f \x7f"
            + "\u0080\u0085\u009b\u009f\u00a0".encode("utf-8")
            + "\u00e9 \\x1b\n".encode("utf-8")
        )
        self.assertEqual(
            common.escaped_tail(data),
            "\\x00\\x07\\x09\\x0d\\x1b[2J\\x1f \\x7f\\x80\\x85\\x9b\\x9f\u00a0"
            "\u00e9 \\x1b\n",
        )

    def test_format_separator_private_and_unassigned_characters_are_escaped(self) -> None:
        # Bidirectional overrides and isolates and other invisible format
        # characters, the line and paragraph separators, and private-use and
        # unassigned code points could reorder or hide what an operator reads;
        # they are the characters the release app verifier's transcript rules
        # refuse. Printable text in any script passes.
        data = (
            "a\u202eb\u2066c\u200bd\ufeffe\u2028f\u2029g\U000e0041h\ue000i\u0378j"
            " \u4e2d\u6587 \u00e9\n"
        ).encode("utf-8")
        self.assertEqual(
            common.escaped_tail(data),
            "a\\u202eb\\u2066c\\u200bd\\ufeffe\\u2028f\\u2029g\\U000e0041h\\ue000i\\u0378j"
            " \u4e2d\u6587 \u00e9\n",
        )

    def test_invalid_utf8_is_replaced(self) -> None:
        self.assertEqual(common.escaped_tail(b"\xff ok \xc3"), "\ufffd ok \ufffd")

    def test_only_the_last_bytes_are_kept(self) -> None:
        self.assertEqual(common.escaped_tail(b"a" * 5000 + b"END", 4096), "a" * 4093 + "END")
        # A cut inside a multibyte character replaces only its fragment.
        self.assertEqual(
            common.escaped_tail("\u00e9\u00e9\u00e9".encode("utf-8"), 5),
            "\ufffd\u00e9\u00e9",
        )

    def test_escaped_text_keeps_its_end_without_splitting_an_escape(self) -> None:
        self.assertEqual(common.escaped_tail(b"\x1b" * 4096, 4096), "\\x1b" * 1024)
        self.assertEqual(common.escaped_tail(b"\x1b" * 10 + b"ab", 7), "\\x1bab")
        self.assertEqual(common.escaped_tail("‮".encode("utf-8") * 3 + b"ab", 9), "\\u202eab")
        self.assertEqual(
            common.escaped_tail("\U000e0041".encode("utf-8") * 2 + b"ab", 14), "\\U000e0041ab"
        )

    def test_the_bound_must_be_a_positive_integer(self) -> None:
        for maximum in (0, -1, True, 4096.0):
            with self.subTest(maximum=maximum), self.assertRaisesRegex(
                ValueError, "^escaped tail bound must be a positive integer$"
            ):
                common.escaped_tail(b"x", maximum)


class GARuntimeCommandDiagnosisTests(unittest.TestCase):
    def test_rejected_command_diagnosis_survives_any_receipt_values(self) -> None:
        # A receipt from persisted evidence may hold any JSON value before its
        # outputs are validated; the diagnosis never raises over one.
        timing = "duration 7.000 s, bound 900 s"
        cases = (
            (
                "non-integer exit and non-text outputs",
                {"exit_code": "0", "stdout": None, "stderr": ["x"]},
                [
                    f"fixture failed its exit check: exit status not an integer (str), "
                    f"expected 0; {timing}",
                    "fixture stdout is not text (NoneType)",
                    "fixture stderr is not text (list)",
                ],
            ),
            (
                "killed by a signal",
                {"exit_code": -9},
                [
                    f"fixture failed its exit check: exit status -9 (SIGKILL), expected 0; "
                    f"{timing}",
                    "fixture stdout is empty",
                    "fixture stderr is empty",
                ],
            ),
            (
                "unknown signal",
                {"exit_code": -200},
                [
                    "fixture failed its exit check: exit status -200 (unknown signal), "
                    f"expected 0; {timing}",
                    "fixture stdout is empty",
                    "fixture stderr is empty",
                ],
            ),
            (
                "argv and duration",
                {"argv": ["/bin/false"], "finished_at": "2026-07-27T11:59:58Z"},
                [
                    "fixture failed its argv and duration checks: exit status 0, "
                    "expected 0; duration -1.000 s, bound 900 s",
                    "fixture stdout is empty",
                    "fixture stderr is empty",
                ],
            ),
            (
                "document",
                {"document": "cfm-ga-command-observation-v1", "stdout": "ok\n"},
                [
                    f"fixture failed its document check: exit status 0, expected 0; {timing}",
                    "fixture stdout (3 bytes) ends with:\nok\n",
                    "fixture stderr is empty",
                ],
            ),
        )
        for label, values, notes in cases:
            with self.subTest(label):
                receipt = command(["/bin/true"])
                receipt.update(values)
                with self.assertRaises(GARuntimeAcceptanceError) as raised:
                    ga_runtime._command(
                        receipt, expected_argv=["/bin/true"], expected_exit=0, label="fixture"
                    )
                self.assertEqual(
                    str(raised.exception),
                    "fixture command identity, exit, or duration is invalid",
                )
                self.assertEqual(getattr(raised.exception, "__notes__", []), notes)

    def test_output_with_credential_material_is_withheld_whole(self) -> None:
        # The patterns only detect a credential: they match a PEM block's
        # BEGIN line, never its body or END line. A stream in which any of
        # them matches anywhere is withheld, with only its size and why.
        body = "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB"
        pem = (
            f"loading signing key\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n"
            "-----END RSA PRIVATE KEY-----\ndone\n"
        )
        aws = "using AKIAIOSFODNN7EXAMPLE for the upload\n"
        receipt = command(["/bin/true"], exit_code=1, stdout=aws, stderr=pem)
        with self.assertRaises(GARuntimeAcceptanceError) as raised:
            ga_runtime._command(
                receipt, expected_argv=["/bin/true"], expected_exit=0, label="fixture"
            )
        self.assertEqual(
            raised.exception.__notes__[1:],
            [
                f"fixture stdout ({len(aws)} bytes) is withheld: it holds "
                "credential-like material",
                f"fixture stderr ({len(pem)} bytes) is withheld: it holds "
                "credential-like material",
            ],
        )
        rendered = common.failure_diagnostic("error: fixture headline", raised.exception)
        for shown in (body, "END RSA PRIVATE KEY", "AKIAIOSFODNN7EXAMPLE", "loading", "done"):
            self.assertNotIn(shown, rendered)


class GARuntimeFailureDiagnosticTests(unittest.TestCase):
    @staticmethod
    def _lines(error: BaseException) -> list[str]:
        return common.failure_diagnostic("error: fixture headline", error).splitlines()

    def test_every_line_of_every_note_is_indented_below_its_failure(self) -> None:
        # A note can hold an escaped output tail of many lines, which may read
        # like a cause or another diagnostic; every line boundary of a note,
        # a carriage return included, starts an indented line, so only the
        # headline and the cause lines start at column 0.
        cause = GARuntimeAcceptanceError("fixture cause")
        cause.add_note("fixture cause note\ncaused by ValueError: forged\nerror: forged\n")
        top = GARuntimeAcceptanceError("fixture top failure")
        top.add_note("fixture tail ends with:\ncaused by OSError: forged\n\nlast line")
        top.add_note("fixture overwrite\rerror: forged")
        top.__cause__ = cause
        self.assertEqual(
            self._lines(top),
            [
                "error: fixture headline",
                "  fixture tail ends with:",
                "  caused by OSError: forged",
                "  ",
                "  last line",
                "  fixture overwrite",
                "  error: forged",
                "caused by GARuntimeAcceptanceError: fixture cause",
                "  fixture cause note",
                "  caused by ValueError: forged",
                "  error: forged",
            ],
        )

    def test_explicit_causes_render_in_order_with_their_notes(self) -> None:
        root = ValueError("artifact entry changed while revalidating: .")
        middle = GARuntimeAcceptanceError(
            f"installed {TO_BUILD} application tree cannot be identified"
        )
        middle.add_note("fixture middle note")
        middle.__cause__ = root
        top = GARuntimeAcceptanceError("fixture top failure")
        top.add_note("fixture top note")
        top.__cause__ = middle
        interrupted = GARuntimeAcceptanceError("fixture interrupted seal")
        interrupted.__cause__ = KeyboardInterrupt()

        self.assertEqual(
            self._lines(top),
            [
                "error: fixture headline",
                "  fixture top note",
                "caused by GARuntimeAcceptanceError: "
                f"installed {TO_BUILD} application tree cannot be identified",
                "  fixture middle note",
                "caused by ValueError: artifact entry changed while revalidating: .",
            ],
        )
        self.assertEqual(
            self._lines(interrupted),
            ["error: fixture headline", "caused by KeyboardInterrupt"],
        )

    def test_implicit_context_renders_unless_suppressed(self) -> None:
        def raise_while_handling(*, suppress: bool) -> GARuntimeAcceptanceError:
            try:
                try:
                    raise OSError("fixture lower failure")
                except OSError:
                    if suppress:
                        raise GARuntimeAcceptanceError("fixture upper failure") from None
                    raise GARuntimeAcceptanceError("fixture upper failure")
            except GARuntimeAcceptanceError as error:
                return error
            raise AssertionError("fixture did not raise")

        self.assertEqual(
            self._lines(raise_while_handling(suppress=False)),
            ["error: fixture headline", "while handling OSError: fixture lower failure"],
        )
        self.assertEqual(
            self._lines(raise_while_handling(suppress=True)),
            ["error: fixture headline"],
        )

    def test_cause_cycle_terminates(self) -> None:
        first = ValueError("fixture first")
        second = OSError("fixture second")
        first.__cause__ = second
        second.__cause__ = first
        self.assertEqual(
            self._lines(first),
            [
                "error: fixture headline",
                "caused by OSError: fixture second",
                "caused by ValueError already shown above (cause cycle)",
            ],
        )

    def test_chain_is_bounded_to_eight_levels(self) -> None:
        def chain(levels: int) -> ValueError:
            top = ValueError("level 0")
            current = top
            for level in range(1, levels + 1):
                cause = ValueError(f"level {level}")
                current.__cause__ = cause
                current = cause
            return top

        causes = [f"caused by ValueError: level {level}" for level in range(1, 9)]
        self.assertEqual(self._lines(chain(8)), ["error: fixture headline", *causes])
        self.assertEqual(
            self._lines(chain(20)),
            [
                "error: fixture headline",
                *causes,
                "cause chain truncated after 8 levels",
            ],
        )

    def test_nested_rendered_exit_is_shown_once_and_ends_the_chain(self) -> None:
        primary = GARuntimeAcceptanceError("fixture runtime primary")
        primary.__cause__ = ValueError("fixture original cause")
        rendered = SystemExit(
            common.failure_diagnostic("error: GA runtime acceptance: fixture runtime primary", primary)
        )
        rendered.__cause__ = primary
        unknown = DurabilityOutcomeUnknown("fixture outcome unknown")
        unknown.__cause__ = rendered
        self.assertEqual(
            self._lines(unknown),
            [
                "error: fixture headline",
                "caused by SystemExit: error: GA runtime acceptance: fixture runtime primary",
                "caused by ValueError: fixture original cause",
            ],
        )
        unknown.add_note(f"primary runtime failure: {rendered}")
        diagnostic = common.failure_diagnostic("error: fixture headline", unknown)
        self.assertEqual(diagnostic.count("fixture original cause"), 1)
        self.assertNotIn("caused by SystemExit", diagnostic)

    def test_main_prints_the_cause_chain_of_a_seal_retry(self) -> None:
        transient = GARuntimeAcceptanceError(
            f"installed {TO_BUILD} application tree cannot be identified"
        )
        transient.__cause__ = ValueError("artifact entry changed while revalidating: .")
        retry = ga_runtime.GASealRetryRequired(
            f"sealing did not complete; run {SEAL_RETRY_COMMAND}"
        )
        retry.__cause__ = transient
        with patch.object(
            ga_runtime, "_arguments", return_value=SimpleNamespace(command="collect")
        ), patch.object(
            ga_runtime, "_repository", return_value=REPOSITORY
        ), patch.object(
            ga_runtime, "collect_ga_runtime_acceptance", side_effect=retry
        ), self.assertRaises(SystemExit) as rejected:
            ga_runtime.main(lambda _repository: {}, prepackage_stage_verifier)
        self.assertIs(rejected.exception.__cause__, retry)
        self.assertEqual(
            str(rejected.exception).splitlines(),
            [
                "error: GA runtime acceptance: sealing did not complete; run "
                f"{SEAL_RETRY_COMMAND}",
                "caused by GARuntimeAcceptanceError: "
                f"installed {TO_BUILD} application tree cannot be identified",
                "caused by ValueError: artifact entry changed while revalidating: .",
            ],
        )

    def test_main_dispatches_resume_seal_without_runtime_commands(self) -> None:
        expected = {"fixture": "runtime expectation"}
        with patch.object(
            ga_runtime, "_arguments", return_value=SimpleNamespace(command="resume-seal")
        ), patch.object(
            ga_runtime, "_repository", return_value=REPOSITORY
        ), patch.object(
            ga_runtime,
            "resume_ga_runtime_seal",
            return_value={"adapter": {"sha256": "1" * 64}},
        ) as resume, patch.object(
            ga_runtime, "collect_ga_runtime_acceptance"
        ) as collect, patch.object(
            ga_runtime, "recover_ga_runtime_collection"
        ) as recover:
            message = ga_runtime.main(lambda _repository: expected, prepackage_stage_verifier)
        resume.assert_called_once_with(
            repository=REPOSITORY,
            expected=expected,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        collect.assert_not_called()
        recover.assert_not_called()
        self.assertEqual(
            message,
            f"GA runtime collection sealed after seal retry: {'1' * 64} "
            f"({len(CHECKS)} raw-derived checks)",
        )


if __name__ == "__main__":
    unittest.main()
