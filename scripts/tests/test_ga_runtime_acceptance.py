from __future__ import annotations

import base64
import calendar
from contextlib import contextmanager
import copy
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
from types import SimpleNamespace
from typing import Any, Iterator
import unittest
from unittest.mock import MagicMock, patch

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
from scripts.harness.packet_capture import PacketCaptureError
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
from scripts.publication import common
from scripts.publication.common import PublicationError, canonical_json, sha256_bytes
from scripts.publication.durable_file import DurabilityOutcomeUnknown
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
STEP_EVENTS = [
    (phase, step)
    for step in COLLECTION_SUCCESS_STEPS
    for phase in ("started", "completed")
]
RAW_PUBLISHED_EVENT = ("raw_published", "collection")
SEAL_RETRY_COMMAND = "scripts/run_ga_runtime_acceptance.sh resume-seal"
RECOVERY_COMMAND = "scripts/run_ga_runtime_acceptance.sh recover"
# Only the product's own quit controls run its graceful shutdown, so the
# collector asks the operator for one and sends the Host no quit request. The
# app's own Settings Force Quit is graceful; the macOS Force Quit window is not.
OPERATOR_QUIT_INSTRUCTION = (
    "GA runtime collection is waiting for you to quit the installed 50028 Clash "
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
# The retired shutdown request. Its quit AppleEvent bypasses the product's
# graceful shutdown and leaves the Packet Tunnel connected.
LEGACY_APPLE_EVENT_QUIT = (
    "/usr/bin/osascript",
    "-e",
    'tell application id "com.bill.clashformac" to quit',
)

# The product DNS leg on the Packet Tunnel utun: the system resolver at the
# tunnel client queries the tunnel DNS peer, and libbox relays the evidence
# resolver's authoritative answer with the client's RD bit echoed.
TUNNEL_CLIENT = "198.18.64.1"
TUNNEL_DNS_PEER = "198.18.64.2"
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
UtunPacket = tuple[float, str, int, str, int, bytes]


def _dns_name_bytes(name: str) -> bytes:
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    return labels + b"\0"


def _tunnel_dns_query(identifier: int, name: str, *, flags: int = 0x0100) -> bytes:
    return (
        struct.pack("!HHHHHH", identifier, flags, 1, 0, 0, 0)
        + _dns_name_bytes(name)
        + struct.pack("!HH", 1, 1)
    )


def _tunnel_dns_response(
    query: bytes,
    *,
    flags: int | None = None,
    answer: str = "192.0.2.1",
    ttl: int = 0,
) -> bytes:
    """Answer one A query as libbox re-packs it: RD echoed, owner uncompressed."""

    identifier, query_flags = struct.unpack_from("!HH", query, 0)
    question = query[12:]
    rdata = ipaddress.ip_address(answer).packed
    header_flags = (0x8400 | (query_flags & 0x0100)) if flags is None else flags
    return (
        struct.pack("!HHHHHH", identifier, header_flags, 1, 1, 0, 0)
        + question
        + question[:-4]
        + struct.pack("!HHIH", 1, 1, ttl, len(rdata))
        + rdata
    )


def _tunnel_dns_packets(
    tokens: dict[str, str],
    *,
    client: str = TUNNEL_CLIENT,
    resolver: str = TUNNEL_DNS_PEER,
    target_query_flags: int = 0x0100,
    target_response: dict[str, Any] | None = None,
) -> list[UtunPacket]:
    packets: list[UtunPacket] = []
    for stage in DNS_STAGES:
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
        packets.append((query_at, client, port, resolver, 53, query))
        packets.append((response_at, resolver, 53, client, port, response))
    return packets


def _utun_udp_pcap(packets: list[UtunPacket]) -> bytes:
    """Write IPv4/UDP frames as tcpdump does on a utun: DLT_NULL, AF_INET."""

    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0))
    ordered = sorted(packets, key=lambda packet: packet[0])
    for index, packet in enumerate(ordered):
        seconds, source, source_port, destination, destination_port, payload = packet
        udp = struct.pack(
            "!HHHH", source_port, destination_port, 8 + len(payload), 0
        ) + payload
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
            ipaddress.ip_address(source).packed,
            ipaddress.ip_address(destination).packed,
        ) + udp
        frame = (2).to_bytes(4, "little") + ip
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


def _utun_dns_flags(capture: bytes) -> list[int]:
    """Return each record's DNS header flags (after AF, IPv4 and UDP headers)."""

    flags: list[int] = []
    offset = 24
    while offset < len(capture):
        _seconds, _micros, captured, _original = struct.unpack_from("<IIII", capture, offset)
        offset += 16
        flags.append(struct.unpack_from("!H", capture, offset + 4 + 20 + 8 + 2)[0])
        offset += captured
    return flags


def _expected_tunnel_dns_filter(tokens: dict[str, str]) -> tuple[str]:
    """Independent oracle for the token-bound tunnel DNS capture filter."""

    def clause(token: str) -> str:
        prefix, digest = token.split("-")
        return (
            f"(udp[20] = {len(token)} and udp[21:4] = 0x{prefix.encode('ascii').hex()}"
            f" and udp[26:4] = 0x{digest[:4].encode('ascii').hex()}"
            f" and udp[30:4] = 0x{digest[4:8].encode('ascii').hex()})"
        )

    names = " or ".join(clause(tokens[stage]) for stage in DNS_STAGES)
    return (
        f"udp and ((src host {TUNNEL_CLIENT} and dst host {TUNNEL_DNS_PEER} "
        f"and dst port 53) or (src host {TUNNEL_DNS_PEER} and src port 53 "
        f"and dst host {TUNNEL_CLIENT})) and ({names})",
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
    parent_bundle_version: str = "50028",
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
        "(0.5.0/50028)\tCFWPacketTunnel\t[activated enabled]\n"
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
    # The GA Mac lists 50008 and 40073 retained and 50025 activated. Enabling
    # Tunnel on 50028 replaces 50025, which macOS then retains until reboot.
    return (
        packet_tunnel_row("0.5.0/50008", SYSTEM_EXTENSION_RETAINED),
        packet_tunnel_row("0.4.0/40073", SYSTEM_EXTENSION_RETAINED),
        packet_tunnel_row("0.5.0/50025", SYSTEM_EXTENSION_RETAINED),
        packet_tunnel_row("0.5.0/50028", SYSTEM_EXTENSION_ACTIVATED),
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
            interface_name, link_type = "utun5", 0
            remote_address, observation_ms = TUNNEL_DNS_PEER, DNS_OBSERVATION_MS
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
            interface_name, link_type = "en0", 1
            remote_address, observation_ms = policy["remote_address"], 5000
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
                "dns_result": None,
                "document": "cfw-packet-send-stage-result-v2",
                "local_address": "198.18.64.1",
                "local_port": 41000,
                "remote_address": policy["remote_address"],
                "remote_port": policy["remote_port"],
                "schema_version": 2,
                "stage": stage,
                "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
                "transport": policy["protocol"],
            }
            if policy["protocol"] == "dns":
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
                os.sys.executable,
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
                ga_runtime._capture_command_argv(
                    interface_name, policy["expected_records"], capture_filter
                ),
                stderr=f"{policy['expected_records']} packets captured\n",
            ),
            endpoint={
                "family": "ipv4",
                "interface_name": interface_name,
                "link_type": link_type,
                "local_address": "198.18.64.1",
                "remote_address": remote_address,
                "remote_port": policy["remote_port"],
            },
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
                            "target/candidates/0.5.0/ga/50028/packages/dmg/v0.5.0/"
                            "Clash.for.Mac_0.5.0_arm64.dmg"
                        ),
                    ],
                    stderr="accepted\nsource=Notarized Developer ID\n",
                ),
                "dmg_set_verify": command(
                    ga_runtime._dmg_verifier_command(self.repository),
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

    def write_collection_receipt(self) -> None:
        root = self.repository.joinpath(*COLLECTION_RELATIVE.parts)
        root.mkdir(mode=0o700)
        intent = {
            "cfw_guard_baseline": guard(),
            "collection": {
                "challenge": CHALLENGE,
                "ga_environment_sha256": GA_ENVIRONMENT_SHA256,
                "session_id": SESSION_ID,
            },
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
        for index, (phase, step) in enumerate([*STEP_EVENTS, RAW_PUBLISHED_EVENT]):
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
            argv = ga_runtime._dmg_verifier_command(self.artifact)
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
        with self.assertRaises(GARuntimeAcceptanceError):
            ga_runtime._command(
                receipt,
                expected_argv=receipt["argv"],
                expected_exit=0,
                label="DMG contained-app byte-proof observation",
            )


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
        self.assertEqual((PRODUCT_VERSION, FROM_BUILD, TO_BUILD), ("0.5.0", "50025", "50028"))
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
                "cfm-ga-runtime-collection-intent-v3",
                3,
                "cfm-ga-runtime-collection-event-v2",
            ),
        )
        self.assertEqual(len(CHECKS), 12)
        self.assertEqual(len(RAW_FILE_NAMES), 15)
        self.assertEqual(
            ACCEPTANCE_RELATIVE,
            Path(
                "target/candidates/0.5.0/ga/50028/stage-inputs/ga-acceptance/"
                "runtime-acceptance.json"
            ),
        )
        self.assertEqual(
            RAW_ROOT_RELATIVE,
            Path(
                "target/candidates/0.5.0/ga/50028/stage-inputs/ga-acceptance/"
                "runtime-evidence"
            ),
        )
        self.assertEqual(
            ENVIRONMENT_RELATIVE,
            Path(
                "target/candidates/0.5.0/ga/50028/stage-inputs/ga-acceptance/"
                "migration-journals/service-transaction/environment.json"
            ),
        )
        self.assertEqual(
            INSTALL_JOURNAL_RELATIVE,
            Path(
                "target/candidates/0.5.0/ga/50028/stage-inputs/ga-acceptance/"
                "migration-journals/dormant-install.json"
            ),
        )

    def test_historical_migration_bindings_cannot_seal_the_active_candidate(self) -> None:
        for from_build, to_build in (
            ("40041", "40043"),
            ("40041", "50028"),
            ("40043", "40043"),
            ("40043", "40044"),
            ("40043", "50028"),
            ("40044", "40044"),
            ("40044", "40045"),
            ("40044", "50028"),
            ("40045", "40045"),
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
            "installed 50028 launch command command identity, exit, or duration is invalid",
        ):
            self.fixture.seal()

    def test_adapter_rename_reply_loss_is_outcome_unknown_and_recoverable(self) -> None:
        from scripts.publication.durable_file import promote_private_pending

        def promote_then_lose_reply(pending: Path, destination: Path) -> None:
            promote_private_pending(pending, destination)
            raise DurabilityOutcomeUnknown("simulated adapter rename reply loss")

        with patch(
            "scripts.ga_runtime_acceptance.promote_private_pending",
            side_effect=promote_then_lose_reply,
        ), self.assertRaises(DurabilityOutcomeUnknown):
            self.fixture.seal()
        self.assertTrue(self.fixture.acceptance.is_file())
        self.assertEqual(self.fixture.seal(), self.fixture.validate())

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

    def test_truncated_raw_published_marker_needs_the_documented_quarantine(
        self,
    ) -> None:
        # RELEASE.md step 7 residual window: an event is created under its
        # final name before its bytes are written, so an interrupted marker
        # write leaves a truncated event-038.json that no command repairs.
        marker = self.fixture.collection_root / "event-038.json"
        original = marker.read_bytes()
        for size in (0, len(original) // 2):
            with self.subTest(size=size):
                marker.unlink()
                marker.write_bytes(original[:size])
                marker.chmod(0o600)
                with self.assertRaisesRegex(
                    GARuntimeAcceptanceError,
                    "GA runtime event-038.json is not strict UTF-8 JSON",
                ):
                    self.fixture.resume_seal()
                recovery = FakeCollectorRuntime(self.fixture)
                with patch.object(
                    ga_runtime, "_installed_guard_baseline", return_value=guard()
                ), self.assertRaisesRegex(
                    GARuntimeAcceptanceError, r"would orphan it.*resume-seal"
                ):
                    recover_ga_runtime_collection(
                        repository=self.fixture.repository,
                        expected=self.fixture.expected,
                        runtime=recovery,
                    )
                self.assertEqual(recovery.calls, [])
                self.assertEqual(marker.read_bytes(), original[:size])
                self.assertFalse(self.fixture.acceptance.exists())
        # The user-approved quarantine keeps the truncated marker outside the
        # collection; resume-seal then revalidates the tree and rewrites it.
        quarantine = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, quarantine)
        marker.rename(quarantine / marker.name)
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        self.assertEqual(marker.read_bytes(), original)

    def test_truncated_pending_adapter_needs_the_documented_quarantine(self) -> None:
        # RELEASE.md step 7 second residual window: seal creates the pending
        # adapter under its final name before its bytes are written, so an
        # interrupted write leaves a truncated pending adapter.
        self.fixture.seal()
        sealed = self.fixture.acceptance.read_bytes()
        self.fixture.acceptance.unlink()
        pending = self.fixture.acceptance.parent / ".runtime-acceptance.json.pending"
        for size in (0, len(sealed) // 2):
            with self.subTest(size=size):
                pending.write_bytes(sealed[:size])
                pending.chmod(0o600)
                with self.assertRaisesRegex(
                    GARuntimeAcceptanceError,
                    "pending GA runtime adapter binds different evidence",
                ):
                    self.fixture.resume_seal()
                recovery = FakeCollectorRuntime(self.fixture)
                with patch.object(
                    ga_runtime, "_installed_guard_baseline", return_value=guard()
                ), self.assertRaisesRegex(
                    GARuntimeAcceptanceError, r"would orphan it.*resume-seal"
                ):
                    recover_ga_runtime_collection(
                        repository=self.fixture.repository,
                        expected=self.fixture.expected,
                        runtime=recovery,
                    )
                collection = FakeCollectorRuntime(self.fixture)
                with self.assertRaisesRegex(
                    GARuntimeAcceptanceError,
                    r"already exists \(runtime-evidence, \.runtime-acceptance\.json\.pending\)",
                ):
                    collect_ga_runtime_acceptance(
                        repository=self.fixture.repository,
                        expected=self.fixture.expected,
                        prepackage_stage_verifier=prepackage_stage_verifier,
                        runtime=collection,
                    )
                self.assertEqual((recovery.calls, collection.calls), ([], []))
                self.assertEqual(pending.read_bytes(), sealed[:size])
                self.assertFalse(self.fixture.acceptance.exists())
        # The user-approved quarantine moves the truncated pending adapter out
        # of stage-inputs; resume-seal then revalidates and rewrites it.
        quarantine = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, quarantine)
        pending.rename(quarantine / pending.name)
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        self.assertEqual(self.fixture.acceptance.read_bytes(), sealed)
        self.assertFalse(pending.exists())

    def test_resume_seal_never_marks_invalid_raw_evidence_published(self) -> None:
        marker = self.fixture.collection_root / "event-038.json"
        marker.unlink()
        self.fixture.documents["launch.json"]["launch_command"]["exit_code"] = 1
        self.fixture.rewrite_json("launch.json")
        self.fixture.rebuild_scan()
        self.fixture.rewrite_json("credential-leak-scan.json")
        with self.assertRaisesRegex(GARuntimeAcceptanceError, "launch command"):
            self.fixture.resume_seal()
        self.assertFalse(marker.exists())
        self.assertFalse(self.fixture.acceptance.exists())
        self.assertFalse(
            (self.fixture.acceptance.parent / ".runtime-acceptance.json.pending").exists()
        )

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
        for name in ("runtime-acceptance.json", ".runtime-acceptance.json.pending"):
            with self.subTest(adapter=name):
                fixture = RuntimeFixture()
                self.addCleanup(fixture.cleanup)
                marker = fixture.collection_root / "event-038.json"
                marker.unlink()
                adapter = fixture.acceptance.parent / name
                adapter.write_bytes(b"{}\n")
                adapter.chmod(0o600)
                with self.assertRaisesRegex(
                    GARuntimeAcceptanceError, "before its raw_published marker"
                ):
                    fixture.resume_seal()
                self.assertFalse(marker.exists())
                self.assertEqual(adapter.read_bytes(), b"{}\n")

    def test_resume_seal_promotes_only_an_identical_pending_adapter(self) -> None:
        self.fixture.seal()
        sealed = self.fixture.acceptance.read_bytes()
        pending = self.fixture.acceptance.parent / ".runtime-acceptance.json.pending"
        self.fixture.acceptance.rename(pending)
        self.assertEqual(self.fixture.resume_seal(), self.fixture.validate())
        self.assertEqual(self.fixture.acceptance.read_bytes(), sealed)
        self.assertFalse(pending.exists())

    def test_resume_seal_refuses_a_different_pending_adapter_without_mutation(self) -> None:
        pending = self.fixture.acceptance.parent / ".runtime-acceptance.json.pending"
        pending.write_bytes(b"{}\n")
        pending.chmod(0o600)
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError, "pending GA runtime adapter binds different evidence"
        ):
            self.fixture.resume_seal()
        self.assertEqual(pending.read_bytes(), b"{}\n")
        self.assertFalse(self.fixture.acceptance.exists())

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
        name = "udp-traffic.pcap"
        document = self.fixture.documents["udp-traffic.json"]
        tokens = document["tokens"]
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
        self.fixture.pcaps[name] = capture
        document["capture"] = {
            "kind": "packet-pcap",
            "path": name,
            "sha256": sha256_bytes(capture),
            "size": len(capture),
        }
        self.fixture.write_all()
        with self.assertRaisesRegex(Exception, "do not prove the required traffic"):
            self.fixture.seal()

    # The exact capture filter for the fixture challenge's dns_traffic tokens
    # (s000-/t000-/e000- plus 32 hex digits, so every first label is 37 bytes):
    # each clause binds the stage prefix and the first eight digest characters
    # s000-96ed7030..., t000-d1f93f86... and e000-a801f52b....
    DNS_CAPTURE_FILTER = (
        "udp and ((src host 198.18.64.1 and dst host 198.18.64.2 and dst port 53)"
        " or (src host 198.18.64.2 and src port 53 and dst host 198.18.64.1))"
        " and ((udp[20] = 37 and udp[21:4] = 0x73303030"
        " and udp[26:4] = 0x39366564 and udp[30:4] = 0x37303330)"
        " or (udp[20] = 37 and udp[21:4] = 0x74303030"
        " and udp[26:4] = 0x64316639 and udp[30:4] = 0x33663836)"
        " or (udp[20] = 37 and udp[21:4] = 0x65303030"
        " and udp[26:4] = 0x61383031 and udp[30:4] = 0x66353262))"
    )

    def _reset_fixture(self) -> RuntimeFixture:
        self.fixture = RuntimeFixture()
        self.addCleanup(self.fixture.cleanup)
        return self.fixture

    def _replace_dns_capture(self, capture: bytes) -> dict[str, Any]:
        document = self.fixture.documents["dns-traffic.json"]
        self.fixture.pcaps["dns-traffic.pcap"] = capture
        document["capture"] = {
            "kind": "packet-pcap",
            "path": "dns-traffic.pcap",
            "sha256": sha256_bytes(capture),
            "size": len(capture),
        }
        return document

    def _assert_seal_rejects(self, message: str, cause: str | None = None) -> None:
        self.fixture.write_all()
        with self.assertRaisesRegex(GARuntimeAcceptanceError, message) as raised:
            self.fixture.seal()
        if cause is not None:
            self.assertIsInstance(raised.exception.__cause__, PacketCaptureError)
            self.assertRegex(str(raised.exception.__cause__), cause)
        self.assertFalse(self.fixture.acceptance.exists())

    def test_dns_traffic_accepts_the_utun_tunnel_peer_leg(self) -> None:
        document = self.fixture.documents["dns-traffic.json"]
        self.assertEqual(
            _utun_dns_flags(self.fixture.pcaps["dns-traffic.pcap"]),
            [0x0100, 0x8500] * 3,
        )
        result = self.fixture.seal()
        self.assertEqual(result, self.fixture.validate())
        self.assertEqual(
            document["endpoint"],
            {
                "family": "ipv4",
                "interface_name": "utun5",
                "link_type": 0,
                "local_address": "198.18.64.1",
                "remote_address": "198.18.64.2",
                "remote_port": 53,
            },
        )
        self.assertEqual(
            document["capture_command"]["argv"][-5:],
            ["-c", "6", "-w", "-", self.DNS_CAPTURE_FILTER],
        )

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
            document["endpoint"].update(
                interface_name="en0", link_type=1, remote_address=upstream
            )
            document["capture_command"]["argv"] = ga_runtime._capture_command_argv(
                "en0", 6, ("udp", "and", "port", "53")
            )
            document["observation_ms"] = 5000
            self._assert_seal_rejects("endpoint differs from the fixed capture policy")
        with self.subTest(shape="upstream packets under the tunnel endpoint"):
            fixture = self._reset_fixture()
            tokens = fixture.documents["dns-traffic.json"]["tokens"]
            self._replace_dns_capture(
                _utun_udp_pcap(_tunnel_dns_packets(tokens, resolver=upstream))
            )
            self._assert_seal_rejects(
                "DNS capture endpoints are invalid", "exact start query"
            )

    def test_dns_traffic_rejects_interleaved_unrelated_resolver_traffic(self) -> None:
        query = _tunnel_dns_query(0x7B01, "www.apple.com")
        unrelated = [
            (0.50, TUNNEL_CLIENT, 53100, TUNNEL_DNS_PEER, 53, query),
            (
                0.56,
                TUNNEL_DNS_PEER,
                53,
                TUNNEL_CLIENT,
                53100,
                _tunnel_dns_response(
                    query, flags=0x8180, answer="17.253.144.10", ttl=60
                ),
            ),
        ]
        # Packets are start, target and end query/response pairs in order.
        cases = (
            (
                "interleaved pair",
                lambda packets: packets + unrelated,
                "partial or has extra traffic",
                None,
            ),
            (
                "pair displaced the end transaction",
                lambda packets: packets[:4] + unrelated,
                "DNS capture endpoints are invalid",
                "exact end query",
            ),
            (
                "query displaced the end response",
                lambda packets: packets[:5] + unrelated[:1],
                "do not prove the required traffic",
                "exactly one query and one authoritative response",
            ),
            (
                "retransmitted target query",
                lambda packets: packets + [(1.25, *packets[2][1:])],
                "DNS capture endpoints are invalid",
                "exact target query",
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
        unproven = "do not prove the required traffic"
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
                "exact target query",
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
            with self.subTest(token=own):
                for offset, start in ((26, 5), (30, 9)):
                    own_word = f"udp[{offset}:4] = 0x{own[start:start + 4].encode('ascii').hex()}"
                    foreign_word = (
                        f"udp[{offset}:4] = 0x{foreign[start:start + 4].encode('ascii').hex()}"
                    )
                    self.assertNotEqual(own_word, foreign_word)
                    self.assertIn(own_word, expression)
                    self.assertNotIn(foreign_word, expression)
                    self.assertIn(foreign_word, other_expression)

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
        self.assertEqual(ga_runtime.TUNNEL_DNS_PEER_IPV4, plan["ipv4DnsPeer"])
        self.assertEqual(
            TRAFFIC_POLICY["dns_traffic"]["remote_address"], plan["ipv4DnsPeer"]
        )
        self.assertEqual(
            (TUNNEL_CLIENT, TUNNEL_DNS_PEER),
            (plan["ipv4Address"], plan["ipv4DnsPeer"]),
        )

    def test_dns_queries_must_originate_from_the_tunnel_client(self) -> None:
        with self.subTest("foreign DNS client"):
            tokens = self.fixture.documents["dns-traffic.json"]["tokens"]
            self._replace_dns_capture(
                _utun_udp_pcap(_tunnel_dns_packets(tokens, client="198.18.64.9"))
            )
            self._assert_seal_rejects("DNS queries did not come from the tunnel client")
        cases = (
            ("tcp_traffic", "local_address", "10.0.0.5"),
            ("dns_traffic", "local_address", "10.0.0.5"),
            ("dns_traffic", "local_address", int(ipaddress.ip_address(TUNNEL_CLIENT))),
            ("dns_traffic", "remote_address", int(ipaddress.ip_address(TUNNEL_DNS_PEER))),
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
        for build in ("40041", "40043", "40044", "40045", "40046", "40047", "40048", "40067"):
            with self.subTest(build=build):
                self._set_service_stdout(
                    "proxy_agent",
                    original.replace(
                        "parent bundle version = 50028",
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
                packet_tunnel_row("0.5.0/50025", SYSTEM_EXTENSION_ACTIVATED)
            )
        )
        with self.assertRaisesRegex(
            GARuntimeAcceptanceError, "lacks the fixed 50028 extension"
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
    the exact 0.5.0/50028 row can prove the candidate extension is live."""

    MISSING = "raw system extension output lacks the fixed 50028 extension"
    NOT_ENABLED = "fixed system extension is not both activated and enabled"
    NOT_RETAINED = (
        "another Packet Tunnel registration is not terminated and waiting to "
        "uninstall on reboot"
    )
    FOREIGN_TEAM = "raw system extension output lists a foreign-team Packet Tunnel"
    MALFORMED = "raw systemextensionsctl output is malformed"
    NOT_EARLIER = "another Packet Tunnel registration is not an earlier build than 50028"
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
        candidate = packet_tunnel_row("0.5.0/50028", SYSTEM_EXTENSION_ACTIVATED)
        for bundle_id in (
            "com.bill.clashformac.packet-tunnelx",
            "com.bill.clashformac.packet-tunnel.helper",
            "xcom.bill.clashformac.packet-tunnel",
        ):
            for team_id in ("YKUPL7Z869", "ABCDE12345"):
                near_match = packet_tunnel_row(
                    "0.5.0/50028",
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
                    packet_tunnel_listing(row("0.5.0/50025", activated)),
                    self.MISSING,
                ),
                "listing before the 50028 replacement": (
                    packet_tunnel_listing(
                        row("0.5.0/50008", retained),
                        row("0.4.0/40073", retained),
                        row("0.5.0/50025", activated),
                    ),
                    self.MISSING,
                ),
                "candidate build under another product version": (
                    packet_tunnel_listing(row("0.5.1/50028", activated)),
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
                        row("0.5.0/50025", activated), row("0.5.0/50028", activated)
                    ),
                    self.NOT_RETAINED,
                ),
                "later build activated": (
                    packet_tunnel_listing(
                        row("0.5.0/50028", activated), row("0.5.0/50029", activated)
                    ),
                    self.NOT_RETAINED,
                ),
            }
        )

    def test_candidate_must_be_activated_enabled_and_flagged(self) -> None:
        row = packet_tunnel_row
        activated = SYSTEM_EXTENSION_ACTIVATED
        predecessor = row("0.5.0/50025", SYSTEM_EXTENSION_RETAINED)
        cases = {
            "waiting for user": (
                packet_tunnel_listing(
                    predecessor,
                    row("0.5.0/50028", "[activated waiting for user]", flags="*\t*"),
                ),
                self.NOT_ENABLED,
            ),
            "retained itself": (
                packet_tunnel_listing(
                    predecessor, row("0.5.0/50028", SYSTEM_EXTENSION_RETAINED)
                ),
                self.NOT_ENABLED,
            ),
        }
        # The state column alone is not proof: both flag columns must agree.
        for flags in ("\t", "*\t", "\t*"):
            cases[f"flags {flags!r}"] = (
                packet_tunnel_listing(row("0.5.0/50028", activated, flags=flags)),
                self.NOT_ENABLED,
            )
        self._assert_rejected(cases)

    def test_predecessor_in_an_unexpected_state_is_rejected(self) -> None:
        candidate = packet_tunnel_row("0.5.0/50028", SYSTEM_EXTENSION_ACTIVATED)
        self._assert_rejected(
            {
                state: (
                    packet_tunnel_listing(
                        packet_tunnel_row("0.5.0/50025", state), candidate
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
        # the GA Mac before 50028 replaced 50025: retained rows lead with two
        # empty flag columns.
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
        candidate = packet_tunnel_row("0.5.0/50028", SYSTEM_EXTENSION_ACTIVATED)
        # A retained state beside either flag is a self-contradicting row.
        self._assert_rejected(
            {
                f"retained flags {flags!r}": (
                    packet_tunnel_listing(
                        packet_tunnel_row(
                            "0.5.0/50025", SYSTEM_EXTENSION_RETAINED, flags=flags
                        ),
                        candidate,
                    ),
                    self.NOT_RETAINED,
                )
                for flags in ("*\t*", "*\t", "\t*")
            }
        )

    def test_retained_registration_must_be_an_earlier_build(self) -> None:
        candidate = packet_tunnel_row("0.5.0/50028", SYSTEM_EXTENSION_ACTIVATED)

        def listing(version: str) -> str:
            return packet_tunnel_listing(
                packet_tunnel_row(version, SYSTEM_EXTENSION_RETAINED), candidate
            )

        cases = {
            f"retained {version}": (listing(version), self.NOT_EARLIER)
            for version in (
                "0.5.1/50028",
                "0.5.0/50029",
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
                        row("0.5.0/50025", retained, team_id="ABCDE12345"),
                        row("0.5.0/50028", activated),
                    ),
                    self.FOREIGN_TEAM,
                ),
                "foreign candidate": (
                    packet_tunnel_listing(
                        row("0.5.0/50025", retained),
                        row("0.5.0/50028", activated, team_id="ABCDE12345"),
                    ),
                    self.FOREIGN_TEAM,
                ),
            }
        )

    def test_duplicate_or_miscounted_listing_is_malformed(self) -> None:
        row = packet_tunnel_row
        candidate = row("0.5.0/50028", SYSTEM_EXTENSION_ACTIVATED)
        self._assert_rejected(
            {
                "duplicate candidate registration": (
                    packet_tunnel_listing(
                        row("0.5.0/50028", SYSTEM_EXTENSION_RETAINED), candidate
                    ),
                    self.MALFORMED,
                ),
                # The summary counts distinct registrations here, so only the
                # repeated version itself exposes the inconsistency.
                "duplicate under a distinct-registration count": (
                    packet_tunnel_listing(candidate).replace(
                        candidate,
                        f"{row('0.5.0/50028', SYSTEM_EXTENSION_RETAINED)}\n{candidate}",
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
        self.guards = [guard(), guard()]
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
        self, check_id: str, tokens: dict[str, str]
    ) -> tuple[dict[str, object], bytes]:
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
            stdout: "GARuntimeCollectorTests._CapturePipe",
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

    def test_capture_authorization_is_required_before_any_app_command(self) -> None:
        runtime = FakeCollectorRuntime(self.fixture)
        with patch.object(runtime, "require_capture_authority", side_effect=GARuntimeAcceptanceError("authorization unavailable")), patch.object(runtime, "release_capture_authority") as release:
            sources = self._patch_evidence_sources()
            with sources[0], sources[1], sources[2], self.assertRaisesRegex(GARuntimeAcceptanceError, "authorization unavailable"):
                collect_ga_runtime_acceptance(
                    repository=self.fixture.repository,
                    expected=self.fixture.expected,
                    prepackage_stage_verifier=prepackage_stage_verifier,
                    runtime=runtime,
                )
        self.assertEqual(runtime.calls, [])
        release.assert_called_once()
        self.assertFalse(self.fixture.acceptance.exists())

    def test_terminal_refusal_needs_recover_before_a_fresh_collect(self) -> None:
        # RELEASE.md step 7: the terminal refusal follows the published
        # collection intent, so recover archives it before a fresh collect.
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
        self.assertEqual(refused.calls, [])
        self.assertEqual(
            collection_events(self.fixture.repository),
            [("aborted_before_mutation", "collection")],
        )
        retried = FakeCollectorRuntime(self.fixture)
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2], self.assertRaisesRegex(
            GARuntimeAcceptanceError,
            "^an unfinished GA runtime collection already exists; recover it$",
        ):
            self._collect(self.fixture, retried)
        self.assertEqual(retried.calls, [])
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        with patch.object(ga_runtime, "_installed_guard_baseline", return_value=guard()):
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        self.assertTrue(archived.is_dir())
        self.assertFalse(self.fixture.collection_root.exists())
        fresh = FakeCollectorRuntime(self.fixture)
        source_patches = self._patch_evidence_sources()
        with source_patches[0], source_patches[1], source_patches[2]:
            collected = self._collect(self.fixture, fresh)
        self.assertEqual(collected, self.fixture.validate())

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
                    ga_runtime._capture_command_argv("utun6", 3, ())

    def test_sender_failure_or_expired_budget_stops_before_later_markers(self) -> None:
        for sender_seconds, exit_code, message in (
            (0, 1, "start collection sender"),
            (46, 0, "complete bounded deadline"),
        ):
            with self.subTest(sender_seconds=sender_seconds, exit_code=exit_code):
                runtime = self._capture_runtime()
                process = self._CaptureProcess(self._CapturePipe(21), self._CapturePipe(22))
                process.poll = lambda: None
                def communicate(timeout):
                    process.returncode = 0
                    return b"bounded fixture packet bytes", b""
                process.communicate = communicate
                selector = MagicMock()
                selector.select.return_value = [(SimpleNamespace(fd=22), 0)]
                elapsed = [0.0]
                sent = []
                def send(argv, *, timeout):
                    sent.append((argv[argv.index("--stage") + 1], timeout))
                    elapsed[0] += sender_seconds
                    return command(argv, exit_code=exit_code, stderr="resolver failed" if exit_code else "")
                with patch.object(runtime, "_tunnel_interface", return_value="utun6"), \
                     patch.object(runtime, "run", side_effect=send), \
                     patch.object(runtime, "_terminate_capture") as terminate, \
                     patch.object(ga_runtime.subprocess, "Popen", return_value=process), \
                     patch.object(ga_runtime.selectors, "DefaultSelector", return_value=selector), \
                     patch.object(ga_runtime.os, "set_blocking"), \
                     patch.object(ga_runtime.os, "read", side_effect=[b"listening on utun6\n", b"failed fixture packet", b"", b""]), \
                     patch.object(ga_runtime.time, "monotonic", side_effect=lambda: elapsed[0]), \
                     patch.object(ga_runtime.time, "sleep"), \
                     patch.object(ga_runtime, "parse_packet_capture", return_value=SimpleNamespace(interfaces=[SimpleNamespace(link_type=0)])):
                    with self.assertRaisesRegex(GARuntimeAcceptanceError, message) as failure:
                        runtime._capture_traffic_bytes("dns_traffic", RuntimeFixture._traffic_tokens("dns_traffic"))
                self.assertEqual([stage for stage, _ in sent], ["start"])
                self.assertLessEqual(sent[0][1], 35)
                terminate.assert_called_once_with(process)
                self.assertTrue(process.stdout.closed)
                self.assertTrue(process.stderr.closed)
                retained = failure.exception.packet_capture_failure
                self.assertEqual(retained.packet_bytes, b"failed fixture packet")
                self.assertEqual(retained.stderr_bytes, b"listening on utun6\n")
                self.assertTrue(retained.outputs_complete)
                self.assertIs(retained.command["acceptance_valid"], False)
                self.assertEqual(len(retained.send_commands), 1)
                self.assertEqual(retained.retention_errors, ())

    def test_dns_collection_captures_the_tunnel_leg(self) -> None:
        # The real decoder, endpoint derivation and marker window run on a
        # utun capture; only the processes and the clock's sleeps are faked.
        runtime = self._capture_runtime()
        tokens = RuntimeFixture._traffic_tokens("dns_traffic")
        document = self.fixture.documents["dns-traffic.json"]
        capture = self.fixture.pcaps["dns-traffic.pcap"]
        receipts = dict(zip(DNS_STAGES, document["send_commands"], strict=True))
        process = self._CaptureProcess(self._CapturePipe(21), self._CapturePipe(22))
        process.poll = lambda: None

        def communicate(timeout):
            process.returncode = 0
            return capture, b"6 packets captured\n"

        process.communicate = communicate
        selector = MagicMock()
        selector.select.return_value = [(SimpleNamespace(fd=22), 0)]
        sent: list[str] = []

        def send(argv, *, timeout):
            stage = argv[argv.index("--stage") + 1]
            sent.append(stage)
            return copy.deepcopy(receipts[stage])

        listening = (
            b"tcpdump: listening on utun6, link-type NULL (BSD loopback), "
            b"snapshot length 524288 bytes\n"
        )
        with patch.object(runtime, "_tunnel_interface", return_value="utun6"), \
             patch.object(runtime, "run", side_effect=send), \
             patch.object(runtime, "_terminate_capture") as terminate, \
             patch.object(ga_runtime.subprocess, "Popen", return_value=process) as spawn, \
             patch.object(ga_runtime.selectors, "DefaultSelector", return_value=selector), \
             patch.object(ga_runtime.os, "set_blocking"), \
             patch.object(ga_runtime.os, "read", return_value=listening), \
             patch.object(ga_runtime.time, "sleep"):
            traffic, observed = runtime._capture_traffic_bytes("dns_traffic", tokens)
        expected_argv = ga_runtime._capture_command_argv(
            "utun6", 6, _expected_tunnel_dns_filter(tokens)
        )
        terminate.assert_not_called()
        self.assertEqual(sent, list(DNS_STAGES))
        self.assertEqual(spawn.call_args.args[0], expected_argv)
        self.assertEqual(traffic["capture_command"]["argv"], expected_argv)
        self.assertEqual(observed, capture)
        self.assertEqual(
            traffic["endpoint"],
            {
                "family": "ipv4",
                "interface_name": "utun6",
                "link_type": 0,
                "local_address": TUNNEL_CLIENT,
                "remote_address": TUNNEL_DNS_PEER,
                "remote_port": 53,
            },
        )
        self.assertEqual(traffic["observation_ms"], DNS_OBSERVATION_MS)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

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
                runtime._capture_traffic_bytes("dns_traffic", RuntimeFixture._traffic_tokens("dns_traffic"))
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

    def test_capture_selector_initialization_failure_cleans_all_resources(
        self,
    ) -> None:
        for stdout_close_error in (False, True):
            with self.subTest(stdout_close_error=stdout_close_error):
                runtime = self._capture_runtime()
                stdout = self._CapturePipe(21, close_error=stdout_close_error)
                stderr = self._CapturePipe(22)
                process = self._CaptureProcess(stdout, stderr)
                with patch.object(
                    runtime,
                    "_tunnel_interface",
                    return_value="utun6",
                ), patch(
                    "scripts.ga_runtime_acceptance.packet_capture_filter_argv",
                    return_value=(),
                ), patch(
                    "scripts.ga_runtime_acceptance.subprocess.Popen",
                    return_value=process,
                ), patch(
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
                    )
                self.assertIn(
                    (
                        "pipes could not be closed"
                        if stdout_close_error
                        else "selector is unavailable"
                    ),
                    str(captured.exception),
                )
                terminate.assert_called_once_with(process)
                self.assertTrue(stdout.closed)
                self.assertTrue(stderr.closed)

    def test_capture_post_selector_io_failure_is_typed_and_interrupt_cleans(
        self,
    ) -> None:
        for failure in (
            OSError("fixture descriptor exhaustion"),
            KeyboardInterrupt(),
        ):
            with self.subTest(failure=type(failure).__name__):
                runtime = self._capture_runtime()
                stdout = self._CapturePipe(21)
                stderr = self._CapturePipe(22)
                process = self._CaptureProcess(stdout, stderr)
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
                    "scripts.ga_runtime_acceptance.subprocess.Popen",
                    return_value=process,
                ), patch(
                    "scripts.ga_runtime_acceptance.os.set_blocking",
                    side_effect=failure,
                ), patch.object(
                    runtime,
                    "_terminate_capture",
                ) as terminate, self.assertRaises(expected) as captured:
                    runtime._capture_traffic_bytes(
                        "tcp_traffic",
                        RuntimeFixture._traffic_tokens("tcp_traffic"),
                    )
                if isinstance(failure, OSError):
                    self.assertIn("process I/O failed", str(captured.exception))
                terminate.assert_called_once_with(process)
                self.assertTrue(stdout.closed)
                self.assertTrue(stderr.closed)

    def _create_recoverable_collection(
        self, baseline: dict[str, object] | None = None
    ) -> None:
        failing = FakeCollectorRuntime(self.fixture, fail_launch=True)
        if baseline is not None:
            failing.guards = [copy.deepcopy(baseline)]
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
            "installed 50028 application tree cannot be identified"
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
        promote = ga_runtime.promote_private_pending

        def promote_then_lose_reply(pending: Path, destination: Path) -> None:
            promote(pending, destination)
            raise DurabilityOutcomeUnknown("simulated adapter rename reply loss")

        source_patches = self._patch_evidence_sources()
        with patch.object(
            ga_runtime, "promote_private_pending", side_effect=promote_then_lose_reply
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
        # Admission shares recovery's predicate: a stale pending adapter left
        # without a raw tree must not admit a collection that recover refuses.
        parent = self.fixture.acceptance.parent
        for name, create in (
            ("runtime-evidence", lambda path: path.mkdir(mode=0o700)),
            ("runtime-acceptance.json", lambda path: path.write_bytes(b"{}\n")),
            (".runtime-acceptance.json.pending", lambda path: path.write_bytes(b"{}\n")),
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
                    self.assertEqual(runtime.guards, [guard(), guard()])
                    self.assertFalse(self.fixture.collection_root.exists())
                finally:
                    if path.is_dir():
                        path.rmdir()
                    else:
                        path.unlink()

    def test_collect_treats_an_unobservable_pending_adapter_as_an_error(self) -> None:
        pending = self.fixture.acceptance.parent / ".runtime-acceptance.json.pending"
        lstat = Path.lstat

        def unreadable_pending(path: Path, *arguments: Any, **values: Any):
            if path == pending:
                raise PermissionError("fixture pending-adapter probe denied")
            return lstat(path, *arguments, **values)

        runtime = FakeCollectorRuntime(self.fixture, fail_launch=True)
        sources = self._patch_evidence_sources()
        with sources[0], sources[1], sources[2], patch.object(
            Path, "lstat", autospec=True, side_effect=unreadable_pending
        ), self.assertRaisesRegex(PermissionError, "fixture pending-adapter probe denied"):
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
            (".runtime-acceptance.json.pending", lambda path: path.write_bytes(b"{}\n")),
        ):
            with self.subTest(published=name):
                path = parent / name
                create(path)
                recovery = FakeCollectorRuntime(self.fixture)
                self._assert_recovery_refused(runtime=recovery)
                self.assertEqual(len(recovery.environments), 3)
                self.assertEqual(recovery.guards, [guard(), guard()])
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
            traffic, capture = runtime.capture_traffic("tcp_traffic", tokens)
        self.assertEqual(order, ["host-begin", "host-test", "host-restore"])
        capture_bytes.assert_called_once_with("tcp_traffic", tokens)
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
        for code in ("baseline_mismatch", "baseline_unavailable", "tunnel_unavailable", "app_control_unavailable"):
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

        approval_wait.assert_called_once_with(1.0)
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
            timeouts[tuple(ga_runtime._dmg_verifier_command(self.fixture.repository))],
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
            str(raised.exception.__cause__), "still contains the installed 50028 Host"
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
        self.assertFalse(
            (self.fixture.acceptance.parent / ".runtime-acceptance.json.pending").exists()
        )

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
        runtime.guards = [copy.deepcopy(baseline), copy.deepcopy(baseline)]
        intent_path = self.fixture.repository.joinpath(*COLLECTION_RELATIVE.parts) / "intent.json"
        run = runtime.run

        def run_after_durable_baseline(argv, *, timeout):
            intent = json.loads(intent_path.read_text(encoding="utf-8"))
            self.assertEqual(intent["cfw_guard_baseline"], baseline)
            self.assertEqual(intent["schema_version"], 3)
            self.assertEqual(intent["document"], "cfm-ga-runtime-collection-intent-v3")
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
                runtime.guards = [before, after]
                source_patches = self._patch_evidence_sources()
                with source_patches[0], source_patches[1], source_patches[2], self.assertRaises(
                    GACollectionRecoveryRequired
                ) as captured:
                    collect_ga_runtime_acceptance(
                        repository=fixture.repository,
                        expected=fixture.expected,
                        prepackage_stage_verifier=prepackage_stage_verifier,
                        runtime=runtime,
                        challenge_bytes=b"C" * 32,
                        session_id=SESSION_ID,
                    )
                self.assertIsInstance(captured.exception.__cause__, GARuntimeAcceptanceError)
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
        self.assertEqual(runtime.guards, [guard(), guard()])
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

    def test_recovery_archives_a_truncated_event_left_before_raw_publication(
        self,
    ) -> None:
        # RELEASE.md step 7: before raw publication an interrupted event write
        # leaves a truncated file; recovery appends after it and archives it.
        self._create_recoverable_collection()
        events = sorted(self.fixture.collection_root.glob("event-*.json"))
        torn = events[-1]
        torn.unlink()
        torn.write_bytes(b"")
        torn.chmod(0o600)
        recovery = self._absent_host_recovery_runtime([GA_ENVIRONMENT, GA_ENVIRONMENT])
        with patch.object(ga_runtime, "_installed_guard_baseline", return_value=guard()):
            archived = recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
        archived_events = sorted(archived.glob("event-*.json"))
        self.assertEqual((archived / torn.name).read_bytes(), b"")
        self.assertEqual(
            [path.name for path in archived_events],
            [f"event-{index:03d}.json" for index in range(len(archived_events))],
        )
        self.assertEqual(
            json.loads(archived_events[-1].read_bytes())["phase"], "recovered"
        )
        self.assertFalse(self.fixture.collection_root.exists())

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
        with patch.object(
            ga_runtime, "_installed_guard_baseline", return_value=guard()
        ), self.assertRaisesRegex(GARuntimeAcceptanceError, "collection's fixed CFW guard"):
            recover_ga_runtime_collection(
                repository=self.fixture.repository,
                expected=self.fixture.expected,
                runtime=recovery,
            )
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
                self.assertEqual(recovery.guards, [guard(), guard()])
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
        self.assertEqual(recovery.guards, [guard(), guard()])
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
        for label, off_proof in (("busy", busy), ("unproven", unproven)):
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
                self.assertEqual(raised.exception.__notes__, [RECOVERY_OFF_PROOF_GUIDANCE])
                self.assertIn(
                    f"\n{RECOVERY_OFF_PROOF_GUIDANCE}\n",
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
            f"\n{RECOVERY_OPERATOR_QUIT_GUIDANCE}\n",
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


class GARuntimeFailureDiagnosticTests(unittest.TestCase):
    @staticmethod
    def _lines(error: BaseException) -> list[str]:
        return common.failure_diagnostic("error: fixture headline", error).splitlines()

    def test_explicit_causes_render_in_order_with_their_notes(self) -> None:
        root = ValueError("artifact entry changed while revalidating: .")
        middle = GARuntimeAcceptanceError(
            "installed 50028 application tree cannot be identified"
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
                "fixture top note",
                "caused by GARuntimeAcceptanceError: "
                "installed 50028 application tree cannot be identified",
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
            "installed 50028 application tree cannot be identified"
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
                "installed 50028 application tree cannot be identified",
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
