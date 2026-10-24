#!/usr/bin/env python3
"""Seal and verify raw runtime evidence for the single active GA build.

This module deliberately does not accept a caller-selected evidence path and it
does not accept a list of boolean outcomes. Collection starts only after the
existing dormant-install and current-service owners have closed their
active-predecessor -> active-GA journals. ``collect`` creates a durable CSPRNG
challenge intent, owns every runtime command and packet byte, atomically
publishes the exact raw tree, and seals the adapter. ``recover`` archives a
collection without published raw evidence: one that aborted before its
mutation boundary at once, any other only after the runtime shutdown/restore
it owns; it never duplicates either installation state machine.
``resume-seal`` runs no runtime command: it only completes sealing of the
collection whose raw tree was published after the proven restore. ``verify``
reopens every byte and journal.

The larger physical/research harness remains assurance-only.  GA acceptance
reuses the signed Host's authenticated Packet control and the source-pinned
packet decoder, but requires only the bounded observations below and cannot be
satisfied by an assurance report or an ``all passed`` summary.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
import hashlib
import getpass
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Callable, Final, Iterable
import uuid

if __package__:
    from . import current_service_transaction
    from . import dormant_app_install
    from .ga_acceptance_environment import (
        GAAcceptanceEnvironmentError,
        environment_sha256,
        observe_environment,
        require_same_environment,
        validate_environment,
    )
    from .ga_acceptance_journal_export import (
        ACCEPTANCE_ROOT_RELATIVE as JOURNAL_EXPORT_ACCEPTANCE_ROOT_RELATIVE,
        ENVIRONMENT_RELATIVE as JOURNAL_EXPORT_ENVIRONMENT_RELATIVE,
        INSTALL_RELATIVE as JOURNAL_EXPORT_INSTALL_RELATIVE,
    )
    from .harness.packet_capture import (
        ALLOWED_LINK_TYPES,
        DNS_A_ADDRESS,
        DnsResolverLeg,
        MAX_SNAPLEN,
        PacketCaptureError,
        ParsedCapture,
        RetransmissionPolicy,
        StagedCaptureEndpoint,
        dns_resolver_leg_stage_endpoints,
        parse_packet_capture,
        staged_marker_window,
        timestamp_fraction,
        validate_staged_capture_tokens,
    )
    from .harness.packet_evidence import (
        PACKET_TRANSPORT_PORT,
        TUNNEL_CAPTURE_LOCAL_ADDRESSES,
        packet_capture_filter_argv,
    )
    from .maintenance_network_observations import (
        NetworkObservationError,
        network_routes,
        tunnel_interfaces,
    )
    from .physical_capture.packet_sender import DOCUMENT as PACKET_SEND_DOCUMENT
    from .physical_capture.packet_host import (
        PacketCaptureDisposition,
        PacketHostError,
        PacketHostReceipt,
        PacketHostSnapshot,
        run_fixed_host_transaction,
    )
    from .publication.common import (
        PublicationError,
        bounded_text,
        canonical_json,
        escaped_tail,
        failure_diagnostic,
        read_regular,
        require_exact_keys,
        require_sha256,
        safe_relative,
        sha256_bytes,
        sha256_file,
        tree_digest,
    )
    from .publication.bounded_process import (
        BoundedProcessError,
        _wait_for_group_exit,
        run_bounded_process,
    )
    from .publication.durable_file import (
        DurabilityOutcomeUnknown,
        RootedDirectoryChanged,
        exclusive_rooted_directory_lock,
        exclusive_rooted_directory_lock_with_parent,
        publish_private_directory_locked,
        publish_private_file_locked,
        read_private_directory_contents_locked,
        read_private_pending_locked,
    )
    from .publication.graph_model import load_pins
    from .publication.release_environment import release_tool_environment
    from .release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        BuildIdentityError,
        canonical_build_version,
        ga_root,
    )
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from scripts import current_service_transaction
    from scripts import dormant_app_install
    from scripts.ga_acceptance_environment import (
        GAAcceptanceEnvironmentError,
        environment_sha256,
        observe_environment,
        require_same_environment,
        validate_environment,
    )
    from scripts.ga_acceptance_journal_export import (
        ACCEPTANCE_ROOT_RELATIVE as JOURNAL_EXPORT_ACCEPTANCE_ROOT_RELATIVE,
        ENVIRONMENT_RELATIVE as JOURNAL_EXPORT_ENVIRONMENT_RELATIVE,
        INSTALL_RELATIVE as JOURNAL_EXPORT_INSTALL_RELATIVE,
    )
    from scripts.harness.packet_capture import (
        ALLOWED_LINK_TYPES,
        DNS_A_ADDRESS,
        DnsResolverLeg,
        MAX_SNAPLEN,
        PacketCaptureError,
        ParsedCapture,
        RetransmissionPolicy,
        StagedCaptureEndpoint,
        dns_resolver_leg_stage_endpoints,
        parse_packet_capture,
        staged_marker_window,
        timestamp_fraction,
        validate_staged_capture_tokens,
    )
    from scripts.harness.packet_evidence import (
        PACKET_TRANSPORT_PORT,
        TUNNEL_CAPTURE_LOCAL_ADDRESSES,
        packet_capture_filter_argv,
    )
    from scripts.maintenance_network_observations import (
        NetworkObservationError,
        network_routes,
        tunnel_interfaces,
    )
    from scripts.physical_capture.packet_sender import (
        DOCUMENT as PACKET_SEND_DOCUMENT,
    )
    from scripts.physical_capture.packet_host import (
        PacketCaptureDisposition,
        PacketHostError,
        PacketHostReceipt,
        PacketHostSnapshot,
        run_fixed_host_transaction,
    )
    from scripts.publication.common import (
        PublicationError,
        bounded_text,
        canonical_json,
        escaped_tail,
        failure_diagnostic,
        read_regular,
        require_exact_keys,
        require_sha256,
        safe_relative,
        sha256_bytes,
        sha256_file,
        tree_digest,
    )
    from scripts.publication.bounded_process import (
        BoundedProcessError,
        _wait_for_group_exit,
        run_bounded_process,
    )
    from scripts.publication.durable_file import (
        DurabilityOutcomeUnknown,
        RootedDirectoryChanged,
        exclusive_rooted_directory_lock,
        exclusive_rooted_directory_lock_with_parent,
        publish_private_directory_locked,
        publish_private_file_locked,
        read_private_directory_contents_locked,
        read_private_pending_locked,
    )
    from scripts.publication.graph_model import load_pins
    from scripts.publication.release_environment import release_tool_environment
    from scripts.release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        BuildIdentityError,
        canonical_build_version,
        ga_root,
    )


@dataclass(frozen=True)
class FailedPacketCaptureEvidence:
    """Bounded diagnostic bytes from a failed capture; never acceptance proof."""

    check_id: str
    command: dict[str, Any]
    # The sudo that ran tcpdump, which leads the capture's process group.
    sudo_pid: int
    send_commands: tuple[dict[str, Any], ...]
    packet_bytes: bytes
    stderr_bytes: bytes
    outputs_complete: bool
    retention_errors: tuple[str, ...]


class GARuntimeAcceptanceError(ValueError):
    """The fixed GA runtime evidence is incomplete, drifted, or unobservable."""

    packet_capture_failure: FailedPacketCaptureEvidence | None = None


class ObservationNotReady(GARuntimeAcceptanceError):
    """A well-formed observation of state that a later one can still show ready.

    Only this rejection is observed again during a readiness wait; any other
    rejection of the same observation ends its step at once.
    """


PrepackageStageVerifier = Callable[[Path], dict[str, Any]]


PRODUCT_VERSION: Final = ACTIVE_RELEASE_IDENTITY.product_version
TO_BUILD: Final = ACTIVE_RELEASE_IDENTITY.ga_build
FROM_BUILD: Final = dormant_app_install.ACTIVE_PREDECESSOR.build_number
TEAM_ID: Final = "YKUPL7Z869"
APP_BUNDLE_ID: Final = "com.bill.clashformac"
PACKET_EXTENSION_BUNDLE_ID: Final = "com.bill.clashformac.packet-tunnel"
# systemextensionsctl prints "(CFBundleShortVersionString/CFBundleVersion)".
PACKET_EXTENSION_VERSION: Final = f"{PRODUCT_VERSION}/{TO_BUILD}"
PACKET_EXTENSION_ACTIVE_STATE: Final = "[activated enabled]"
# The only state in which macOS keeps a replaced Packet Tunnel listed: it no
# longer runs and is removed at the next reboot.
PACKET_EXTENSION_RETAINED_STATE: Final = "[terminated waiting to uninstall on reboot]"
# A retained row's CFBundleShortVersionString; its CFBundleVersion must be an
# earlier canonical build than the candidate's.
PACKET_EXTENSION_SHORT_VERSION_RE: Final = re.compile(
    r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}"
)
PROXY_LABEL: Final = "com.bill.clashformac.proxy-agent"
AUTHORITY_LABEL: Final = "com.bill.clashformac.global-authority"
INSTALLED_APP: Final = Path("/Applications/Clash for Mac.app")
INSTALLED_EXECUTABLE: Final = INSTALLED_APP / "Contents/MacOS/clash-for-mac"
PROXY_EXECUTABLE: Final = (
    INSTALLED_APP
    / "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
)
AUTHORITY_EXECUTABLE: Final = (
    INSTALLED_APP / "Contents/Library/HelperTools/CFWGlobalAuthority"
)

GA_ROOT_RELATIVE: Final = ga_root(Path("."))
ACCEPTANCE_ROOT_RELATIVE: Final = JOURNAL_EXPORT_ACCEPTANCE_ROOT_RELATIVE
ACCEPTANCE_RELATIVE: Final = ACCEPTANCE_ROOT_RELATIVE / "runtime-acceptance.json"
RAW_ROOT_RELATIVE: Final = ACCEPTANCE_ROOT_RELATIVE / "runtime-evidence"
COLLECTION_RELATIVE: Final = ACCEPTANCE_ROOT_RELATIVE / "runtime-collection"
ENVIRONMENT_RELATIVE: Final = JOURNAL_EXPORT_ENVIRONMENT_RELATIVE
INSTALL_JOURNAL_RELATIVE: Final = JOURNAL_EXPORT_INSTALL_RELATIVE
DMG_RELATIVE: Final = (
    GA_ROOT_RELATIVE
    / f"packages/dmg/v{PRODUCT_VERSION}/Clash.for.Mac_{PRODUCT_VERSION}_arm64.dmg"
)
DMG_SET_RELATIVE: Final = GA_ROOT_RELATIVE / f"packages/dmg/v{PRODUCT_VERSION}"

DOCUMENT: Final = "cfm-ga-runtime-acceptance-v2"
SCHEMA_VERSION: Final = 2
CHECK_DOCUMENT: Final = "cfm-ga-runtime-check-v2"
COMMAND_DOCUMENT: Final = "cfm-ga-command-observation-v2"
SECRET_POLICY: Final = "cfm-ga-evidence-secret-patterns-v1"
GATE_CLASS: Final = "ga_required"

CHECKS: Final = (
    "credential_leak_scan",
    "dns_traffic",
    "exact_dmg_install",
    "high_risk_rejections",
    "launch",
    "legacy_cfw_preserved",
    "network_extension",
    "service_registration",
    "shutdown_restore",
    "system_extension",
    "tcp_traffic",
    "udp_traffic",
)
TRAFFIC_CHECKS: Final = ("dns_traffic", "tcp_traffic", "udp_traffic")
JSON_FILES: Final = frozenset(f"{name.replace('_', '-')}.json" for name in CHECKS)
PCAP_FILES: Final = frozenset(
    f"{name.replace('_', '-')}.pcap" for name in TRAFFIC_CHECKS
)
RAW_FILE_NAMES: Final = frozenset({*JSON_FILES, *PCAP_FILES})

MAX_JSON_BYTES: Final = 1024 * 1024
MAX_PCAP_BYTES: Final = 32 * 1024 * 1024
MAX_TOTAL_BYTES: Final = 64 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES: Final = 256 * 1024
# An operator note about a failed command keeps at most this much of the end
# of each output stream.
COMMAND_DIAGNOSTIC_TAIL_BYTES: Final = 4096
# The bounds of the sudo run that proves the held capture password.
CAPTURE_AUTHORITY_TIMEOUT_SECONDS: Final = 10
CAPTURE_AUTHORITY_OUTPUT_BYTES: Final = 4096
MAX_COMMAND_SECONDS: Final = 15 * 60
DMG_BYTE_PROOF_TIMEOUT_SECONDS: Final = 30 * 60
PACKET_HOST_READY_SECONDS: Final = 10 * 60
# The signed Host consumes one of its 64 launcher tickets, each live for 305
# seconds, for every attempt it admits, including one it then refuses because
# Tunnel or a mode change is not ready. Six seconds between those retries keeps
# at most about 51 live through the operator's wait and leaves tickets for the
# dns, tcp, udp and stop-cleanup transactions that follow it.
PACKET_HOST_TICKET_RETRY_SECONDS: Final = 6.0
# The signed Host allows 60 seconds for its test callback. Include interface
# lookup, tcpdump readiness, every sender, the capture settle and the stop in
# one budget, leaving time for a sender's ten-second group cleanup,
# five-second tcpdump cleanup, three-second failure retention and the
# protocol reply.
PACKET_EXERCISE_SECONDS: Final = 35
# tcpdump stops by itself after this many packets, so a capture that reaches
# it fails as extra traffic; the collector stops every capture it accepts.
# Nominal traffic is six DNS records or three TCP or UDP records, and each
# repeated query or move to the other resolver leg adds at most a query and
# its answer, so 32 leaves room for several on every stage. The cap also
# bounds the pcap: 24 + 32 * (16 + MAX_SNAPLEN) bytes is under MAX_PCAP_BYTES.
CAPTURE_PACKET_CAP: Final = 32
# After the end marker's sender returns, the capture runs this long before the
# collector stops it, so a stage's late repeated query, the answer to it or a
# late TCP retransmission is judged with the rest instead of escaping the
# capture. tcpdump runs with --immediate-mode, so libpcap hands it each packet
# as it arrives; tcpdump(1) says a capture written to a file is otherwise
# buffered, and libpcap would hold packets for the one-second BPF read timeout
# tcpdump sets, which this settle also covers.
CAPTURE_SETTLE_SECONDS: Final = 1.5
# The least of the exercise the stop needs after the settle. It has two steps,
# the process observation that finds tcpdump and the wait for tcpdump's
# statistics and exit, and the exercise starts no step with less than a whole
# second left. The settle starts only with this much more than itself left,
# so the deadline cannot pass between the settle and the interrupt, where the
# failed capture's cleanup would kill tcpdump before it printed its count.
CAPTURE_STOP_SECONDS: Final = 2
# The statistics tcpdump prints on stderr when it stops ("%lu packet%s
# captured", "%u packet%s dropped by kernel"): the packets it wrote, and the
# packets that matched its filter but that the kernel dropped before tcpdump
# read them.
CAPTURE_STATISTIC_RE: Final = re.compile(
    r"(0|[1-9][0-9]*) packets? (captured|dropped by kernel)"
)
# For each process of the group that a capture's sudo leads, as
# start_new_session makes it: its parent, its real, effective and saved user
# IDs, its state and its accounting name, which ps(1) says can be depended on,
# unlike the command and arguments a process may change. The collector finds
# the tcpdump that sudo runs by them and stops it. Only that group is listed:
# ps prints every accounting name unescaped and cut at 16 bytes, so another
# process's name could otherwise fail the strict decode of the listing. The
# collector's environment has no COMMAND_MODE; the legacy mode that
# COMMAND_MODE=legacy selects rejects this argv, so the observation would fail.
# A name runs from its first to its last non-space character, which a match
# finds in linear time even across a long run of spaces inside it; a name of
# only whitespace is its last character, as the lazy `(.+?)\s*` this replaced
# read it in quadratic time.
CAPTURE_PROCESS_COLUMNS: Final = "pid=,ppid=,ruid=,uid=,svuid=,state=,ucomm="
CAPTURE_PROCESS_ROW_RE: Final = re.compile(
    r"\s*([1-9][0-9]*)\s+([0-9]+)\s+(-?[0-9]+)\s+(-?[0-9]+)\s+(-?[0-9]+)\s+(\S+)\s+"
    r"(\S(?:.*\S)?|\s)\s*"
)
# A refusal to stop a capture shows at most this many rows of sudo's process
# group; sudo runs one command, so more means something else is wrong.
CAPTURE_PROCESS_NOTE_ROWS: Final = 8
# configd can still be applying the restored proxy, DNS and routes when the
# Host's Off proof completes. A restored guard that differs is observed again
# once a second, and no observation starts after 30 seconds; the judgement
# itself is unchanged, and a guard that cannot be observed fails at once.
# collect judges the guard right before its launch the same way.
GUARD_SETTLE_SECONDS: Final = 30
GUARD_SETTLE_INTERVAL_SECONDS: Final = 1.0
# `open -a` returns once LaunchServices accepts the launch, before the Host
# need be listed, and both services are on-demand MachServices that launchd
# starts when the Host first connects to them. An observation that shows only
# that state not ready yet is repeated once a second, and none starts after
# these bounds; each keeps its own command timeout, so a step can last one
# timeout longer. Any other rejection ends the step at once, and only the
# accepted observation is recorded.
LAUNCH_PROCESS_READY_SECONDS: Final = 30
SERVICE_READY_SECONDS: Final = 60
READINESS_POLL_SECONDS: Final = 1.0


MAX_RUNTIME_FILES: Final = 32
TOKEN_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,63}$")
INTERFACE_RE: Final = re.compile(r"^(?:utun[0-9]{1,3}|en[0-9]{1,2}|pktap,all)$")
# contracts/tunnel-address-plan-v1.json ipv4DnsPeer and ipv6DnsPeer. The
# Packet Tunnel makes both the resolvers for every domain, so the product DNS
# leg GA can observe on utun ends at one of them, queried from the tunnel
# address of the same family. macOS lists the IPv6 peer first. The evidence
# resolver answers only token queries, so other system lookups during the
# case go unanswered and macOS may send a later stage's query to the other
# peer. Either leg carries the same single A question from getaddrinfo. The
# signed dns-a-primary case forwards each query outside utun to the evidence
# resolver. libbox returns that resolver's authoritative answer under the
# client's query ID, re-packed without name compression.
TUNNEL_DNS_PEER_IPV4: Final = "198.18.64.2"
TUNNEL_DNS_PEER_IPV6: Final = "2001:2:0:64::2"
TUNNEL_DNS_LEGS: Final = (
    DnsResolverLeg(TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"], TUNNEL_DNS_PEER_IPV4),
    DnsResolverLeg(TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv6"], TUNNEL_DNS_PEER_IPV6),
)
# A Packet Tunnel whose network state was not fully removed leaves these
# tunnel-plan addresses on a utun, a route or a system resolver.
CFM_TUNNEL_LOCAL_ADDRESSES: Final = frozenset(
    ipaddress.ip_address(address) for address in TUNNEL_CAPTURE_LOCAL_ADDRESSES.values()
)
CFM_TUNNEL_DNS_PEERS: Final = frozenset(
    ipaddress.ip_address(address) for address in (TUNNEL_DNS_PEER_IPV4, TUNNEL_DNS_PEER_IPV6)
)
# The question family of the dns-a-primary sender: getaddrinfo(AF_INET).
TUNNEL_DNS_QUESTION_FAMILY: Final = "ipv4"
# _derive_capture_token's shape: a four-character stage prefix, "-" and 32
# lowercase hex digest characters, one 37-byte QNAME label. The capture filter
# loads fixed offsets of that label and the decoder lowercases names.
DNS_EVIDENCE_LABEL_RE: Final = re.compile(r"^[a-z0-9]{4}-[0-9a-f]{32}$")

# Each capture is stopped by time, so it keeps whatever a stage repeats before
# the stop: a resolver's repeated query or move to the other leg, libbox's
# answer to each, or a TCP retransmission. DNS and TCP therefore admit
# identical retransmissions and account for every record; nothing
# retransmits a UDP datagram, so UDP keeps exactly one record per stage.
TRAFFIC_POLICY: Final = {
    "dns_traffic": {
        "case_id": "dns-a-primary",
        "protocol": "dns",
        "remote_port": 53,
        "retransmissions": RetransmissionPolicy.IDENTICAL_RETRANSMISSIONS,
    },
    "tcp_traffic": {
        "case_id": "tcp-ipv4",
        "protocol": "tcp",
        "remote_address": "35.194.216.98",
        "remote_port": PACKET_TRANSPORT_PORT,
        "retransmissions": RetransmissionPolicy.IDENTICAL_RETRANSMISSIONS,
    },
    "udp_traffic": {
        "case_id": "udp",
        "protocol": "udp",
        "remote_address": "35.194.216.98",
        "remote_port": PACKET_TRANSPORT_PORT,
        "retransmissions": RetransmissionPolicy.EXACT,
        "expected_records": 3,
    },
}
# The sender's arguments after its interpreter. The collector runs the sender
# with the release Python that the collection intent records; the artifact
# checkout is the working directory.
PACKET_SENDER_COMMAND: Final = (
    "-I",
    "-S",
    "-B",
    "-W",
    "error",
    "scripts/physical_capture/packet_sender.py",
)
# release_python_runtime admits only a pinned CPython 3 release version.
PYTHON_VERSION_RE: Final = re.compile(r"3\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
MAX_COLLECTOR_PATH_LENGTH: Final = 1024
PACKET_STAGES: Final = ("start", "target", "end")
PACKET_EVIDENCE_FLAG: Final = "--physical-packet-evidence-v5"
SERVICE_MAINTENANCE_FLAG: Final = "--service-maintenance-v2"
PACKET_HOST_DOCUMENT: Final = "cfw-packet-host-completed-v5"
PACKET_HOST_SCHEMA_VERSION: Final = 5
# The product's graceful shutdown, which normally stops the runtime and proves
# Off before the Host exits, runs from Quit Clash for Mac (⌘Q) in the app menu,
# Quit in the menu-bar menu and the Settings page's own Quit and Force Quit
# buttons.
# A quit from the Dock, AppleScript or Activity Monitor, or the macOS Force
# Quit window, either sends the quit AppleEvent, which tao 0.37.1 turns
# straight into applicationWillTerminate, or ends the process; the Packet
# Tunnel then stays connected until the next launch. The collector therefore
# sends the Host nothing and asks the operator for the ⌘Q quit. The evidence
# keeps this request as the instruction that was issued: no quit control
# leaves a receipt, so it cannot show which control ended the Host.
OPERATOR_QUIT_INSTRUCTION: Final = (
    f"GA runtime collection is waiting for you to quit the installed {TO_BUILD} Clash "
    "for Mac with Quit Clash for Mac (⌘Q) in its app menu or Quit in its menu "
    "bar menu; do not quit it from the Dock, AppleScript or Activity Monitor, "
    "or with the macOS Force Quit window (Option-Command-Esc)"
)
OPERATOR_QUIT_REQUEST: Final = {
    "instruction": OPERATOR_QUIT_INSTRUCTION,
    "kind": "operator_quit_instruction",
}
# Bounds a person reading the instruction and choosing Quit. The Host's own
# stop and Off proof before it exits fall inside the same wait.
OPERATOR_QUIT_SECONDS: Final = 10 * 60
OFF_PROOF_COMMAND: Final = (
    INSTALLED_EXECUTABLE.as_posix(),
    SERVICE_MAINTENANCE_FLAG,
    "prove-off",
)
PROCESS_OBSERVATION_COMMAND: Final = (
    "/bin/ps",
    "-axo",
    "pid=,uid=,lstart=,comm=",
)
# Collection runs, and verification checks, the two commands above and these;
# the ProxyAgent's and the DMG verifier's depend on the user and the operator
# checkout, so _proxy_agent_print_command and _dmg_verifier_command build them.
DMG_GATEKEEPER_COMMAND: Final = (
    "/usr/sbin/spctl",
    "--assess",
    "--type",
    "open",
    "--context",
    "context:primary-signature",
    "-vv",
    DMG_RELATIVE.as_posix(),
)
LAUNCH_COMMAND: Final = ("/usr/bin/open", "-a", INSTALLED_APP.as_posix())
AUTHORITY_PRINT_COMMAND: Final = ("/bin/launchctl", "print", f"system/{AUTHORITY_LABEL}")
SYSTEM_EXTENSION_COMMAND: Final = ("/usr/bin/systemextensionsctl", "list")
HIGH_RISK_PROBES: Final = (
    (
        "unknown-service-maintenance-action",
        (
            INSTALLED_EXECUTABLE.as_posix(),
            SERVICE_MAINTENANCE_FLAG,
            "unknown",
        ),
        64,
        "startup argument admission failed: service maintenance action is not one "
        "fixed v2 operation\n",
    ),
    (
        "unauthenticated-packet-control",
        (INSTALLED_EXECUTABLE.as_posix(), PACKET_EVIDENCE_FLAG),
        70,
        "physical Packet evidence Host control failed: physical Packet control "
        "descriptor is invalid\n",
    ),
    (
        "extra-packet-control-argument",
        (
            INSTALLED_EXECUTABLE.as_posix(),
            PACKET_EVIDENCE_FLAG,
            "--unexpected",
        ),
        64,
        "startup argument admission failed: startup arguments are not a supported exact mode\n",
    ),
)

# The scan is intentionally narrow enough not to treat words such as "token"
# in the packet schema as credentials.  It detects concrete credential encodings
# and never includes matching bytes in its exception text.
SECRET_PATTERNS: Final = (
    re.compile(rb"-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[opusr]_[A-Za-z0-9]{24,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{24,}\b"),
    re.compile(rb"(?i)authorization:[ \t]*bearer[ \t]+[A-Za-z0-9._~+/-]{16,}"),
    re.compile(
        rb'(?i)"(?:access_token|refresh_token|client_secret|private_key|password)"'
        rb"[ \t]*:[ \t]*\"[^\"\r\n]{8,}\""
    ),
    re.compile(
        rb"(?i)\b(?:TAURI_SIGNING_PRIVATE_KEY|APPLE_API_KEY|NOTARY_PASSWORD)="
        rb"[^\x00\r\n]{8,}"
    ),
)


@dataclass(frozen=True)
class FileSnapshot:
    relative: str
    data: bytes
    size: int
    sha256: str
    identity: tuple[int, int, int, int, int, int]

    def record(self) -> dict[str, Any]:
        return {"path": self.relative, "sha256": self.sha256, "size": self.size}


def _error(message: str) -> GARuntimeAcceptanceError:
    return GARuntimeAcceptanceError(message)


def _canonical_repository(repository: Path) -> Path:
    candidate = Path(repository)
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        raise _error("GA repository is unavailable") from error
    if (
        candidate.absolute() != resolved
        or resolved.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise _error("GA repository must be one canonical owned directory")
    return resolved


def _fixed_paths(repository: Path) -> tuple[Path, Path]:
    return (
        repository.joinpath(*ACCEPTANCE_RELATIVE.parts),
        repository.joinpath(*RAW_ROOT_RELATIVE.parts),
    )


def _fixed_path_present(path: Path) -> bool:
    """Observe one fixed output; an unreadable state is an error, not absence."""

    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _published_runtime_outputs(repository: Path) -> tuple[str, ...]:
    """Name each existing raw tree or adapter.

    collect admission and recover share this one predicate, so neither starts
    a runtime command while any published output exists.
    """

    acceptance_path, raw_root = _fixed_paths(repository)
    return tuple(
        path.name for path in (raw_root, acceptance_path) if _fixed_path_present(path)
    )


def _operator_root() -> Path:
    """The operator checkout whose release tooling runs this module."""

    return Path(__file__).resolve().parent.parent


def _dmg_verifier_command(operator_root: Path, repository: Path) -> list[str]:
    """Run the operator's DMG verifier against the artifact checkout's DMG set.

    The prefix up to ``operator_root`` is the operator's launcher; the rest are
    the command's own arguments.
    """

    return [
        "/bin/bash",
        "-p",
        "-c",
        "set -euo pipefail; "
        'source "$1/scripts/release_python_launcher.sh"; '
        'cfw_run_release_python_script "$1" '
        '"$1/scripts/release_artifact_set_cli.py" "${@:2}"',
        "ga-dmg-verification",
        str(operator_root),
        "verify-dmg",
        "--directory",
        str(repository / DMG_SET_RELATIVE),
        "--version",
        PRODUCT_VERSION,
        "--repository",
        str(repository),
    ]


def _require_fixed_paths(
    repository: Path,
    acceptance_path: Path,
    raw_evidence_root: Path,
) -> None:
    expected_acceptance, expected_raw = _fixed_paths(repository)
    if Path(acceptance_path).absolute() != expected_acceptance:
        raise _error(f"GA runtime adapter path is not the fixed {TO_BUILD} path")
    if Path(raw_evidence_root).absolute() != expected_raw:
        raise _error(f"GA runtime raw-evidence path is not the fixed {TO_BUILD} path")


def _strict_json(data: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _error(f"{label} repeats JSON field {key!r}")
            result[key] = value
        return result

    def reject_constant(token: str) -> Any:
        raise _error(f"{label} contains non-finite JSON constant {token}")

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
    except GARuntimeAcceptanceError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        raise _error(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise _error(f"{label} is not one canonical JSON object")
    try:
        encoded = canonical_json(value)
    except (RecursionError, UnicodeError) as error:
        raise _error(f"{label} is not one canonical JSON object") from error
    if encoded != data:
        raise _error(f"{label} is not one canonical JSON object")
    return value


def _require_private_directory(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise _error(f"GA runtime directory is unavailable: {path}") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _error(f"GA runtime directory is not an owned 0700 real directory: {path}")
    return metadata


def _private_regular_metadata(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise _error(f"GA runtime evidence is unavailable: {path}") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise _error(f"GA runtime evidence is not an owned single-link 0600 file: {path}")
    return metadata


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_mode,
        metadata.st_nlink,
    )


def _load_bound_environment(
    repository: Path,
    expected_sha256: str,
) -> dict[str, Any]:
    path = repository.joinpath(*ENVIRONMENT_RELATIVE.parts)
    try:
        with exclusive_rooted_directory_lock(
            repository,
            path.parent,
            require_private=True,
        ) as descriptor:
            data = read_private_pending_locked(
                descriptor,
                path.parent,
                path.name,
                MAX_JSON_BYTES,
            )
    except (PublicationError, RootedDirectoryChanged) as error:
        raise _error("fixed GA environment document cannot be reopened safely") from error
    document = _strict_json(data, "fixed GA environment document")
    try:
        normalized = validate_environment(document)
        observed_sha256 = environment_sha256(normalized)
    except GAAcceptanceEnvironmentError as error:
        raise _error("fixed GA environment document is invalid") from error
    if observed_sha256 != expected_sha256:
        raise _error("fixed GA environment differs from the expected binding")
    return normalized


def _require_current_environment(
    repository: Path,
    runtime: ProductionCollectorRuntime,
    expected_sha256: str,
    *,
    label: str,
) -> dict[str, Any]:
    expected_environment = _load_bound_environment(repository, expected_sha256)
    try:
        observed_environment = runtime.capture_environment()
        return require_same_environment(
            expected_environment,
            observed_environment,
            label=label,
        )
    except GAAcceptanceEnvironmentError as error:
        raise _error(f"{label} does not match the fixed GA environment") from error


def _snapshot_raw_tree(root: Path) -> dict[str, FileSnapshot]:
    _require_private_directory(root)
    try:
        names = os.listdir(root)
    except OSError as error:
        raise _error("GA runtime evidence inventory cannot be enumerated") from error
    if len(names) > MAX_RUNTIME_FILES or set(names) != set(RAW_FILE_NAMES):
        raise _error("GA runtime evidence has a missing or unexpected file set")
    snapshots: dict[str, FileSnapshot] = {}
    total = 0
    for name in sorted(names):
        safe_relative(name, "GA runtime evidence filename")
        path = root / name
        before = _private_regular_metadata(path)
        maximum = MAX_PCAP_BYTES if name.endswith(".pcap") else MAX_JSON_BYTES
        try:
            data = read_regular(path, maximum)
        except PublicationError as error:
            raise _error(f"GA runtime evidence cannot be read safely: {name}") from error
        after = _private_regular_metadata(path)
        if _file_identity(before) != _file_identity(after):
            raise _error(f"GA runtime evidence changed while reopening: {name}")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise _error("GA runtime evidence exceeds its aggregate byte bound")
        snapshots[name] = FileSnapshot(
            relative=name,
            data=data,
            size=len(data),
            sha256=sha256_bytes(data),
            identity=_file_identity(after),
        )
    return snapshots


def _confirm_snapshot(root: Path, expected: dict[str, FileSnapshot]) -> None:
    observed = _snapshot_raw_tree(root)
    if set(observed) != set(expected):
        raise _error("GA runtime evidence inventory changed during verification")
    for name in sorted(expected):
        if observed[name] != expected[name]:
            raise _error(f"GA runtime evidence changed during verification: {name}")


def _tree_entries(snapshots: dict[str, FileSnapshot]) -> list[dict[str, Any]]:
    return [
        {
            "path": snapshot.relative,
            "sha256": snapshot.sha256,
            "size": snapshot.size,
            "type": "file",
        }
        for snapshot in (snapshots[name] for name in sorted(snapshots))
    ]


def _validate_expected(value: object) -> dict[str, Any]:
    expected = require_exact_keys(
        value,
        {
            "checks",
            "document",
            "dmg_gatekeeper_sha256",
            "dmg_set_seal_sha256",
            "dmg_sha256",
            "from_build",
            "ga_environment_sha256",
            "install_journal_sha256",
            "product_version",
            "service_journal_tree_sha256",
            "to_build",
        },
        "GA runtime expected bindings",
    )
    if (
        expected["document"] != DOCUMENT
        or expected["checks"] != CHECKS
        or expected["product_version"] != PRODUCT_VERSION
        or expected["from_build"] != FROM_BUILD
        or expected["to_build"] != TO_BUILD
    ):
        raise _error(
            f"GA runtime expected identity or check set differs from {PRODUCT_VERSION}/{TO_BUILD}"
        )
    for field in (
        "dmg_gatekeeper_sha256",
        "dmg_set_seal_sha256",
        "dmg_sha256",
        "ga_environment_sha256",
        "install_journal_sha256",
        "service_journal_tree_sha256",
    ):
        try:
            require_sha256(expected[field], f"GA runtime {field}")
        except PublicationError as error:
            raise _error(f"GA runtime expected {field} is malformed") from error
    return expected


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise _error(f"{label} must be a UTC ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise _error(f"{label} is not ISO-8601") from error
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise _error(f"{label} must use UTC")
    return parsed


def _bounded_output(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > MAX_COMMAND_OUTPUT_BYTES
        or "\x00" in value
    ):
        raise _error(f"{label} is not bounded UTF-8 command output")
    return value


def _exit_description(value: object) -> str:
    """Name a command's exit status for an operator note; never raises."""

    if value is None:
        return "unavailable"
    if type(value) is not int:
        return f"not an integer ({type(value).__name__})"
    if value >= 0:
        return str(value)
    try:
        return f"{value} ({signal.Signals(-value).name})"
    except ValueError:
        return f"{value} (unknown signal)"


def _output_note(label: str, stream: str, value: object) -> str:
    """Describe the end of one command output stream for the operator.

    The credential patterns detect a credential but do not bound it: a PEM
    block matches only at its BEGIN line. A stream in which any pattern
    matches anywhere is therefore withheld whole, and the note gives only its
    size and why. It never raises: a receipt may hold any JSON value before
    validation.
    """

    if isinstance(value, str):
        data = value.encode("utf-8", errors="replace")
    elif isinstance(value, bytes):
        data = value
    else:
        return f"{label} {stream} is not text ({type(value).__name__})"
    if not data:
        return f"{label} {stream} is empty"
    if any(pattern.search(data) is not None for pattern in SECRET_PATTERNS):
        return (
            f"{label} {stream} ({len(data)} bytes) is withheld: it holds "
            "credential-like material"
        )
    return (
        f"{label} {stream} ({len(data)} bytes) ends with:\n"
        f"{escaped_tail(data, COMMAND_DIAGNOSTIC_TAIL_BYTES)}"
    )


def _command(
    value: object,
    *,
    expected_argv: list[str],
    expected_exit: int,
    label: str,
    maximum_seconds: int = MAX_COMMAND_SECONDS,
) -> dict[str, Any]:
    if (
        type(maximum_seconds) is not int
        or not 1 <= maximum_seconds <= DMG_BYTE_PROOF_TIMEOUT_SECONDS
    ):
        raise _error(f"{label} maximum command duration is invalid")
    receipt = require_exact_keys(
        value,
        {
            "argv",
            "document",
            "exit_code",
            "finished_at",
            "schema_version",
            "started_at",
            "stderr",
            "stdout",
        },
        label,
    )
    started = _timestamp(receipt["started_at"], f"{label}.started_at")
    finished = _timestamp(receipt["finished_at"], f"{label}.finished_at")
    seconds = (finished - started).total_seconds()
    failed = [
        check
        for check, rejected in (
            (
                "document",
                receipt["document"] != COMMAND_DOCUMENT
                or type(receipt["schema_version"]) is not int
                or receipt["schema_version"] != SCHEMA_VERSION,
            ),
            ("argv", receipt["argv"] != expected_argv),
            (
                "exit",
                type(receipt["exit_code"]) is not int
                or receipt["exit_code"] != expected_exit,
            ),
            ("duration", not started < finished or seconds > maximum_seconds),
        )
        if rejected
    ]
    if failed:
        # The message stays fixed; the notes name the failed checks and show
        # the operator the bounded end of each output that holds no
        # credential-like material.
        error = _error(f"{label} command identity, exit, or duration is invalid")
        error.add_note(
            f"{label} failed its {' and '.join(failed)} "
            f"check{'s' if len(failed) > 1 else ''}: exit status "
            f"{_exit_description(receipt['exit_code'])}, expected {expected_exit}; "
            f"duration {seconds:.3f} s, bound {maximum_seconds} s"
        )
        error.add_note(_output_note(label, "stdout", receipt["stdout"]))
        error.add_note(_output_note(label, "stderr", receipt["stderr"]))
        raise error
    _bounded_output(receipt["stdout"], f"{label}.stdout")
    _bounded_output(receipt["stderr"], f"{label}.stderr")
    return receipt


def _check_document(value: object, check_id: str, fields: set[str]) -> dict[str, Any]:
    document = require_exact_keys(
        value,
        {"check_id", "collection", "document", "schema_version", *fields},
        f"{check_id} evidence",
    )
    if (
        document["document"] != CHECK_DOCUMENT
        or type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
        or document["check_id"] != check_id
    ):
        raise _error(f"{check_id} evidence identity is invalid")
    _collection_binding(document["collection"], f"{check_id} collection")
    return document


def _canonical_challenge(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise _error(f"{label} challenge is malformed")
    try:
        challenge = base64.urlsafe_b64decode(value + "==")
    except (ValueError, TypeError) as error:
        raise _error(f"{label} challenge is not base64url") from error
    if (
        len(challenge) != 32
        or base64.urlsafe_b64encode(challenge).decode("ascii").rstrip("=")
        != value
    ):
        raise _error(f"{label} challenge is not one canonical 256-bit value")
    return value


def _collection_binding(value: object, label: str) -> dict[str, str]:
    binding = require_exact_keys(
        value,
        {"challenge", "ga_environment_sha256", "session_id"},
        label,
    )
    try:
        session = str(uuid.UUID(binding["session_id"]))
    except (AttributeError, TypeError, ValueError) as error:
        raise _error(f"{label} session is not one canonical UUID") from error
    if session != binding["session_id"]:
        raise _error(f"{label} identity is malformed")
    challenge = _canonical_challenge(binding["challenge"], label)
    try:
        ga_environment_sha256 = require_sha256(
            binding["ga_environment_sha256"],
            f"{label} GA environment",
        )
    except PublicationError as error:
        raise _error(f"{label} GA environment digest is malformed") from error
    return {
        "challenge": challenge,
        "ga_environment_sha256": ga_environment_sha256,
        "session_id": session,
    }


def _derive_capture_token(challenge: str, check_id: str, stage: str) -> str:
    normalized_challenge = _canonical_challenge(
        challenge,
        "capture token challenge",
    )
    prefix = {"start": "s000", "target": "t000", "end": "e000"}.get(stage)
    if check_id not in TRAFFIC_CHECKS or prefix is None:
        raise _error("capture token domain is not source-owned")
    material = base64.urlsafe_b64decode(normalized_challenge + "==")
    digest = hashlib.sha256(
        b"cfm-ga-runtime-capture-token-v1\0"
        + check_id.encode("ascii")
        + b"\0"
        + stage.encode("ascii")
        + b"\0"
        + material
    ).hexdigest()[:32]
    return f"{prefix}-{digest}"


def _packet_host_snapshot_document(snapshot: PacketHostSnapshot) -> dict[str, Any]:
    return {
        "config_digest": snapshot.config_digest,
        "desired_mode": snapshot.desired_mode,
        "generation": snapshot.generation,
        "ipv6_enabled": snapshot.ipv6_enabled,
        "owner": snapshot.owner,
        "phase": snapshot.phase,
        "ready": snapshot.ready,
    }


def _packet_host_receipt_document(receipt: PacketHostReceipt) -> dict[str, Any]:
    return {
        "baseline": _packet_host_snapshot_document(receipt.baseline),
        "baseline_observation_sequence": receipt.baseline_observation_sequence,
        "candidate_observation_sequence": receipt.candidate_observation_sequence,
        "case_id": receipt.case_id,
        "document": PACKET_HOST_DOCUMENT,
        "restore": _packet_host_snapshot_document(receipt.restore),
        "restore_observation_sequence": receipt.restore_observation_sequence,
        "schema_version": PACKET_HOST_SCHEMA_VERSION,
        "sequence": 8,
        "session_id": receipt.session_id,
        "test": _packet_host_snapshot_document(receipt.test),
        "test_observation_sequence": receipt.test_observation_sequence,
    }


def _packet_host_snapshot(
    value: object,
    *,
    label: str,
    expected_phase: str,
) -> dict[str, Any]:
    snapshot = require_exact_keys(
        value,
        {
            "config_digest",
            "desired_mode",
            "generation",
            "ipv6_enabled",
            "owner",
            "phase",
            "ready",
        },
        label,
    )
    if type(snapshot["generation"]) is not int or snapshot["generation"] <= 0:
        raise _error(f"{label} generation is invalid")
    if expected_phase == "off":
        if snapshot != {
            "config_digest": None,
            "desired_mode": "off",
            "generation": snapshot["generation"],
            "ipv6_enabled": False,
            "owner": None,
            "phase": "off",
            "ready": False,
        }:
            raise _error(f"{label} is not an exact product-owned Off observation")
        return snapshot
    digest = snapshot["config_digest"]
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or snapshot["desired_mode"] != "tunnel"
        or snapshot["ipv6_enabled"] is not True
        or snapshot["owner"] != "packet_tunnel_system_extension"
        or snapshot["phase"] != "tunnel_active"
        or snapshot["ready"] is not True
    ):
        raise _error(f"{label} is not an exact ready Packet Tunnel observation")
    return snapshot


def _packet_host_receipt(
    value: object,
    *,
    expected_case_id: str,
    expected_test_phase: str,
) -> dict[str, Any]:
    receipt = require_exact_keys(
        value,
        {
            "baseline",
            "baseline_observation_sequence",
            "candidate_observation_sequence",
            "case_id",
            "document",
            "restore",
            "restore_observation_sequence",
            "schema_version",
            "sequence",
            "session_id",
            "test",
            "test_observation_sequence",
        },
        f"{expected_case_id} authenticated Packet Host receipt",
    )
    baseline = _packet_host_snapshot(
        receipt["baseline"],
        label=f"{expected_case_id} baseline",
        expected_phase="tunnel_active",
    )
    test = _packet_host_snapshot(
        receipt["test"],
        label=f"{expected_case_id} test",
        expected_phase=expected_test_phase,
    )
    restore = _packet_host_snapshot(
        receipt["restore"],
        label=f"{expected_case_id} restore",
        expected_phase="tunnel_active",
    )
    integer_fields = (
        "baseline_observation_sequence",
        "candidate_observation_sequence",
        "restore_observation_sequence",
        "test_observation_sequence",
    )
    if (
        receipt["document"] != PACKET_HOST_DOCUMENT
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != PACKET_HOST_SCHEMA_VERSION
        or type(receipt["sequence"]) is not int
        or receipt["sequence"] != 8
        or receipt["case_id"] != expected_case_id
        or not isinstance(receipt["session_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", receipt["session_id"]) is None
        or any(type(receipt[field]) is not int or receipt[field] <= 0 for field in integer_fields)
        or receipt["candidate_observation_sequence"]
        != receipt["test_observation_sequence"]
        or not (
            receipt["baseline_observation_sequence"]
            < receipt["test_observation_sequence"]
            < receipt["restore_observation_sequence"]
        )
        or not (
            baseline["generation"] < test["generation"] < restore["generation"]
        )
        or baseline["config_digest"] != restore["config_digest"]
        or (
            expected_test_phase == "tunnel_active"
            and test["config_digest"] == baseline["config_digest"]
        )
    ):
        raise _error(f"{expected_case_id} authenticated Packet Host receipt is inconsistent")
    return receipt


def _installed_candidate_tree(repository: Path, expected: dict[str, Any]) -> str:
    path = repository.joinpath(*INSTALL_JOURNAL_RELATIVE.parts)
    _private_regular_metadata(path)
    try:
        data = read_regular(path, MAX_JSON_BYTES)
    except PublicationError as error:
        raise _error("GA install journal cannot be reopened safely") from error
    if sha256_bytes(data) != expected["install_journal_sha256"]:
        raise _error("GA install journal differs from the runtime binding")
    journal = _strict_json(data, "GA install journal")
    try:
        normalized = dormant_app_install.validate_journal(
            journal,
            dormant_app_install.GA_INSTALL_PROFILE,
        )
    except dormant_app_install.InstallError as error:
        raise _error("GA install journal is invalid") from error
    if (
        normalized["phase"] != "installed"
        or normalized["candidate"]["build_number"] != TO_BUILD
        or normalized["previous"]["build_number"] != FROM_BUILD
    ):
        raise _error(
            f"GA install journal is not the completed {FROM_BUILD} to {TO_BUILD} install"
        )
    try:
        installed = dormant_app_install.read_app_identity(INSTALLED_APP)
    except dormant_app_install.InstallError as error:
        raise _error(f"installed {TO_BUILD} application tree cannot be identified") from error
    # The journal's candidate also binds its manifest, source and commit, which
    # the installed bundle cannot show; compare the application identity only.
    if installed != dormant_app_install._candidate_from_journal(normalized).app:
        raise _error("installed application bytes differ from the closed install journal")
    return installed.tree_sha256


def _installed_guard_baseline(
    repository: Path, expected: dict[str, Any]
) -> dict[str, Any]:
    path = repository.joinpath(*INSTALL_JOURNAL_RELATIVE.parts)
    _private_regular_metadata(path)
    data = read_regular(path, MAX_JSON_BYTES)
    if sha256_bytes(data) != expected["install_journal_sha256"]:
        raise _error("GA install journal changed before guard binding")
    try:
        journal = dormant_app_install.validate_journal(
            _strict_json(data, "GA install journal guard binding"),
            dormant_app_install.GA_INSTALL_PROFILE,
        )
    except dormant_app_install.InstallError as error:
        raise _error("GA install journal guard binding is invalid") from error
    guards = journal["guards"]
    if not isinstance(guards, list) or not guards:
        raise _error("GA install journal has no CFW guard lineage")
    baseline = _guard(guards[0]["before"], "install journal baseline")
    for segment in guards:
        before = _guard(segment["before"], "install journal before")
        after = _guard(segment["after"], "install journal after")
        try:
            dormant_app_install._assert_guard_unchanged(baseline, before)
            dormant_app_install._assert_guard_unchanged(before, after)
        except dormant_app_install.InstallError as error:
            raise _error("GA install journal CFW guard lineage drifted") from error
    return baseline


def _dmg_contained_candidate_tree(
    repository: Path,
    expected: dict[str, Any],
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> str:
    from scripts import release_artifact_set

    try:
        seal = release_artifact_set.verify_dmg_set(
            repository.joinpath(*DMG_SET_RELATIVE.parts),
            repository=repository,
            version=PRODUCT_VERSION,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
    except (OSError, ValueError, release_artifact_set.ArtifactSetError) as error:
        raise _error("DMG byte-proof verification failed") from error
    candidate = require_exact_keys(
        seal["candidate_app"],
        {
            "build_number",
            "manifest",
            "path",
            "signed_app_tree_sha256",
            "tree_algorithm",
        },
        "DMG candidate app binding",
    )
    if (
        seal["artifacts"]["dmg"]["sha256"] != expected["dmg_sha256"]
        or candidate["build_number"] != TO_BUILD
        or candidate["tree_algorithm"] != "sha256-tree-v2"
    ):
        raise _error("DMG byte-proof binds different package or application bytes")
    return require_sha256(
        candidate["signed_app_tree_sha256"], "DMG-contained app tree"
    )


def _dmg_gatekeeper_observation(value: object) -> dict[str, Any]:
    gatekeeper = _command(
        value,
        expected_argv=list(DMG_GATEKEEPER_COMMAND),
        expected_exit=0,
        label="DMG Gatekeeper observation",
    )
    gatekeeper_output = gatekeeper["stdout"] + gatekeeper["stderr"]
    if "accepted" not in gatekeeper_output or "Notarized Developer ID" not in gatekeeper_output:
        raise _error("raw DMG Gatekeeper output is not notarized acceptance")
    return gatekeeper


def _dmg_verifier_observation(
    value: object, *, repository: Path, operator_root: Path
) -> dict[str, Any]:
    verification = _command(
        value,
        expected_argv=_dmg_verifier_command(operator_root, repository),
        expected_exit=0,
        label="DMG contained-app byte-proof observation",
        maximum_seconds=DMG_BYTE_PROOF_TIMEOUT_SECONDS,
    )
    if (
        verification["stdout"]
        != f"DMG release set verified: {repository / DMG_SET_RELATIVE}\n"
        or verification["stderr"]
    ):
        raise _error("raw DMG verifier output is not the fixed byte-proof result")
    return verification


def _validate_exact_dmg_install(
    value: dict[str, Any],
    repository: Path,
    expected: dict[str, Any],
    prepackage_stage_verifier: PrepackageStageVerifier,
    operator_root: Path,
) -> None:
    document = _check_document(
        value,
        "exact_dmg_install",
        {
            "bindings",
            "commands",
            "dmg_contained_app_tree_sha256",
            "installed_app_tree_sha256",
        },
    )
    bindings = require_exact_keys(
        document["bindings"],
        {
            "dmg_gatekeeper_sha256",
            "dmg_set_seal_sha256",
            "dmg_sha256",
            "install_journal_sha256",
            "service_journal_tree_sha256",
        },
        "exact DMG install bindings",
    )
    expected_bindings = {
        key: expected[key]
        for key in (
            "dmg_gatekeeper_sha256",
            "dmg_set_seal_sha256",
            "dmg_sha256",
            "install_journal_sha256",
            "service_journal_tree_sha256",
        )
    }
    if bindings != expected_bindings:
        raise _error("exact DMG install binds a different package or journal")
    installed_tree = _installed_candidate_tree(repository, expected)
    dmg_tree = _dmg_contained_candidate_tree(
        repository,
        expected,
        prepackage_stage_verifier,
    )
    if (
        document["dmg_contained_app_tree_sha256"] != dmg_tree
        or document["installed_app_tree_sha256"] != installed_tree
        or dmg_tree != installed_tree
    ):
        raise _error(
            f"DMG-contained app and installed {TO_BUILD} app are not the same tree"
        )
    commands = require_exact_keys(
        document["commands"],
        {"dmg_gatekeeper", "dmg_set_verify"},
        "DMG install commands",
    )
    _dmg_gatekeeper_observation(commands["dmg_gatekeeper"])
    _dmg_verifier_observation(
        commands["dmg_set_verify"], repository=repository, operator_root=operator_root
    )


def _running_host_observation(value: object) -> list[dict[str, Any]]:
    receipt = _command(
        value,
        expected_argv=list(PROCESS_OBSERVATION_COMMAND),
        expected_exit=0,
        label="process-table observation",
    )
    try:
        processes = dormant_app_install._parse_processes(receipt["stdout"])
    except dormant_app_install.InstallError as error:
        raise _error("raw process-table output is malformed") from error
    app_processes = [
        item for item in processes if item["path"] == INSTALLED_EXECUTABLE.as_posix()
    ]
    message = f"raw process table does not contain exactly one installed {TO_BUILD} Host"
    if not app_processes:
        # A launched Host can still be starting; a second one never resolves.
        raise ObservationNotReady(message)
    if len(app_processes) != 1:
        raise _error(message)
    return processes


def _host_absence_observation(value: object) -> list[dict[str, Any]]:
    receipt = _command(
        value,
        expected_argv=list(PROCESS_OBSERVATION_COMMAND),
        expected_exit=0,
        label="installed Host shutdown process-table observation",
    )
    try:
        processes = dormant_app_install._parse_processes(receipt["stdout"])
    except dormant_app_install.InstallError as error:
        raise _error("raw installed Host shutdown process table is malformed") from error
    if any(
        process["path"] == INSTALLED_EXECUTABLE.as_posix() for process in processes
    ):
        raise _error(
            f"normal shutdown evidence still contains the installed {TO_BUILD} Host"
        )
    return processes


def _launch_command_observation(value: object) -> dict[str, Any]:
    launch = _command(
        value,
        expected_argv=list(LAUNCH_COMMAND),
        expected_exit=0,
        label=f"installed {TO_BUILD} launch command",
    )
    if launch["stderr"]:
        raise _error(f"installed {TO_BUILD} launch command emitted an error")
    return launch


def _validate_launch(value: dict[str, Any]) -> None:
    document = _check_document(
        value, "launch", {"launch_command", "process_observation"}
    )
    _launch_command_observation(document["launch_command"])
    _running_host_observation(document["process_observation"])


def _require_launchctl_running(
    output: str,
    program: Path,
    label: str,
    *,
    service_label: str,
) -> None:
    """Require the real launchd contract for the registered SMAppService job.

    Both services are registered from the signed application bundle and declare
    `BundleProgram`, so launchd resolves the executable inside that bundle and
    reports a bundle-relative `program identifier` with resolution `mode: 2`
    plus the owning bundle and code-signing identity. It never reports the
    absolute `program` line that only an absolute-`Program` job produces.

    This is the same fixed job contract the release service transaction already
    proves in `current_service_transaction._registered_job_pid`, and it binds
    strictly more than an absolute path: the running executable is the one
    inside the installed active GA bundle, registered through ServiceManagement,
    and signed under the fixed team and service identifiers.
    """

    try:
        relative = program.relative_to(INSTALLED_APP)
    except ValueError as error:
        raise _error(
            f"fixed {label} executable is outside the installed {TO_BUILD} bundle"
        ) from error
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    required = (
        "managed_by = com.apple.xpc.ServiceManagement",
        "state = running",
        f"program identifier = {relative.as_posix()} (mode: 2)",
        f"parent bundle identifier = {APP_BUNDLE_ID}",
        f"parent bundle version = {TO_BUILD}",
        f'"signing-identifier" => "{service_label}"',
        f'"team-identifier" => "{TEAM_ID}"',
    )
    missing = [value for value in required if lines.count(value) != 1]
    if not missing:
        return
    message = f"raw launchctl output does not show the fixed running {label}"
    # launchd lists an on-demand MachService job before it first spawns it;
    # any other difference from the fixed job never resolves by waiting.
    if missing == ["state = running"] and "state = running" not in lines:
        raise ObservationNotReady(message)
    raise _error(message)


def _proxy_agent_print_command(uid: int) -> list[str]:
    return ["/bin/launchctl", "print", f"gui/{uid}/{PROXY_LABEL}"]


def _require_proxy_agent_running(receipt: dict[str, Any]) -> None:
    _require_launchctl_running(
        receipt["stdout"],
        PROXY_EXECUTABLE,
        "ProxyAgent",
        service_label=PROXY_LABEL,
    )


def _require_global_authority_running(receipt: dict[str, Any]) -> None:
    _require_launchctl_running(
        receipt["stdout"],
        AUTHORITY_EXECUTABLE,
        "GlobalAuthority",
        service_label=AUTHORITY_LABEL,
    )


def _validate_service_registration(value: dict[str, Any]) -> None:
    document = _check_document(value, "service_registration", {"commands"})
    commands = require_exact_keys(
        document["commands"], {"global_authority", "proxy_agent"}, "service commands"
    )
    proxy = _command(
        commands["proxy_agent"],
        expected_argv=_proxy_agent_print_command(os.geteuid()),
        expected_exit=0,
        label="ProxyAgent launchctl observation",
    )
    authority = _command(
        commands["global_authority"],
        expected_argv=list(AUTHORITY_PRINT_COMMAND),
        expected_exit=0,
        label="GlobalAuthority launchctl observation",
    )
    _require_proxy_agent_running(proxy)
    _require_global_authority_running(authority)


def _retained_packet_extension_build(version: str) -> int:
    short_version, separator, build = version.partition("/")
    malformed = "another Packet Tunnel registration has a malformed version"
    if not separator or PACKET_EXTENSION_SHORT_VERSION_RE.fullmatch(short_version) is None:
        raise _error(malformed)
    try:
        return int(canonical_build_version(build, "retained Packet Tunnel build"))
    except BuildIdentityError as error:
        raise _error(malformed) from error


def _system_extension_observation(value: object) -> dict[str, Any]:
    receipt = _command(
        value,
        expected_argv=list(SYSTEM_EXTENSION_COMMAND),
        expected_exit=0,
        label="system extension observation",
    )
    try:
        registrations = dormant_app_install.parse_system_extension_registrations(
            receipt["stdout"]
        )
    except dormant_app_install.InstallError as error:
        raise _error("raw systemextensionsctl output is malformed") from error
    packet_tunnels = [
        registration
        for registration in registrations
        if registration.bundle_id == PACKET_EXTENSION_BUNDLE_ID
    ]
    if any(registration.team_id != TEAM_ID for registration in packet_tunnels):
        raise _error("raw system extension output lists a foreign-team Packet Tunnel")
    # The parser rejects a repeated team/bundle/version, so this fails only
    # when no row carries the candidate version.
    candidates = [
        registration
        for registration in packet_tunnels
        if registration.version == PACKET_EXTENSION_VERSION
    ]
    if len(candidates) != 1:
        raise _error(f"raw system extension output lacks the fixed {TO_BUILD} extension")
    candidate = candidates[0]
    if not (
        candidate.enabled
        and candidate.active
        and candidate.state == PACKET_EXTENSION_ACTIVE_STATE
    ):
        raise _error("fixed system extension is not both activated and enabled")
    retained = [
        registration for registration in packet_tunnels if registration is not candidate
    ]
    # macOS leaves both flag columns empty on a retained row.
    if any(
        registration.enabled
        or registration.active
        or registration.state != PACKET_EXTENSION_RETAINED_STATE
        for registration in retained
    ):
        raise _error(
            "another Packet Tunnel registration is not terminated and waiting to "
            "uninstall on reboot"
        )
    if any(
        _retained_packet_extension_build(registration.version) >= int(TO_BUILD)
        for registration in retained
    ):
        raise _error(
            f"another Packet Tunnel registration is not an earlier build than {TO_BUILD}"
        )
    return receipt


def _validate_system_extension(value: dict[str, Any]) -> None:
    document = _check_document(value, "system_extension", {"command"})
    _system_extension_observation(document["command"])


def _validate_network_extension(
    value: dict[str, Any],
    documents: dict[str, dict[str, Any]],
) -> None:
    document = _check_document(value, "network_extension", {"traffic_bindings"})
    bindings = require_exact_keys(
        document["traffic_bindings"],
        set(TRAFFIC_CHECKS),
        "network extension traffic bindings",
    )
    for check_id in TRAFFIC_CHECKS:
        filename = f"{check_id.replace('_', '-')}.json"
        traffic = documents[filename]
        binding = require_exact_keys(
            bindings[check_id],
            {"case_id", "host_observation_sha256"},
            f"{check_id} network extension binding",
        )
        host_observation = traffic.get("host_observation")
        _packet_host_receipt(
            host_observation,
            expected_case_id=TRAFFIC_POLICY[check_id]["case_id"],
            expected_test_phase="tunnel_active",
        )
        if binding != {
            "case_id": TRAFFIC_POLICY[check_id]["case_id"],
            "host_observation_sha256": sha256_bytes(canonical_json(host_observation)),
        }:
            raise _error(
                f"{check_id} does not bind its authenticated Packet Tunnel observation"
            )


def _high_risk_rejection_observation(
    value: object, probe: tuple[str, tuple[str, ...], int, str]
) -> dict[str, Any]:
    probe_id, argv, exit_code, expected_stderr = probe
    receipt = _command(
        value,
        expected_argv=list(argv),
        expected_exit=exit_code,
        label=f"{probe_id} rejection observation",
    )
    if receipt["stdout"] or receipt["stderr"] != expected_stderr:
        raise _error(f"{probe_id} did not produce the fixed candidate rejection")
    return receipt


def _validate_high_risk_rejections(value: dict[str, Any]) -> None:
    document = _check_document(value, "high_risk_rejections", {"observations"})
    observations = document["observations"]
    if not isinstance(observations, list) or len(observations) != len(HIGH_RISK_PROBES):
        raise _error("high-risk rejection evidence must contain every fixed denial")
    for observation, probe in zip(observations, HIGH_RISK_PROBES, strict=True):
        _high_risk_rejection_observation(observation, probe)


def _guard(value: object, label: str) -> dict[str, Any]:
    try:
        return dormant_app_install._validate_guard(value)
    except dormant_app_install.InstallError as error:
        raise _error(f"{label} CFW guard is malformed") from error


def _validate_off_proof_receipt(value: object, *, label: str) -> dict[str, Any]:
    off_proof = _command(
        value,
        expected_argv=list(OFF_PROOF_COMMAND),
        expected_exit=0,
        label=label,
    )
    try:
        receipt = dormant_app_install.parse_service_maintenance_receipt(
            dormant_app_install.CommandResult(
                returncode=off_proof["exit_code"],
                stdout=off_proof["stdout"],
                stderr=off_proof["stderr"],
            ),
            "prove-off",
        )
    except dormant_app_install.InstallError as error:
        raise _error("signed installed Host did not prove the candidate globally Off") from error
    if receipt["global_authority"] != "enabled" or receipt["proxy_agent"] != "enabled":
        raise _error("signed installed Host Off proof lost the recommissioned service pair")
    return off_proof


def _validate_shutdown_restore(value: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    document = _check_document(
        value,
        "shutdown_restore",
        {
            "after_guard",
            "before_guard",
            "host_process_observation",
            "off_proof_command",
            "process_observation",
            "shutdown_request",
            "stop_restore_observation",
        },
    )
    before = _guard(document["before_guard"], "shutdown before")
    after = _guard(document["after_guard"], "shutdown after")
    try:
        dormant_app_install._assert_guard_unchanged(before, after)
    except dormant_app_install.InstallError as error:
        raise _error("shutdown did not restore the exact pre-run CFW state") from error
    stop_restore = _packet_host_receipt(
        document["stop_restore_observation"],
        expected_case_id="stop-cleanup",
        expected_test_phase="off",
    )
    if stop_restore["baseline"]["config_digest"] != stop_restore["restore"][
        "config_digest"
    ]:
        raise _error("candidate stop/restore did not return to its exact tunnel baseline")
    # The request records the fixed instruction that was issued, not the quit
    # control that was used: no quit leaves a receipt. What this evidence
    # proves is that the Host exited, then one independent signed Off proof
    # and the exact CFW guard restoration followed.
    request = require_exact_keys(
        document["shutdown_request"],
        {"instruction", "kind"},
        "candidate shutdown request",
    )
    if request != OPERATOR_QUIT_REQUEST:
        raise _error(
            "candidate shutdown request is not the fixed operator quit instruction"
        )
    host_process = _command(
        document["host_process_observation"],
        expected_argv=list(PROCESS_OBSERVATION_COMMAND),
        expected_exit=0,
        label="installed Host shutdown process-table observation",
    )
    _host_absence_observation(document["host_process_observation"])
    off_proof = _validate_off_proof_receipt(
        document["off_proof_command"],
        label="candidate signed Host Off proof",
    )
    process = _command(
        document["process_observation"],
        expected_argv=list(PROCESS_OBSERVATION_COMMAND),
        expected_exit=0,
        label="final installed Host process-table observation",
    )
    _host_absence_observation(document["process_observation"])
    if not (
        timestamp_fraction(host_process["started_at"])
        <= timestamp_fraction(host_process["finished_at"])
        <= timestamp_fraction(off_proof["started_at"])
        <= timestamp_fraction(off_proof["finished_at"])
        <= timestamp_fraction(process["started_at"])
        <= timestamp_fraction(process["finished_at"])
    ):
        raise _error(
            "candidate shutdown, Off proof, and Host process observations are not causal"
        )
    return before, after


def _validate_legacy_cfw(
    value: dict[str, Any],
    repository: Path,
    expected: dict[str, Any],
    shutdown_guards: tuple[dict[str, Any], dict[str, Any]],
    intent: dict[str, Any],
) -> None:
    document = _check_document(
        value,
        "legacy_cfw_preserved",
        {
            "after_guard",
            "before_guard",
            "install_journal_sha256",
            "service_journal_tree_sha256",
        },
    )
    before = _guard(document["before_guard"], "legacy CFW before")
    after = _guard(document["after_guard"], "legacy CFW after")
    if (
        document["install_journal_sha256"] != expected["install_journal_sha256"]
        or document["service_journal_tree_sha256"]
        != expected["service_journal_tree_sha256"]
        or (before, after) != shutdown_guards
    ):
        raise _error("legacy CFW preservation is not bound to the exact install/runtime run")
    baseline = _collection_guard_baseline(repository, intent, expected)
    if before != baseline:
        raise _error("runtime CFW baseline differs from the durable collection intent")
    try:
        dormant_app_install._assert_guard_unchanged(before, after)
    except dormant_app_install.InstallError as error:
        raise _error(
            "legacy Clash for Windows state changed during GA runtime acceptance"
        ) from error


def _traffic_descriptor(
    value: object, *, expected_name: str, snapshot: FileSnapshot
) -> dict[str, Any]:
    descriptor = require_exact_keys(
        value, {"kind", "path", "sha256", "size"}, "traffic capture descriptor"
    )
    if descriptor != {
        "kind": "packet-pcap",
        "path": expected_name,
        "sha256": snapshot.sha256,
        "size": snapshot.size,
    }:
        raise _error("traffic capture descriptor differs from reopened pcap bytes")
    return descriptor


def _dns_endpoint(value: object, check_id: str) -> dict[str, Any]:
    """Return the tunnel DNS endpoint: its interface and each stage's leg.

    A stage's query and answer may use either tunnel leg, so the endpoint
    records the family each stage used instead of one family and address
    pair; TUNNEL_DNS_LEGS fixes both legs' addresses. The check document keeps
    its version: its exact key set rejects the former single-family endpoint.
    """

    endpoint = require_exact_keys(
        value,
        {"interface_name", "link_type", "remote_port", "stage_families"},
        f"{check_id} endpoint",
    )
    stage_families = require_exact_keys(
        endpoint["stage_families"], set(PACKET_STAGES), f"{check_id} stage families"
    )
    if (
        any(family not in ("ipv4", "ipv6") for family in stage_families.values())
        or type(endpoint["remote_port"]) is not int
        or endpoint["remote_port"] != TRAFFIC_POLICY[check_id]["remote_port"]
        or type(endpoint["link_type"]) is not int
        or endpoint["link_type"] not in ALLOWED_LINK_TYPES
        or not isinstance(endpoint["interface_name"], str)
        or INTERFACE_RE.fullmatch(endpoint["interface_name"]) is None
    ):
        raise _error(f"{check_id} endpoint differs from the fixed capture policy")
    return endpoint


def _tunnel_dns_stage_endpoints(
    check_id: str, capture: bytes, tokens: dict[str, str]
) -> tuple[StagedCaptureEndpoint, StagedCaptureEndpoint, StagedCaptureEndpoint]:
    """Derive each stage's tunnel DNS tuple, on either leg, from the capture.

    Each is the tuple of the stage's first answered query; every record must
    be a query or answer of one of the tokens. Collection and verification
    both derive them here, so both name a failure alike.
    """

    try:
        return dns_resolver_leg_stage_endpoints(
            capture,
            "packet-pcap",
            family=TUNNEL_DNS_QUESTION_FAMILY,
            legs=TUNNEL_DNS_LEGS,
            tokens=tuple(tokens[stage].encode("ascii") for stage in PACKET_STAGES),
            retransmissions=TRAFFIC_POLICY[check_id]["retransmissions"],
        )
    except PacketCaptureError as error:
        raise _error(f"{check_id} DNS capture endpoints are invalid") from error


def _stage_families(
    endpoints: tuple[StagedCaptureEndpoint, StagedCaptureEndpoint, StagedCaptureEndpoint],
) -> dict[str, str]:
    """Name the IP family of the tunnel leg of each stage's first answered query."""

    return {
        endpoint.stage: (
            "ipv4"
            if ipaddress.ip_address(endpoint.local_address).version == 4
            else "ipv6"
        )
        for endpoint in endpoints
    }


def _endpoint(value: object, check_id: str) -> dict[str, Any]:
    if TRAFFIC_POLICY[check_id]["protocol"] == "dns":
        return _dns_endpoint(value, check_id)
    endpoint = require_exact_keys(
        value,
        {
            "family",
            "interface_name",
            "link_type",
            "local_address",
            "remote_address",
            "remote_port",
        },
        f"{check_id} endpoint",
    )
    policy = TRAFFIC_POLICY[check_id]
    try:
        ipaddress.ip_address(endpoint["local_address"])
        ipaddress.ip_address(endpoint["remote_address"])
    except (TypeError, ValueError) as error:
        raise _error(f"{check_id} endpoint address is invalid") from error
    # Collection records the tunnel client and the policy peer as these exact
    # strings; another spelling of either address is not the captured tuple.
    if (
        endpoint["family"] != "ipv4"
        or endpoint["local_address"] != TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"]
        or endpoint["remote_address"] != policy["remote_address"]
        or type(endpoint["remote_port"]) is not int
        or endpoint["remote_port"] != policy["remote_port"]
        or type(endpoint["link_type"]) is not int
        or endpoint["link_type"] not in ALLOWED_LINK_TYPES
        or not isinstance(endpoint["interface_name"], str)
        or INTERFACE_RE.fullmatch(endpoint["interface_name"]) is None
    ):
        raise _error(f"{check_id} endpoint differs from the fixed capture policy")
    return endpoint


def _packet_sender_argv(
    interpreter: str,
    *,
    check_id: str,
    stage: str,
    token: str,
    local_address: str,
) -> list[str]:
    policy = TRAFFIC_POLICY[check_id]
    command = [
        interpreter,
        *PACKET_SENDER_COMMAND,
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
        command.extend(
            [
                "--local-address",
                local_address,
                "--local-port",
                "0",
                "--remote-address",
                policy["remote_address"],
                "--remote-port",
                str(policy["remote_port"]),
            ]
        )
    command.extend(
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
    return command


def _packet_send_result(
    receipt: dict[str, Any],
    *,
    check_id: str,
    stage: str,
    token: str,
    local_address: str,
) -> dict[str, Any]:
    result = _strict_json(
        receipt["stdout"].encode("utf-8"),
        f"{check_id} {stage} packet sender output",
    )
    result = require_exact_keys(
        result,
        {
            "bytes_submitted",
            "case_id",
            "dns_result",
            "document",
            "local_address",
            "local_port",
            "remote_address",
            "remote_port",
            "schema_version",
            "stage",
            "token_sha256",
            "transport",
        },
        f"{check_id} {stage} packet sender output",
    )
    policy = TRAFFIC_POLICY[check_id]
    expected_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    if (
        result["document"] != PACKET_SEND_DOCUMENT
        or type(result["schema_version"]) is not int
        or result["schema_version"] != 2
        or result["case_id"] != policy["case_id"]
        or result["stage"] != stage
        or result["token_sha256"] != expected_digest
        or type(result["bytes_submitted"]) is not int
        or result["bytes_submitted"] != len(token)
        or result["transport"]
        != ("resolver" if policy["protocol"] == "dns" else policy["protocol"])
    ):
        raise _error(f"{check_id} {stage} sender receipt identity is invalid")
    if policy["protocol"] == "dns":
        dns = require_exact_keys(
            result["dns_result"],
            {"query", "requested_type", "resolver_role", "trigger"},
            f"{check_id} {stage} DNS sender result",
        )
        query = require_exact_keys(
            dns["query"], {"addresses", "name", "token_sha256"}, "DNS query result"
        )
        if (
            result["local_address"] is not None
            or result["local_port"] is not None
            or result["remote_address"] is not None
            or result["remote_port"] is not None
            or dns["trigger"] != "getaddrinfo"
            or dns["resolver_role"] != "primary"
            or dns["requested_type"] != "A"
            or query["name"] != f"{token}.evidence.test"
            or query["token_sha256"] != expected_digest
        ):
            raise _error(f"{check_id} {stage} DNS result is incomplete")
        if query["addresses"] != [DNS_A_ADDRESS]:
            raise _error(
                f"{check_id} {stage} getaddrinfo did not return the evidence answer"
            )
    else:
        if (
            result["dns_result"] is not None
            or result["local_address"] != local_address
            or type(result["local_port"]) is not int
            or not 1 <= result["local_port"] <= 65535
            or result["remote_address"] != policy["remote_address"]
            or result["remote_port"] != policy["remote_port"]
        ):
            raise _error(f"{check_id} {stage} socket receipt is incomplete")
    return result


def _tokens(value: object, check_id: str) -> dict[str, str]:
    tokens = require_exact_keys(value, {"end", "start", "target"}, f"{check_id} tokens")
    if any(
        not isinstance(item, str) or TOKEN_RE.fullmatch(item) is None
        for item in tokens.values()
    ):
        raise _error(f"{check_id} tokens are not bounded unique evidence tokens")
    if len(set(tokens.values())) != 3:
        raise _error(f"{check_id} reuses a capture token")
    return tokens


def _traffic_capture_filter_argv(
    check_id: str, tokens: dict[str, str]
) -> tuple[str, ...]:
    """Return the one BPF expression used to collect and to re-verify a check."""

    policy = TRAFFIC_POLICY[check_id]
    ordered = tuple(tokens[stage] for stage in PACKET_STAGES)
    if policy["protocol"] != "dns":
        return packet_capture_filter_argv(case_id=policy["case_id"], tokens=ordered)
    if any(DNS_EVIDENCE_LABEL_RE.fullmatch(token) is None for token in ordered):
        raise _error(f"{check_id} tokens are not single DNS evidence labels")

    def word(token: str, start: int) -> int:
        return int.from_bytes(token.encode("ascii")[start : start + 4], "big")

    # Label offsets 0 (stage prefix), 5 and 9 (first eight digest characters).
    labels = tuple(
        (len(token), word(token, 0), word(token, 5), word(token, 9))
        for token in ordered
    )
    if len({prefix for _length, prefix, _head, _tail in labels}) != len(labels):
        raise _error(f"{check_id} token BPF prefixes are not unique")
    port = policy["remote_port"]
    # Every system lookup uses these resolvers, so admit only DNS messages
    # whose first QNAME label matches one of this collection's tokens in its
    # length (after the 8-byte UDP and 12-byte DNS headers), stage prefix
    # (label + 1) and first eight digest characters (label + 6 and label + 10;
    # label + 5 is the "-"). libpcap's udp[] indexes only IPv4, so the IPv6
    # leg loads the label at ip6[60], behind the fixed 40-byte header, and
    # requires UDP as its next header: a datagram behind an IPv6 extension
    # header does not match. The query type, the other 24 digest characters
    # and the rest of the name are not filtered, so a non-A query or a
    # retransmission for a token name, on either leg, also passes; validation
    # then admits only exact A queries and authoritative answers of the
    # tokens, repeated identically, and fails closed on any other record.
    ipv4_leg, ipv6_leg = TUNNEL_DNS_LEGS
    clauses = []
    for leg, selector, layer, label in (
        (ipv4_leg, "udp", "udp", 20),
        (ipv6_leg, "ip6 and ip6[6] = 17", "ip6", 60),
    ):
        client, resolver = leg.client_address, leg.resolver_address
        names = " or ".join(
            f"({layer}[{label}] = {length} and {layer}[{label + 1}:4] = 0x{prefix:08x}"
            f" and {layer}[{label + 6}:4] = 0x{head:08x}"
            f" and {layer}[{label + 10}:4] = 0x{tail:08x})"
            for length, prefix, head, tail in labels
        )
        clauses.append(
            f"({selector} and ((src host {client} and dst host {resolver}"
            f" and dst port {port}) or (src host {resolver} and src port {port}"
            f" and dst host {client})) and ({names}))"
        )
    return (" or ".join(clauses),)


def _traffic_bytes_error(check_id: str) -> GARuntimeAcceptanceError:
    """Refuse a check's packets; the cause names the rule they broke."""

    return _error(f"{check_id} packet bytes do not prove the required traffic")


def _require_capture_receipt(check_id: str, pcap: bytes, stderr: str) -> ParsedCapture:
    """Parse a check's pcap and judge tcpdump's receipt for it before any packet.

    A kernel drop, the packet cap or a count that differs from the pcap
    explains whatever packet failure would follow, so both collection and
    verification report it first.
    """

    try:
        parsed = parse_packet_capture(pcap, "packet-pcap")
    except PacketCaptureError as error:
        raise _traffic_bytes_error(check_id) from error
    _require_capture_statistic(stderr, len(parsed.records), check_id)
    return parsed


def _require_traffic_proof(
    check_id: str,
    pcap: bytes,
    *,
    endpoint: dict[str, Any],
    tokens: dict[str, str],
    observation_ms: int,
    capture_command: dict[str, Any],
    send_commands: list[dict[str, Any]],
    send_results: list[dict[str, Any]],
) -> None:
    """Prove one check's traffic from its pcap and its command receipts.

    Collection applies it before it keeps a capture, and verification again
    to the reopened evidence, so both judge the same packets by one rule.
    """

    policy = TRAFFIC_POLICY[check_id]
    _require_capture_receipt(check_id, pcap, capture_command["stderr"])
    dns = policy["protocol"] == "dns"
    if dns:
        endpoints = _tunnel_dns_stage_endpoints(check_id, pcap, tokens)
        if _stage_families(endpoints) != endpoint["stage_families"]:
            raise _error(f"{check_id} DNS stage families differ from the capture")
    else:
        endpoints = tuple(
            StagedCaptureEndpoint(
                stage=stage,
                local_address=result["local_address"],
                local_port=result["local_port"],
                remote_address=result["remote_address"],
                remote_port=result["remote_port"],
            )
            for stage, result in zip(PACKET_STAGES, send_results, strict=True)
        )
    try:
        proof = validate_staged_capture_tokens(
            pcap,
            "packet-pcap",
            protocol=policy["protocol"],
            family=TUNNEL_DNS_QUESTION_FAMILY if dns else endpoint["family"],
            endpoints=endpoints,
            expected_link_type=endpoint["link_type"],
            expected_interface_name=endpoint["interface_name"],
            expected_quic_version=None,
            token=tokens["target"].encode("ascii"),
            start_marker=tokens["start"].encode("ascii"),
            end_marker=tokens["end"].encode("ascii"),
            expect_token=True,
            declared_observation_ms=observation_ms,
            retransmissions=policy["retransmissions"],
            dns_resolver_legs=TUNNEL_DNS_LEGS if dns else None,
        )
    except PacketCaptureError as error:
        raise _traffic_bytes_error(check_id) from error
    # The proof itself refuses an absent target token and has an answer for
    # each DNS stage; only the record count is this policy's own.
    exact = policy["retransmissions"] is RetransmissionPolicy.EXACT
    if exact and proof.total_record_count != policy["expected_records"]:
        raise _error(f"{check_id} packet proof is partial or has extra traffic")
    capture_started = timestamp_fraction(capture_command["started_at"])
    capture_finished = timestamp_fraction(capture_command["finished_at"])
    if not (
        capture_started
        <= timestamp_fraction(send_commands[0]["started_at"])
        <= proof.start_event_started_at
        <= proof.start_event_ended_at
        <= timestamp_fraction(send_commands[0]["finished_at"])
        <= timestamp_fraction(send_commands[1]["started_at"])
        <= proof.target_started_at
        <= proof.target_ended_at
        <= timestamp_fraction(send_commands[1]["finished_at"])
        <= timestamp_fraction(send_commands[2]["started_at"])
        <= proof.end_event_started_at
        <= proof.end_event_ended_at
        <= timestamp_fraction(send_commands[2]["finished_at"])
        <= capture_finished
    ):
        raise _error(f"{check_id} command and packet timelines are not causal")
    if not exact:
        # The events above bound only each stage's first answered query or
        # data segment. Its other records, a query left unanswered before
        # that event or any repeat after it, may follow its sender, even into
        # a later stage's, and the settle; none precedes its own sender or
        # follows the capture.
        spans = proof.stage_record_spans
        if spans is None:
            raise _error(
                f"{check_id} packet proof lacks the stage record spans its "
                "retransmission policy requires"
            )
        for receipt, stage, span in zip(send_commands, PACKET_STAGES, spans, strict=True):
            if not (
                timestamp_fraction(receipt["started_at"])
                <= span.first_at
                <= span.last_at
                <= capture_finished
            ):
                raise _error(
                    f"{check_id} {stage} packets lie outside its sender's start and "
                    "the capture's end"
                )


def _validate_traffic(
    check_id: str,
    value: dict[str, Any],
    pcap: FileSnapshot,
    interpreter: str,
) -> set[str]:
    document = _check_document(
        value,
        check_id,
        {
            "capture",
            "capture_command",
            "endpoint",
            "host_observation",
            "observation_ms",
            "protocol",
            "send_commands",
            "tokens",
        },
    )
    policy = TRAFFIC_POLICY[check_id]
    if document["protocol"] != policy["protocol"]:
        raise _error(f"{check_id} protocol differs from the fixed policy")
    _packet_host_receipt(
        document["host_observation"],
        expected_case_id=policy["case_id"],
        expected_test_phase="tunnel_active",
    )
    expected_pcap_name = f"{check_id.replace('_', '-')}.pcap"
    _traffic_descriptor(document["capture"], expected_name=expected_pcap_name, snapshot=pcap)
    endpoint = _endpoint(document["endpoint"], check_id)
    tokens = _tokens(document["tokens"], check_id)
    observation_ms = document["observation_ms"]
    if type(observation_ms) is not int or not 1000 <= observation_ms <= 30_000:
        raise _error(f"{check_id} observation window is outside 1s..30s")
    filter_argv = _traffic_capture_filter_argv(check_id, tokens)
    capture_argv = _capture_command_argv(endpoint["interface_name"], filter_argv)
    capture_command = _command(
        document["capture_command"],
        expected_argv=capture_argv,
        expected_exit=0,
        label=f"{check_id} packet capture command",
    )
    send_values = document["send_commands"]
    if not isinstance(send_values, list) or len(send_values) != 3:
        raise _error(f"{check_id} must retain start/target/end sender commands")
    send_commands: list[dict[str, Any]] = []
    send_results: list[dict[str, Any]] = []
    for index, stage in enumerate(PACKET_STAGES):
        receipt = _command(
            send_values[index],
            expected_argv=_packet_sender_argv(
                interpreter,
                check_id=check_id,
                stage=stage,
                token=tokens[stage],
                local_address=TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"],
            ),
            expected_exit=0,
            label=f"{check_id} {stage} traffic send command",
        )
        send_commands.append(receipt)
        send_results.append(
            _packet_send_result(
                receipt,
                check_id=check_id,
                stage=stage,
                token=tokens[stage],
                local_address=TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"],
            )
        )
    _require_traffic_proof(
        check_id,
        pcap.data,
        endpoint=endpoint,
        tokens=tokens,
        observation_ms=observation_ms,
        capture_command=capture_command,
        send_commands=send_commands,
        send_results=send_results,
    )
    return set(tokens.values())


def _validate_credential_scan(
    value: dict[str, Any], snapshots: dict[str, FileSnapshot]
) -> None:
    document = _check_document(
        value, "credential_leak_scan", {"corpus", "pattern_policy"}
    )
    if document["pattern_policy"] != SECRET_POLICY:
        raise _error("credential scan does not use the fixed GA evidence policy")
    scan_name = "credential-leak-scan.json"
    corpus = document["corpus"]
    expected_names = sorted(set(snapshots) - {scan_name})
    if not isinstance(corpus, list) or len(corpus) != len(expected_names):
        raise _error("credential scan corpus does not cover every exact evidence byte file")
    observed_names: list[str] = []
    for index, record_value in enumerate(corpus):
        record = require_exact_keys(
            record_value,
            {"path", "sha256", "size"},
            f"credential corpus[{index}]",
        )
        if not isinstance(record["path"], str):
            raise _error("credential corpus path is malformed")
        path = safe_relative(record["path"], "credential corpus path")
        if len(path.parts) != 1 or path.as_posix() not in snapshots:
            raise _error("credential corpus path is outside the fixed evidence set")
        snapshot = snapshots[path.as_posix()]
        if record != snapshot.record():
            raise _error("credential corpus descriptor differs from reopened evidence bytes")
        observed_names.append(path.as_posix())
    if observed_names != expected_names:
        raise _error("credential scan corpus is duplicated, reordered, or incomplete")
    for name in expected_names:
        data = snapshots[name].data
        if any(pattern.search(data) is not None for pattern in SECRET_PATTERNS):
            # Do not include the matched bytes, line, or offset in this error.
            raise _error("credential-like material is present in the exact GA evidence corpus")


def _json_snapshots(snapshots: dict[str, FileSnapshot]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name in sorted(JSON_FILES):
        result[name] = _strict_json(snapshots[name].data, f"GA runtime {name}")
    return result


def _validate_raw_evidence(
    repository: Path,
    snapshots: dict[str, FileSnapshot],
    expected: dict[str, Any],
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str], bytes]:
    documents = _json_snapshots(snapshots)
    collections = {
        tuple(sorted(_collection_binding(document["collection"], name).items()))
        for name, document in documents.items()
        if isinstance(document, dict) and "collection" in document
    }
    if len(collections) != 1:
        raise _error(
            "GA runtime checks do not bind one collection session/challenge/environment"
        )
    collection = dict(next(iter(collections)))
    if collection["ga_environment_sha256"] != expected["ga_environment_sha256"]:
        raise _error("GA runtime checks bind a different fixed GA environment")
    intent, intent_collection = _load_collection_intent(
        repository, repository.joinpath(*COLLECTION_RELATIVE.parts)
    )
    if intent_collection != collection:
        raise _error("GA runtime checks belong to a different collection")
    # Receipts embed the collector's operator checkout and release Python;
    # they are checked against the collection's own record of both.
    collector = intent["collector"]
    _validate_exact_dmg_install(
        documents["exact-dmg-install.json"],
        repository,
        expected,
        prepackage_stage_verifier,
        Path(collector["operator_root"]),
    )
    _validate_launch(documents["launch.json"])
    _validate_service_registration(documents["service-registration.json"])
    _validate_system_extension(documents["system-extension.json"])
    _validate_network_extension(documents["network-extension.json"], documents)
    _validate_high_risk_rejections(documents["high-risk-rejections.json"])
    shutdown_guards = _validate_shutdown_restore(documents["shutdown-restore.json"])
    _validate_legacy_cfw(
        documents["legacy-cfw-preserved.json"],
        repository,
        expected,
        shutdown_guards,
        intent,
    )
    seen_tokens: set[str] = set()
    host_sessions = {
        documents["shutdown-restore.json"]["stop_restore_observation"]["session_id"]
    }
    for check_id in TRAFFIC_CHECKS:
        filename = f"{check_id.replace('_', '-')}.json"
        pcap_name = f"{check_id.replace('_', '-')}.pcap"
        tokens = _validate_traffic(
            check_id,
            documents[filename],
            snapshots[pcap_name],
            collector["python"]["executable"],
        )
        expected_tokens = {
            _derive_capture_token(collection["challenge"], check_id, stage)
            for stage in PACKET_STAGES
        }
        if tokens != expected_tokens:
            raise _error(f"{check_id} tokens are not derived from the collection challenge")
        if seen_tokens & tokens:
            raise _error("GA traffic checks reuse an evidence token")
        seen_tokens.update(tokens)
        host_session = documents[filename]["host_observation"]["session_id"]
        if host_session in host_sessions:
            raise _error("GA checks reuse an authenticated Packet Host session")
        host_sessions.add(host_session)
    if len(host_sessions) != len(TRAFFIC_CHECKS) + 1:
        raise _error("GA checks do not retain one fresh Packet Host session per transaction")
    _validate_credential_scan(documents["credential-leak-scan.json"], snapshots)

    artifacts: dict[str, list[dict[str, Any]]] = {}
    for check_id in CHECKS:
        json_name = f"{check_id.replace('_', '-')}.json"
        records = [snapshots[json_name].record()]
        if check_id in TRAFFIC_CHECKS:
            records.append(snapshots[f"{check_id.replace('_', '-')}.pcap"].record())
        artifacts[check_id] = records
    return artifacts, collection, canonical_json(intent)


def _adapter_document(
    expected: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
    artifacts: dict[str, list[dict[str, Any]]],
    collection: dict[str, str],
    collection_receipt: dict[str, str],
) -> dict[str, Any]:
    entries = _tree_entries(snapshots)
    return {
        "bindings": {
            key: expected[key]
            for key in (
                "dmg_gatekeeper_sha256",
                "dmg_set_seal_sha256",
                "dmg_sha256",
                "ga_environment_sha256",
                "install_journal_sha256",
                "service_journal_tree_sha256",
            )
        },
        "checks": [
            {"artifacts": artifacts[check_id], "id": check_id}
            for check_id in CHECKS
        ],
        "collection": collection,
        "collection_receipt": collection_receipt,
        "document": DOCUMENT,
        "evidence_tree": {"entries": entries, "sha256": tree_digest(entries)},
        "gate_class": GATE_CLASS,
        "migration": {"from_build": FROM_BUILD, "to_build": TO_BUILD},
        "product_version": PRODUCT_VERSION,
        "schema_version": SCHEMA_VERSION,
    }


def _validate_adapter_shape(
    value: object,
    expected: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
    artifacts: dict[str, list[dict[str, Any]]],
    collection: dict[str, str],
    collection_receipt: dict[str, str],
) -> dict[str, Any]:
    document = require_exact_keys(
        value,
        {
            "bindings",
            "checks",
            "collection",
            "collection_receipt",
            "document",
            "evidence_tree",
            "gate_class",
            "migration",
            "product_version",
            "schema_version",
        },
        "GA runtime acceptance adapter",
    )
    expected_document = _adapter_document(
        expected, snapshots, artifacts, collection, collection_receipt
    )
    if document != expected_document:
        raise _error("GA runtime acceptance adapter differs from reopened raw evidence")
    return document


def _repository_record(repository: Path, path: Path, digest: str) -> dict[str, str]:
    try:
        relative = path.relative_to(repository).as_posix()
    except ValueError as error:
        raise _error("GA runtime evidence path is outside the repository") from error
    safe_relative(relative, "GA runtime record path")
    return {"path": relative, "sha256": digest}


def _validate_ga_runtime_acceptance(
    *,
    repository: Path,
    acceptance_path: Path,
    raw_evidence_root: Path,
    expected: object,
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> dict[str, dict[str, str]]:
    """Reopen and derive all twelve GA outcomes from the fixed raw evidence."""

    repository = _canonical_repository(repository)
    _require_fixed_paths(repository, acceptance_path, raw_evidence_root)
    normalized_expected = _validate_expected(expected)
    snapshots = _snapshot_raw_tree(raw_evidence_root)
    artifacts, collection, collection_intent = _validate_raw_evidence(
        repository,
        snapshots,
        normalized_expected,
        prepackage_stage_verifier,
    )
    collection_receipt = _validate_collection_receipt(
        repository, collection, collection_intent
    )
    _private_regular_metadata(acceptance_path)
    try:
        adapter_data = read_regular(acceptance_path, MAX_JSON_BYTES)
    except PublicationError as error:
        raise _error("GA runtime adapter cannot be reopened safely") from error
    adapter = _strict_json(adapter_data, "GA runtime acceptance adapter")
    _validate_adapter_shape(
        adapter,
        normalized_expected,
        snapshots,
        artifacts,
        collection,
        collection_receipt,
    )
    _confirm_snapshot(raw_evidence_root, snapshots)
    if _validate_collection_receipt(
        repository, collection, collection_intent
    ) != collection_receipt:
        raise _error("GA runtime collection receipt changed during verification")
    adapter_digest = sha256_file(acceptance_path)
    if adapter_digest != sha256_bytes(adapter_data):
        raise _error("GA runtime adapter changed while verification completed")
    entries = _tree_entries(snapshots)
    return {
        "adapter": _repository_record(repository, acceptance_path, adapter_digest),
        "runtime_evidence": _repository_record(
            repository,
            raw_evidence_root,
            tree_digest(entries),
        ),
    }


def validate_ga_runtime_acceptance(
    *,
    repository: Path,
    acceptance_path: Path,
    raw_evidence_root: Path,
    expected: object,
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> dict[str, dict[str, str]]:
    """Public adapter boundary with one fail-closed ``ValueError`` family."""

    try:
        return _validate_ga_runtime_acceptance(
            repository=repository,
            acceptance_path=acceptance_path,
            raw_evidence_root=raw_evidence_root,
            expected=expected,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
    except GARuntimeAcceptanceError:
        raise
    except PublicationError as error:
        raise _error("GA runtime evidence violates the strict publication contract") from error


def seal_ga_runtime_acceptance(
    *,
    repository: Path,
    expected: object,
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> dict[str, dict[str, str]]:
    """Validate the fixed raw tree and create/recover the immutable adapter."""

    repository = _canonical_repository(repository)
    acceptance_path, raw_root = _fixed_paths(repository)
    normalized_expected = _validate_expected(expected)
    snapshots = _snapshot_raw_tree(raw_root)
    artifacts, collection, collection_intent = _validate_raw_evidence(
        repository,
        snapshots,
        normalized_expected,
        prepackage_stage_verifier,
    )
    collection_receipt = _validate_collection_receipt(
        repository, collection, collection_intent
    )
    document = _adapter_document(
        normalized_expected,
        snapshots,
        artifacts,
        collection,
        collection_receipt,
    )
    encoded = canonical_json(document)
    parent = acceptance_path.parent
    try:
        with exclusive_rooted_directory_lock(
            repository,
            parent,
            require_private=True,
        ) as descriptor:
            if _fixed_path_present(acceptance_path):
                _private_regular_metadata(acceptance_path)
                # A retry after an unknown rename outcome must make the
                # adapter and its directory entry durable before success.
                try:
                    observed = read_private_pending_locked(
                        descriptor,
                        parent,
                        acceptance_path.name,
                        MAX_JSON_BYTES,
                    )
                except PublicationError as error:
                    raise _error(
                        "existing GA runtime adapter cannot be durably reopened"
                    ) from error
                if observed != encoded:
                    raise _error(
                        "refusing to replace a different immutable GA runtime adapter"
                    )
            else:
                # The adapter is derived from the reopened evidence, so a
                # retry writes the same bytes; it appears only complete.
                publish_private_file_locked(
                    staging_descriptor=descriptor,
                    staging_directory=parent,
                    destination_descriptor=descriptor,
                    destination_directory=parent,
                    name=acceptance_path.name,
                    data=encoded,
                )
    except (DurabilityOutcomeUnknown, RootedDirectoryChanged):
        raise
    except PublicationError as error:
        raise _error("GA runtime adapter durable publication failed") from error
    return validate_ga_runtime_acceptance(
        repository=repository,
        acceptance_path=acceptance_path,
        raw_evidence_root=raw_root,
        expected=normalized_expected,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )


COLLECTION_DOCUMENT: Final = "cfm-ga-runtime-collection-intent-v4"
COLLECTION_INTENT_SCHEMA_VERSION: Final = 4
COLLECTION_EVENT_DOCUMENT: Final = "cfm-ga-runtime-collection-event-v2"
COLLECTION_SUCCESS_STEPS: Final = (
    "dmg-gatekeeper",
    "dmg-contained-app-byte-proof",
    "launch",
    "launch-process-observation",
    "proxy-service-observation",
    "authority-service-observation",
    "high-risk-unknown-service-maintenance-action",
    "high-risk-unauthenticated-packet-control",
    "high-risk-extra-packet-control-argument",
    "traffic-dns_traffic",
    "traffic-tcp_traffic",
    "traffic-udp_traffic",
    "system-extension-observation",
    "network-extension-binding",
    "shutdown-stop-restore",
    "shutdown-request",
    "shutdown-host-process-observation",
    "shutdown-off-proof",
    "shutdown-process-observation",
)
COLLECTION_STEP_PAIRS: Final = tuple(
    (phase, step)
    for step in COLLECTION_SUCCESS_STEPS
    for phase in ("started", "completed")
)
RAW_PUBLISHED_PAIR: Final = ("raw_published", "collection")
COMPLETED_COLLECTION_PAIRS: Final = (*COLLECTION_STEP_PAIRS, RAW_PUBLISHED_PAIR)
# collect's mutation boundary: it is crossed immediately before this step's
# started event, and no earlier step changes anything recovery restores.
MUTATION_BOUNDARY_STEP: Final = "launch"
MUTATION_BOUNDARY_PAIR: Final = ("started", MUTATION_BOUNDARY_STEP)
# collect's terminal event for a failure after or before its mutation boundary.
RECOVERY_REQUIRED_PAIR: Final = ("recovery_required", "collection")
ABORTED_BEFORE_MUTATION_PAIR: Final = ("aborted_before_mutation", "collection")
PRE_MUTATION_STEP_PAIRS: Final = COLLECTION_STEP_PAIRS[
    : COLLECTION_STEP_PAIRS.index(MUTATION_BOUNDARY_PAIR)
]
# recover's marker for an attempt it archives without any runtime work.
RECOVERED_BEFORE_MUTATION_PAIR: Final = ("recovered", "collection")
SEAL_RETRY_COMMAND: Final = "scripts/run_ga_runtime_acceptance.sh resume-seal"
RECOVERY_COMMAND: Final = "scripts/run_ga_runtime_acceptance.sh recover"
UNFINISHED_COLLECTION_REFUSAL: Final = (
    "an unfinished GA runtime collection already exists; recover it"
)
PRE_MUTATION_ABORT_GUIDANCE: Final = (
    "GA runtime collection stopped before it launched the Host; run "
    f"{RECOVERY_COMMAND} to archive this attempt, then collect again"
)
# A refusal of the pre-flight or of the capture authorization before any
# collection state; the pre-flight's refusal right before launch is an aborted
# attempt, which PRE_MUTATION_ABORT_GUIDANCE covers.
PREFLIGHT_RETRY_GUIDANCE: Final = (
    "GA runtime collection recorded nothing for this attempt; rerun collect once "
    "that is done"
)
# A Host that ended without its graceful shutdown leaves its runtime on, and
# only the Host's next launch reconciles it. recover never relaunches the app.
# Reconciliation that stops a runtime it cannot adopt reports a stopped
# failure rather than Off, and a launch whose status read fails exits on ⌘Q
# without cleanup; a second failed Off proof therefore needs investigation.
RECOVERY_OFF_PROOF_GUIDANCE: Final = (
    "the installed Host may have exited without its graceful shutdown and left "
    "its runtime on: open Clash for Mac so its startup reconciliation stops the "
    "orphaned runtime, confirm its dashboard shows TUN Mode and System Proxy "
    "off (it may show Off or a stopped failure state; do not retry them), quit "
    "it with Quit Clash for Mac (⌘Q) in its app menu, then rerun "
    f"{RECOVERY_COMMAND}; if the Off proof still fails after that, stop and "
    "investigate instead of repeating these steps"
)
# A graceful shutdown that cannot stop the runtime normally keeps the Host open
# and reports the failure; any other quit would leave that runtime on.
RECOVERY_OPERATOR_QUIT_GUIDANCE: Final = (
    "recovery did not observe the installed Host exit: if it is still running, "
    "quit it with Quit Clash for Mac (⌘Q) in its app menu, then rerun "
    f"{RECOVERY_COMMAND}; if it does not exit after ⌘Q, stop and investigate "
    "instead of quitting it any other way"
)


class GACollectionRecoveryRequired(GARuntimeAcceptanceError):
    """A collection entered the mutation boundary and requires fixed recovery."""


class GASealRetryRequired(GARuntimeAcceptanceError):
    """Raw evidence is published after the proven restore; only sealing is retried."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _failed_capture_pipe_snapshot(
    stream: BinaryIO, prefix: bytes, maximum: int, deadline: float
) -> tuple[bytes, bool]:
    """Drain only currently available bytes, with size and time bounds."""
    if len(prefix) > maximum:
        return prefix[:maximum], False
    output = bytearray(prefix)
    descriptor = stream.fileno()
    os.set_blocking(descriptor, False)
    while time.monotonic() < deadline:
        try:
            chunk = os.read(descriptor, min(65536, maximum - len(output) + 1))
        except BlockingIOError:
            return bytes(output), False
        if not chunk:
            return bytes(output), True
        room = maximum - len(output)
        output.extend(chunk[:room])
        if len(chunk) > room:
            return bytes(output), False
    return bytes(output), False


def _cleanup_failure(
    failure: GARuntimeAcceptanceError | None, message: str, error: OSError
) -> GARuntimeAcceptanceError:
    """Record one failed capture cleanup step.

    The first becomes the cleanup failure, caused by its error; a later one is
    a note on that failure, so none is lost.
    """

    if failure is None:
        failure = _error(message)
        failure.__cause__ = error
    else:
        failure.add_note(f"{message}: {error!r}")
    return failure


def _capture_file_bytes(capture: BinaryIO, maximum: int) -> bytes:
    """Read tcpdump's pcap file from its start, at most one byte past maximum.

    tcpdump writes through a duplicate of the file's descriptor and shares its
    offset, so the read never moves it.
    """

    descriptor = capture.fileno()
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.pread(descriptor, min(65536, maximum + 1 - len(data)), len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _failed_capture_notes(evidence: FailedPacketCaptureEvidence) -> list[str]:
    """Render a failed capture's bounded text diagnostics, never its packets.

    The summary names the capture's sudo pid: a capture that fails because
    tcpdump refused the interrupt or its process group was not cleaned up can
    leave a root sudo or tcpdump in that group, which RELEASE.md has the
    operator list and stop by it.
    """

    label = f"{evidence.check_id} tcpdump"
    summary = (
        f"{label} ran under sudo pid {evidence.sudo_pid}; exit status "
        f"{_exit_description(evidence.command.get('exit_code'))}; "
        f"{len(evidence.packet_bytes)} packet bytes retained, not shown; outputs "
        f"{'complete' if evidence.outputs_complete else 'incomplete'}"
    )
    if evidence.retention_errors:
        summary += f"; retention errors: {', '.join(evidence.retention_errors)}"
    return [summary, _output_note(label, "stderr", evidence.stderr_bytes)]


# The BoundedProcessError reasons raised after the command ran carry the output
# it wrote before it was stopped; with any other reason none was retained.
BOUNDED_FAILURE_OUTPUT_REASONS: Final = frozenset(
    {"timeout", "output-limit", "input", "descendant"}
)


def _bounded_failure_notes(
    subject: str,
    output_label: str,
    error: BoundedProcessError,
    *,
    timeout: int,
    output_limit: int,
) -> list[str]:
    """Name the boundary a bounded command broke and show what it wrote."""

    notes = [
        f"{subject} failed its {error.reason} boundary: timeout {timeout} s, "
        f"output limit {output_limit} bytes"
    ]
    if error.reason not in BOUNDED_FAILURE_OUTPUT_REASONS:
        return [*notes, f"{output_label} retained no output"]
    return [
        *notes,
        _output_note(output_label, "stdout", error.stdout),
        _output_note(output_label, "stderr", error.stderr),
    ]


def _read_capture_password() -> bytearray | None:
    """Read the capture password from the terminal as its UTF-8 line.

    None means the terminal could not decode it, or it cannot be encoded: the
    codec's error holds the password and names one of its bytes, so it is
    dropped here and never chained to the refusal.
    """

    try:
        password = getpass.getpass("Authorize bounded CFM packet capture: ")
        return bytearray((password + "\n").encode("utf-8"))
    except UnicodeError:
        return None


def _capture_command_argv(interface: str, filter_argv: Iterable[str]) -> list[str]:
    """Open BPF with administrator authority, then capture as the operator.

    macOS BPF devices are normally root-only. tcpdump's -Z drops its user and
    group before writing packet bytes; no device permissions are changed.
    tcpdump writes its snapshot length into the pcap header, and its default
    on the Packet Tunnel utun (524288) is above what parse_packet_capture
    accepts, so -s fixes it at that bound. -c stops it at CAPTURE_PACKET_CAP,
    which no capture the collector stops and accepts reaches, and
    --immediate-mode has libpcap hand it each packet as it arrives (see
    CAPTURE_SETTLE_SECONDS).
    The same fixed argv is used for execution and receipt verification.
    """
    uid = os.getuid()
    if uid == 0 or os.geteuid() != uid:
        raise _error("packet capture must be coordinated by the ordinary release account")
    try:
        account = pwd.getpwuid(uid)
    except KeyError as error:
        raise _error("packet capture operator account is unavailable") from error
    if account.pw_uid != uid or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,254}", account.pw_name):
        raise _error("packet capture operator account is not canonical")
    return [
        "/usr/bin/sudo", "-S", "-p", "CFM capture authorization: ", "--", "/usr/sbin/tcpdump",
        "-Z", account.pw_name, "--immediate-mode",
        "-U", "-n", "-s", str(MAX_SNAPLEN), "-i", interface,
        "-c", str(CAPTURE_PACKET_CAP), "-w", "-", *filter_argv,
    ]


def _require_capture_statistic(stderr: str, records: int, label: str) -> None:
    """Require tcpdump's statistics for a complete capture below the cap.

    It must count the pcap's records as captured and report no matching
    packet dropped by the kernel: the rules for repeated packets judge every
    matching packet tcpdump read before it stopped. Collection and receipt
    verification apply the same rule.
    """

    counts: dict[str, list[int]] = {"captured": [], "dropped by kernel": []}
    for line in stderr.splitlines():
        match = CAPTURE_STATISTIC_RE.fullmatch(line)
        if match is not None:
            counts[match[2]].append(int(match[1]))
    if any(len(values) != 1 for values in counts.values()):
        raise _error(f"{label} tcpdump output lacks a capture receipt")
    (captured,) = counts["captured"]
    (dropped,) = counts["dropped by kernel"]
    if dropped:
        raise _error(
            f"{label} tcpdump reports {dropped} matching packets dropped by the kernel"
        )
    if captured >= CAPTURE_PACKET_CAP:
        raise _error(
            f"{label} tcpdump reached its {CAPTURE_PACKET_CAP}-packet cap: extra traffic"
        )
    if captured != records:
        raise _error(
            f"{label} tcpdump captured {captured} packets but its pcap holds "
            f"{records} records"
        )


@dataclass(frozen=True)
class _CaptureProcessRow:
    """One CAPTURE_PROCESS_COLUMNS row of the process group a capture's sudo leads."""

    pid: int
    parent: int
    # Real, effective and saved.
    user_ids: tuple[int, int, int]
    state: str
    name: str

    def note(self) -> str:
        return (
            f"{self.pid} {self.parent} {'/'.join(str(uid) for uid in self.user_ids)} "
            f"{_inert(self.state)} {_inert(self.name)}"
        )


def _capture_process_rows(stdout: str) -> list[_CaptureProcessRow]:
    """Parse a CAPTURE_PROCESS_COLUMNS listing."""

    rows: list[_CaptureProcessRow] = []
    for line in stdout.splitlines():
        match = CAPTURE_PROCESS_ROW_RE.fullmatch(line)
        if match is None:
            raise _error("tcpdump process observation is malformed")
        rows.append(
            _CaptureProcessRow(
                pid=int(match[1]),
                parent=int(match[2]),
                user_ids=(int(match[3]), int(match[4]), int(match[5])),
                state=match[6],
                name=match[7],
            )
        )
    return rows


class ProductionCollectorRuntime:
    """Bounded production runner for the fixed GA collection registry."""

    def __init__(self, repository: Path) -> None:
        self.repository = _canonical_repository(repository)
        pins = load_pins(self.repository / "scripts/dependency_pins.env")
        self.environment = release_tool_environment(self.repository, pins)
        self._capture_password = bytearray()

    def run(self, argv: list[str], *, timeout: int = 900) -> dict[str, Any]:
        started_at = _utc_now()
        try:
            completed = run_bounded_process(
                argv,
                cwd=self.repository,
                environment=self.environment,
                timeout=timeout,
                output_limit=MAX_COMMAND_OUTPUT_BYTES,
            )
        except OSError as error:
            raise _error(
                "fixed GA collection command failed its bounded process boundary"
            ) from error
        except BoundedProcessError as error:
            failure = _error(
                "fixed GA collection command failed its bounded process boundary"
            )
            # The fixed command registry carries no credential in argv; sudo
            # reads the capture password only from its private input pipe.
            for note in _bounded_failure_notes(
                f"command {json.dumps(argv, default=repr)}",
                "bounded command",
                error,
                timeout=timeout,
                output_limit=MAX_COMMAND_OUTPUT_BYTES,
            ):
                failure.add_note(note)
            raise failure from error
        finished_at = _utc_now()
        try:
            stdout = completed.stdout.decode("utf-8", errors="strict")
            stderr = completed.stderr.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise _error("fixed GA collection command output is not UTF-8") from error
        return {
            "argv": list(argv),
            "document": COMMAND_DOCUMENT,
            "exit_code": completed.returncode,
            "finished_at": finished_at,
            "schema_version": SCHEMA_VERSION,
            "started_at": started_at,
            "stderr": stderr,
            "stdout": stdout,
        }

    def capture_environment(self) -> dict[str, Any]:
        return observe_environment()

    def require_capture_authority(self) -> None:
        # collect runs this before it records anything or changes app state;
        # an operator's restoration wrapper can also call it before stopping
        # an active connection. An absent sudo authorization must never
        # strand an active connection.
        _capture_command_argv("lo0", ())
        if not self._capture_password:
            if not sys.stdin.isatty():
                # Unattended input never supplies the credential, so only an
                # authorization sudo already holds can admit the capture.
                cached = self.run(
                    ["/usr/bin/sudo", "-n", "--", "/usr/sbin/tcpdump", "--version"],
                    timeout=10,
                )
                if cached["exit_code"] == 0:
                    return
                raise _error("packet capture needs administrator authorization in a terminal before collection")
            # A terminal always gives the password, even over a cached sudo
            # ticket: the ticket can expire during the DMG proof and operator
            # waits before tcpdump's own sudo first reads the held password.
            password = _read_capture_password()
            if password is None:
                raise _error("packet capture authorization input is not UTF-8")
            self._capture_password = password
            if len(self._capture_password) > 4096:
                self.release_capture_authority()
                raise _error("packet capture authorization input exceeds its bound")
        try:
            try:
                # -k ignores a cached ticket, so this proves the held password
                # itself, not an authorization that can expire before tcpdump.
                result = run_bounded_process(
                    ["/usr/bin/sudo", "-k", "-S", "-p", "CFM capture authorization: ", "--", "/usr/sbin/tcpdump", "--version"],
                    cwd=self.repository,
                    environment=self.environment,
                    input_bytes=bytes(self._capture_password),
                    timeout=CAPTURE_AUTHORITY_TIMEOUT_SECONDS,
                    output_limit=CAPTURE_AUTHORITY_OUTPUT_BYTES,
                )
            except BoundedProcessError as error:
                failure = _error(
                    "packet capture administrator authorization failed before collection"
                )
                # sudo reads the password from its input pipe and never
                # writes it; its prompts and tcpdump's version may be shown.
                for note in _bounded_failure_notes(
                    "sudo verification",
                    "sudo verification",
                    error,
                    timeout=CAPTURE_AUTHORITY_TIMEOUT_SECONDS,
                    output_limit=CAPTURE_AUTHORITY_OUTPUT_BYTES,
                ):
                    failure.add_note(note)
                raise failure from error
            if result.returncode != 0:
                raise _error("packet capture administrator authorization failed before collection")
        except BaseException:
            self.release_capture_authority()
            raise

    def release_capture_authority(self) -> None:
        # Zeroing is best effort: only this bytearray is overwritten. getpass
        # returns an immutable str, and that str with its newline, its UTF-8
        # encoding, the bytes copy that proves it to sudo and the buffer of
        # each capture's stdin pipe are copies no code here can zero.
        self._capture_password[:] = b"\0" * len(self._capture_password)
        self._capture_password.clear()

    def require_host_quit_and_tunnel_disconnected(self) -> None:
        """Refuse a collection while Clash for Mac could still own networking.

        The collection baseline must be the network without Clash for Mac: a
        running Host or a connected Clash for Mac VPN would put its own proxy,
        DNS, routes and utun into a baseline that the end of the run, after
        the operator's quit, can never restore. The service transaction's Host
        check and the installer's VPN check decide both. A system proxy on a
        loopback host, an orphaned Clash for Mac System Proxy or another local
        proxy tool, would likewise fail only at the end, once the product
        restores the system proxy; while Clash for Windows runs, its guard
        owns that proxy instead. collect runs this again immediately before
        its launch, so a Host opened during the DMG proof is never taken for
        the one it launches.
        """

        runner = dormant_app_install.production_command_runner
        try:
            processes = dormant_app_install._parse_processes(
                dormant_app_install._require_command_success(
                    runner(PROCESS_OBSERVATION_COMMAND),
                    "Clash for Mac process observation",
                )
            )
        except dormant_app_install.InstallError as error:
            raise _error(
                "Clash for Mac processes could not be observed before collection"
            ) from error
        try:
            current_service_transaction._require_no_host_process(processes)
        except dormant_app_install.InstallError as error:
            raise _error(
                "GA runtime collection needs every Clash for Mac Host quit before it "
                "starts; quit it with Quit Clash for Mac (⌘Q) in its app menu"
            ) from error
        try:
            dormant_app_install.require_cfm_system_extension_inactive(runner)
        except dormant_app_install.InstallError as error:
            if error.code not in {"cfm_tunnel_not_disconnected", "cfm_tunnel_state_changed"}:
                # Includes a Clash for Mac extension from another team: the
                # cause names which observation refused.
                raise _error(
                    "Clash for Mac VPN state could not be proven disconnected before "
                    "collection"
                ) from error
            raise _error(
                "GA runtime collection needs every Clash for Mac VPN disconnected "
                f"before it starts; turn TUN Mode off in the installed {TO_BUILD} "
                "dashboard, then quit it with Quit Clash for Mac (⌘Q) in its app menu"
            ) from error
        if any(
            process["path"] in (dormant_app_install.CFW_GUI, dormant_app_install.CFW_CORE)
            for process in processes
        ):
            # Clash for Windows binds 127.0.0.1:7890 while it runs; the
            # baseline guard requires exactly that binding, and the collection
            # must leave it unchanged.
            return
        try:
            proxy = dormant_app_install._require_command_success(
                runner(("/usr/sbin/scutil", "--proxy")), "system proxy observation"
            )
        except dormant_app_install.InstallError as error:
            raise _error("system proxy could not be observed before collection") from error
        try:
            dormant_app_install.require_system_proxy_observation(proxy)
            found = _loopback_system_proxies(proxy, label="collection pre-flight")
        except (NetworkObservationError, dormant_app_install.InstallError) as error:
            raise _error(
                "system proxy observation before collection is malformed"
            ) from error
        if found:
            raise _error(
                "GA runtime collection needs no HTTP, HTTPS or SOCKS system proxy on a "
                f"loopback host before it starts ({'; '.join(found)}); open the "
                f"installed {TO_BUILD} Clash for Mac, turn System Proxy off in its "
                "dashboard and approve the macOS prompt, then quit it with Quit Clash "
                "for Mac (⌘Q) in its app menu, or quit the other proxy tool"
            )

    def capture_guard(self) -> dict[str, Any]:
        try:
            return dormant_app_install.capture_cfw_guard(
                dormant_app_install.production_command_runner,
                require_cfm_absent=False,
            )
        except dormant_app_install.InstallError as error:
            raise _error("fixed CFW guard could not be observed") from error

    @staticmethod
    def _run_packet_host_transaction(
        *,
        case_id: str,
        begin_capture: Callable[[Any], PacketCaptureDisposition],
        exercise_test: Callable[[Any], PacketCaptureDisposition],
        finish_capture: Callable[[Any], PacketCaptureDisposition],
    ) -> PacketHostReceipt:
        deadline = time.monotonic() + PACKET_HOST_READY_SECONDS
        announced_operator_boundary = False
        while True:
            try:
                return run_fixed_host_transaction(
                    case_id=case_id,
                    begin_capture=begin_capture,
                    exercise_test=exercise_test,
                    finish_capture=finish_capture,
                )
            except PacketHostError as error:
                if error.cleanup_code is not None:
                    raise
                # A dashboard mode change, such as the operator selecting
                # Tunnel, holds the Host's maintenance lease for the whole
                # start; the Host refuses before any baseline or test state.
                waiting_for_operator = error.code in {
                    "baseline_mismatch",
                    "baseline_unavailable",
                    "maintenance_busy",
                    "tunnel_unavailable",
                }
                retryable = waiting_for_operator or error.code == "app_control_unavailable"
                if not retryable or time.monotonic() >= deadline:
                    raise
                if waiting_for_operator and not announced_operator_boundary:
                    print(
                        "GA runtime collection is waiting for macOS approval and "
                        f"Tunnel mode in the installed {TO_BUILD} dashboard",
                        file=sys.stderr,
                        flush=True,
                    )
                    announced_operator_boundary = True
                time.sleep(
                    PACKET_HOST_TICKET_RETRY_SECONDS if waiting_for_operator else 0.25
                )

    def _tunnel_interface(self) -> str:
        receipt = self.run(["/sbin/ifconfig"], timeout=15)
        _command(
            receipt,
            expected_argv=["/sbin/ifconfig"],
            expected_exit=0,
            label="GA tunnel interface observation",
            maximum_seconds=15,
        )
        current: str | None = None
        matches: list[str] = []
        address = TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"]
        for line in receipt["stdout"].splitlines():
            if line and not line[0].isspace():
                name, separator, _rest = line.partition(":")
                current = name if separator and re.fullmatch(r"utun[0-9]{1,3}", name) else None
            if current is not None and re.search(
                rf"^\s*inet {re.escape(address)}(?:\s|$)", line
            ):
                matches.append(current)
        if len(matches) != 1:
            raise _error("GA Packet capture address is not bound to one utun interface")
        return matches[0]

    @staticmethod
    def _terminate_capture(process: subprocess.Popen[bytes]) -> None:
        denied: PermissionError | None = None
        try:
            running = process.poll() is None
        except OSError as error:
            raise _error("tcpdump capture state could not be observed") from error
        if running:
            try:
                os.killpg(process.pid, 9)
            except ProcessLookupError as error:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired as timeout_error:
                    raise _error(
                        "tcpdump capture process group could not be cleaned up"
                    ) from timeout_error
                except OSError as wait_error:
                    raise _error(
                        "tcpdump capture process exit could not be observed"
                    ) from wait_error
                try:
                    still_running = process.poll() is None
                except OSError as poll_error:
                    raise _error(
                        "tcpdump capture process exit could not be observed"
                    ) from poll_error
                if still_running:
                    raise _error(
                        "tcpdump capture process exit could not be observed"
                    ) from error
                return
            except PermissionError as error:
                # The group holds no process the operator may signal: only a
                # sudo that keeps root once tcpdump, which -Z made the
                # operator's, has exited; only zombies, once sudo has exited
                # too; or a tcpdump that is still root. sudo exits only once its
                # command has, or is that command, so the bounded waits below
                # for sudo and its group decide, and a root tcpdump makes them
                # time out.
                denied = error
            except OSError as error:
                raise _error(
                    "tcpdump capture process group could not be terminated"
                ) from error
        # sudo's exit is not tcpdump's: a tcpdump still root when sudo ended,
        # which the operator's SIGKILL could not reach, or one a sudo that
        # ended first left behind, stays in sudo's process group. As
        # bounded_process._terminate_group does, cleanup ends only once that
        # group is gone too, within the same five seconds as sudo's exit.
        deadline = time.monotonic() + 5
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise _error("tcpdump capture process group could not be cleaned up") from (
                error if denied is None else denied
            )
        except OSError as error:
            raise _error("tcpdump capture process exit could not be observed") from error
        try:
            group_gone = _wait_for_group_exit(process.pid, deadline)
        except OSError as error:
            raise _error("tcpdump capture process group could not be observed") from error
        if not group_gone:
            raise _error("tcpdump capture process group could not be cleaned up") from denied

    def _interrupt_capture(self, process: subprocess.Popen[bytes], *, timeout: int) -> None:
        """Stop tcpdump with one SIGINT to its own process, so it prints its count.

        Once tcpdump has opened the device, -Z makes it the operator's
        (tcpdump(1)), so the operator may signal it; sudo's front end can keep
        root as its real and saved user ID, and the kernel then refuses the
        operator's signal to it. Signalled alone, tcpdump gets one SIGINT: sudo
        relays only a signal it receives itself (sudo(8), "Signal handling"),
        a signal to the process group could reach tcpdump twice, and
        tcpdump(1) says a second SIGINT on macOS exits at once without the
        capture statistics. A capture that already stopped, as its packet cap
        stops it, fails instead, also when it stops while the collector finds
        or signals it.
        """

        if process.poll() is not None:
            raise _error("tcpdump stopped before the collector stopped it")
        tcpdump = self._tcpdump_process_id(process, timeout=timeout)
        try:
            os.kill(tcpdump, signal.SIGINT)
        except ProcessLookupError as error:
            raise _error("tcpdump stopped before the collector stopped it") from error
        except PermissionError as error:
            raise _error("tcpdump refused the operator's interrupt") from error

    def _tcpdump_process_id(self, process: subprocess.Popen[bytes], *, timeout: int) -> int:
        """Return the PID of the one tcpdump that this capture's sudo runs.

        sudo forks tcpdump, or executes it in place when its policy defines no
        close function (sudo(8), "Process model"); without a terminal sudo
        uses no pty, so tcpdump stays in sudo's process group. Once tcpdump
        has opened the device, -Z leaves its real, effective and saved user
        IDs the operator's, and the kernel delivers the operator's signal only
        to a process whose real or saved user ID is the operator's. A tcpdump
        that has exited, or no tcpdump once sudo has exited, fails as a
        capture that stopped itself; a sudo that is still running without its
        tcpdump fails as not running one. Each refusal notes the rows of
        sudo's process group.
        """

        receipt = _run_collector_command(
            self,
            ["/bin/ps", "-x", "-g", str(process.pid), "-o", CAPTURE_PROCESS_COLUMNS],
            timeout=timeout,
            label="tcpdump process observation",
        )
        rows = _capture_process_rows(receipt["stdout"])
        tcpdumps = [
            row
            for row in rows
            if process.pid in (row.pid, row.parent) and row.name == "tcpdump"
        ]

        def refusal(message: str) -> GARuntimeAcceptanceError:
            error = _error(message)
            shown = [row.note() for row in rows[:CAPTURE_PROCESS_NOTE_ROWS]]
            if len(rows) > len(shown):
                shown.append(f"{len(rows) - len(shown)} more")
            error.add_note(
                f"processes in the group of this capture's sudo: {'; '.join(shown)}"
            )
            return error

        if any(row.state.startswith("Z") for row in tcpdumps) or (
            not tcpdumps and process.poll() is not None
        ):
            raise refusal("tcpdump stopped before the collector stopped it")
        if len(tcpdumps) != 1:
            raise refusal("tcpdump is not one process under its sudo")
        (tcpdump,) = tcpdumps
        if tcpdump.user_ids != (os.getuid(),) * 3:
            raise refusal("tcpdump still runs as a user other than the operator")
        return tcpdump.pid

    def _capture_traffic_bytes(
        self,
        check_id: str,
        tokens: dict[str, str],
        *,
        interpreter: str,
    ) -> tuple[dict[str, Any], bytes]:
        exercise_deadline = time.monotonic() + PACKET_EXERCISE_SECONDS

        def remaining_seconds() -> int:
            remaining = exercise_deadline - time.monotonic()
            if remaining < 1:
                raise _error("packet exercise exceeded its complete bounded deadline")
            return int(remaining)

        policy = TRAFFIC_POLICY[check_id]
        interface = self._tunnel_interface()
        remaining_seconds()
        filter_argv = _traffic_capture_filter_argv(check_id, tokens)
        capture_argv = _capture_command_argv(interface, filter_argv)
        # tcpdump writes its pcap into an unlinked private file, which never
        # fills, instead of a pipe: the collector reads nothing from tcpdump
        # while a sender runs, and a thread draining a pipe that outlived a
        # failed capture would make every later Packet Host launch refuse as
        # multithreaded. The cap bounds the file.
        started_at = _utc_now()
        try:
            capture_file = tempfile.TemporaryFile(buffering=0)
        except OSError as error:
            raise _error("tcpdump capture file could not be created") from error
        try:
            process = subprocess.Popen(
                capture_argv,
                cwd=self.repository,
                env=self.environment,
                stdin=subprocess.PIPE,
                stdout=capture_file,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except BaseException as error:
            # Only an OSError is the start's own failure. The file is closed
            # either way; if that fails, the close failure is raised from the
            # start's failure, while an interrupt is re-raised as it is.
            start_failure = error
            if isinstance(error, OSError):
                start_failure = _error("fixed tcpdump capture could not start")
                start_failure.__cause__ = error
            try:
                capture_file.close()
            except OSError as close_error:
                if not isinstance(start_failure, Exception):
                    start_failure.add_note(
                        f"tcpdump capture file could not be closed: {close_error!r}"
                    )
                    raise start_failure from None
                close_failure = _error("tcpdump capture file could not be closed")
                close_failure.add_note(f"{close_failure}: {close_error!r}")
                raise close_failure from start_failure
            raise start_failure
        prefix = bytearray()
        selector: selectors.BaseSelector | None = None
        primary: BaseException | None = None
        cleanup_failure: GARuntimeAcceptanceError | None = None
        result: tuple[dict[str, Any], bytes] | None = None
        send_commands: list[dict[str, Any]] = []
        capture_bytes = b""
        remaining_stderr = b""
        output_complete = False
        try:
            if process.stderr is None or process.stdin is None:
                raise _error("fixed tcpdump capture pipes are unavailable")
            # The credential is sent only to sudo's private input pipe. It is
            # never an argv, environment value, file, log or evidence field.
            process.stdin.write(self._capture_password)
            process.stdin.close()
            process.stdin = None
            try:
                selector = selectors.DefaultSelector()
            except OSError as error:
                raise _error("tcpdump output selector is unavailable") from error
            os.set_blocking(process.stderr.fileno(), False)
            selector.register(process.stderr, selectors.EVENT_READ)
            deadline = min(exercise_deadline, time.monotonic() + 10)
            ready = False
            while time.monotonic() < deadline and not ready:
                if process.poll() is not None:
                    break
                for key, _events in selector.select(0.1):
                    try:
                        chunk = os.read(key.fd, 4096)
                    except BlockingIOError:
                        continue
                    prefix.extend(chunk)
                    if len(prefix) > MAX_COMMAND_OUTPUT_BYTES:
                        raise _error("tcpdump readiness output exceeded its bound")
                    ready = b"listening on" in prefix
            if not ready:
                raise _error("tcpdump did not reach its bounded listening state")
            for index, stage in enumerate(PACKET_STAGES):
                argv = _packet_sender_argv(
                    interpreter,
                    check_id=check_id,
                    stage=stage,
                    token=tokens[stage],
                    local_address=TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"],
                )
                timeout = remaining_seconds()
                receipt = self.run(argv, timeout=timeout)
                send_commands.append(receipt)
                # A failed start marker cannot authorize target/end traffic.
                # Check each actual sender before advancing the capture stage.
                _command(receipt, expected_argv=argv, expected_exit=0,
                         label=f"{check_id} {stage} collection sender",
                         maximum_seconds=timeout)
                remaining_seconds()
                if index < len(PACKET_STAGES) - 1:
                    if exercise_deadline - time.monotonic() <= 1.1:
                        raise _error("packet exercise has no time for the next marker")
                    time.sleep(1.1)
            if (
                exercise_deadline - time.monotonic()
                < CAPTURE_SETTLE_SECONDS + CAPTURE_STOP_SECONDS
            ):
                raise _error("packet exercise has no time for the capture settle and stop")
            time.sleep(CAPTURE_SETTLE_SECONDS)
            self._interrupt_capture(process, timeout=min(10, remaining_seconds()))
            try:
                _output, remaining_stderr = process.communicate(
                    timeout=remaining_seconds())
                output_complete = True
            except subprocess.TimeoutExpired as error:
                remaining_stderr = error.stderr or b""
                raise _error("tcpdump did not stop after the collector interrupted it") from error
            finished_at = _utc_now()
            capture_bytes = _capture_file_bytes(capture_file, MAX_PCAP_BYTES)
            stderr_bytes = bytes(prefix) + remaining_stderr
            if (
                process.returncode != 0
                or not capture_bytes
                or len(capture_bytes) > MAX_PCAP_BYTES
                or len(stderr_bytes) > MAX_COMMAND_OUTPUT_BYTES
            ):
                raise _error("tcpdump capture exit or output is invalid")
            try:
                stderr = stderr_bytes.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise _error("tcpdump stderr is not UTF-8") from error
            parsed = _require_capture_receipt(check_id, capture_bytes, stderr)
            link_types = {item.link_type for item in parsed.interfaces}
            if len(link_types) != 1:
                raise _error("tcpdump pcap has an ambiguous link type")
            capture_command = {
                "argv": capture_argv,
                "document": COMMAND_DOCUMENT,
                "exit_code": process.returncode,
                "finished_at": finished_at,
                "schema_version": SCHEMA_VERSION,
                "started_at": started_at,
                "stderr": stderr,
                "stdout": "",
            }
            send_results = [
                _packet_send_result(
                    _command(
                        receipt,
                        expected_argv=_packet_sender_argv(
                            interpreter,
                            check_id=check_id,
                            stage=stage,
                            token=tokens[stage],
                            local_address=TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"],
                        ),
                        expected_exit=0,
                        label=f"{check_id} {stage} collection sender",
                    ),
                    check_id=check_id,
                    stage=stage,
                    token=tokens[stage],
                    local_address=TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"],
                )
                for stage, receipt in zip(PACKET_STAGES, send_commands, strict=True)
            ]
            dns = policy["protocol"] == "dns"
            if dns:
                staged_endpoints = _tunnel_dns_stage_endpoints(check_id, capture_bytes, tokens)
                endpoint = {
                    "interface_name": interface,
                    "link_type": next(iter(link_types)),
                    "remote_port": policy["remote_port"],
                    "stage_families": _stage_families(staged_endpoints),
                }
            else:
                staged_endpoints = tuple(
                    StagedCaptureEndpoint(
                        stage=stage,
                        local_address=result["local_address"],
                        local_port=result["local_port"],
                        remote_address=result["remote_address"],
                        remote_port=result["remote_port"],
                    )
                    for stage, result in zip(PACKET_STAGES, send_results, strict=True)
                )
                endpoint = {
                    "family": "ipv4",
                    "interface_name": interface,
                    "link_type": next(iter(link_types)),
                    "local_address": TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"],
                    "remote_address": policy["remote_address"],
                    "remote_port": policy["remote_port"],
                }
            try:
                window_start, window_end = staged_marker_window(
                    capture_bytes,
                    "packet-pcap",
                    protocol=policy["protocol"],
                    family=TUNNEL_DNS_QUESTION_FAMILY if dns else "ipv4",
                    endpoints=staged_endpoints,
                    start_marker=tokens["start"].encode("ascii"),
                    end_marker=tokens["end"].encode("ascii"),
                    retransmissions=policy["retransmissions"],
                    dns_resolver_legs=TUNNEL_DNS_LEGS if dns else None,
                )
            except PacketCaptureError as error:
                raise _traffic_bytes_error(check_id) from error
            duration = (window_end - window_start) * 1000
            observation_ms = duration.numerator // duration.denominator
            _require_traffic_proof(
                check_id,
                capture_bytes,
                endpoint=endpoint,
                tokens=tokens,
                observation_ms=observation_ms,
                capture_command=capture_command,
                send_commands=send_commands,
                send_results=send_results,
            )
            remaining_seconds()
            result = (
                {
                    "capture_command": capture_command,
                    "endpoint": endpoint,
                    "observation_ms": observation_ms,
                    "send_commands": send_commands,
                },
                capture_bytes,
            )
        except OSError as error:
            primary = _error("tcpdump capture process I/O failed")
            primary.__cause__ = error
        except BaseException as error:
            primary = error
        finally:
            if primary is not None:
                try:
                    self._terminate_capture(process)
                except GARuntimeAcceptanceError as error:
                    cleanup_failure = error
                if isinstance(primary, Exception):
                    retention_errors: list[str] = []
                    retention_deadline = time.monotonic() + 3
                    captured_stderr = bytes(prefix) + remaining_stderr
                    try:
                        if output_complete:
                            stderr_retained = captured_stderr[:MAX_COMMAND_OUTPUT_BYTES]
                            stderr_complete = len(captured_stderr) <= MAX_COMMAND_OUTPUT_BYTES
                        elif process.stderr is None:
                            stderr_retained = captured_stderr[:MAX_COMMAND_OUTPUT_BYTES]
                            stderr_complete = False
                            retention_errors.append("stderr: pipe unavailable")
                        else:
                            stderr_retained, stderr_complete = _failed_capture_pipe_snapshot(
                                process.stderr,
                                captured_stderr,
                                MAX_COMMAND_OUTPUT_BYTES,
                                retention_deadline,
                            )
                    except (OSError, ValueError) as error:
                        stderr_retained = captured_stderr[:MAX_COMMAND_OUTPUT_BYTES]
                        stderr_complete = False
                        retention_errors.append(f"stderr: {type(error).__name__}")
                    # tcpdump keeps its stderr open until it exits, so the
                    # outputs are complete only with that pipe's end: then the
                    # pcap file holds everything tcpdump wrote.
                    try:
                        written = _capture_file_bytes(capture_file, MAX_PCAP_BYTES)
                        packet_retained = written[:MAX_PCAP_BYTES]
                        packet_complete = len(written) <= MAX_PCAP_BYTES
                    except (OSError, ValueError) as error:
                        packet_retained, packet_complete = b"", False
                        retention_errors.append(f"pcap: {type(error).__name__}")
                    if not isinstance(primary, GARuntimeAcceptanceError):
                        wrapped = _error(str(primary))
                        wrapped.__cause__ = primary
                        primary = wrapped
                    primary.packet_capture_failure = FailedPacketCaptureEvidence(
                        check_id=check_id,
                        command={"argv": capture_argv, "exit_code": process.returncode,
                                 "started_at": started_at, "finished_at": _utc_now(),
                                 "acceptance_valid": False},
                        sudo_pid=process.pid,
                        send_commands=tuple(send_commands),
                        packet_bytes=packet_retained, stderr_bytes=stderr_retained,
                        outputs_complete=packet_complete and stderr_complete,
                        retention_errors=tuple(retention_errors),
                    )
                    for note in _failed_capture_notes(primary.packet_capture_failure):
                        primary.add_note(note)
            if selector is not None:
                try:
                    selector.close()
                except OSError as error:
                    cleanup_failure = _cleanup_failure(
                        cleanup_failure, "tcpdump output selector could not be closed", error
                    )
            for stream in (process.stdout, process.stderr, process.stdin):
                if stream is None:
                    continue
                try:
                    stream.close()
                except OSError as error:
                    cleanup_failure = _cleanup_failure(
                        cleanup_failure, "tcpdump capture pipes could not be closed", error
                    )
            try:
                capture_file.close()
            except OSError as error:
                cleanup_failure = _cleanup_failure(
                    cleanup_failure, "tcpdump capture file could not be closed", error
                )
        if cleanup_failure is not None:
            if primary is None:
                raise cleanup_failure
            # The primary failure becomes the cleanup failure's cause, or an
            # interrupt is re-raised as it is, as at the start; either way the
            # cleanup failure stays visible as a note with its own cause.
            cause = cleanup_failure.__cause__
            headline = str(cleanup_failure) if cause is None else f"{cleanup_failure}: {cause!r}"
            if not isinstance(primary, Exception):
                primary.add_note(headline)
                for note in getattr(cleanup_failure, "__notes__", ()):
                    primary.add_note(note)
                raise primary
            if cause is not None:
                cleanup_failure.add_note(headline)
            raise cleanup_failure from primary
        if primary is not None:
            raise primary
        if result is not None:
            return result
        raise _error("tcpdump capture ended without a result")

    def capture_traffic(
        self,
        check_id: str,
        tokens: dict[str, str],
        *,
        interpreter: str,
    ) -> tuple[dict[str, Any], bytes]:
        """Capture traffic only while the authenticated signed Host reports test state.

        Each sender runs with ``interpreter``, the collection's recorded Python.
        """

        captured: dict[str, object] = {}

        def begin_capture(_baseline: object) -> PacketCaptureDisposition:
            return PacketCaptureDisposition.COMPLETE

        def exercise_test(_test: object) -> PacketCaptureDisposition:
            traffic, capture = self._capture_traffic_bytes(
                check_id, tokens, interpreter=interpreter
            )
            captured["traffic"] = traffic
            captured["capture"] = capture
            return PacketCaptureDisposition.COMPLETE

        def finish_capture(_terminal: object) -> PacketCaptureDisposition:
            return PacketCaptureDisposition.COMPLETE

        try:
            receipt = self._run_packet_host_transaction(
                case_id=TRAFFIC_POLICY[check_id]["case_id"],
                begin_capture=begin_capture,
                exercise_test=exercise_test,
                finish_capture=finish_capture,
            )
        except PacketHostError as error:
            raise _error(
                "authenticated installed Packet Host traffic transaction failed closed"
            ) from error
        traffic = captured.get("traffic")
        capture = captured.get("capture")
        if not isinstance(traffic, dict) or not isinstance(capture, bytes):
            raise _error("authenticated Packet Host omitted the traffic capture callback")
        traffic["host_observation"] = _packet_host_receipt_document(receipt)
        return traffic, capture

    def capture_stop_restore(self) -> dict[str, Any]:
        """Drive the source-owned Off case and retain its exact Host receipt."""

        def complete(_stage: object) -> PacketCaptureDisposition:
            return PacketCaptureDisposition.COMPLETE

        try:
            receipt = self._run_packet_host_transaction(
                case_id="stop-cleanup",
                begin_capture=complete,
                exercise_test=complete,
                finish_capture=complete,
            )
        except PacketHostError as error:
            raise _error(
                "authenticated installed Packet Host stop/restore transaction failed closed"
            ) from error
        return _packet_host_receipt_document(receipt)

    def await_host_absence(self, *, timeout: int) -> dict[str, Any]:
        """Observe, bounded, that the dashboard Host is absent.

        Callers use it only once the Host should already be gone: after the
        operator-quit wait saw it exit, or when recovery found no Host. It
        sends the Host nothing.
        """

        if type(timeout) is not int or not 1 <= timeout <= 120:
            raise _error("installed Host absence timeout is outside 1..120 seconds")
        return self._poll_host_absence(
            timeout,
            expired=(
                f"installed Host was still running when its {timeout}-second "
                "absence observation ended"
            ),
        )

    def await_operator_quit(self) -> dict[str, Any]:
        """Ask the operator once for the graceful quit, then poll until the Host exits.

        The operator bound is fixed here rather than chosen by a caller, so
        every await_host_absence caller keeps its 1..120 second bound.
        """

        print(OPERATOR_QUIT_INSTRUCTION, file=sys.stderr, flush=True)
        return self._poll_host_absence(
            OPERATOR_QUIT_SECONDS,
            expired=(
                "installed Host did not exit within the "
                f"{OPERATOR_QUIT_SECONDS // 60}-minute operator quit bound"
            ),
        )

    def _poll_host_absence(self, timeout: int, *, expired: str) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            receipt = _run_collector_command(
                self,
                list(PROCESS_OBSERVATION_COMMAND),
                timeout=min(10, timeout),
                label="installed Host shutdown process observation",
            )
            try:
                processes = dormant_app_install._parse_processes(receipt["stdout"])
            except dormant_app_install.InstallError as error:
                raise _error("installed Host shutdown process table is malformed") from error
            if not any(
                process["path"] == INSTALLED_EXECUTABLE.as_posix()
                for process in processes
            ):
                return receipt
            if time.monotonic() >= deadline:
                raise _error(expired)
            time.sleep(0.25)


def _run_collector_command(
    runtime: ProductionCollectorRuntime,
    argv: list[str],
    *,
    expected_exit: int = 0,
    timeout: int = 900,
    label: str,
) -> dict[str, Any]:
    return _command(
        runtime.run(argv, timeout=timeout),
        expected_argv=argv,
        expected_exit=expected_exit,
        label=label,
        maximum_seconds=timeout,
    )


def _collector_path(value: object, label: str) -> str:
    try:
        text = bounded_text(value, label, maximum=MAX_COLLECTOR_PATH_LENGTH)
    except PublicationError as error:
        raise _error(f"{label} is not a bounded path") from error
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or text.startswith("//")
        or path.as_posix() != text
        or ".." in path.parts
    ):
        raise _error(f"{label} is not a normalized absolute path")
    return text


def _collector(value: object, label: str) -> dict[str, Any]:
    """Validate the record of where and with which Python a collection ran.

    Only the shape is checked here. The receipts must match this record; the
    record need not match the verifier, whose checkout or release Python may
    be newer. The closed launcher admitted this Python when it collected.
    """

    collector = require_exact_keys(value, {"operator_root", "python"}, label)
    python = require_exact_keys(
        collector["python"], {"executable", "version"}, f"{label} Python"
    )
    _collector_path(collector["operator_root"], f"{label} operator root")
    _collector_path(python["executable"], f"{label} Python executable")
    if (
        not isinstance(python["version"], str)
        or PYTHON_VERSION_RE.fullmatch(python["version"]) is None
    ):
        raise _error(f"{label} Python version is not a release Python version")
    return collector


def _collector_identity(
    executable: str, operator_root: Path, version: str
) -> dict[str, Any]:
    """Record the operator checkout and release Python running a collection.

    ``executable`` is the exact ``sys.executable`` string that every sender
    argv starts with. The closed launcher already admitted that Python, so
    the record names it rather than proving it again.
    """

    return _collector(
        {
            "operator_root": str(operator_root),
            "python": {"executable": executable, "version": version},
        },
        "GA runtime collector identity",
    )


def _collection_intent(
    expected: dict[str, Any],
    collection: dict[str, str],
    baseline: dict[str, Any],
    collector: dict[str, Any],
) -> dict[str, Any]:
    return {
        "cfw_guard_baseline": _guard(baseline, "collection intent baseline"),
        "collection": collection,
        "collector": collector,
        "document": COLLECTION_DOCUMENT,
        "journal_bindings": {
            key: expected[key]
            for key in ("install_journal_sha256", "service_journal_tree_sha256")
        },
        "package_bindings": {
            key: expected[key]
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


def _publish_collection_intent(
    repository: Path,
    expected: dict[str, Any],
    collection: dict[str, str],
    baseline: dict[str, Any],
    collector: dict[str, Any],
) -> Path:
    path = repository.joinpath(*COLLECTION_RELATIVE.parts)
    parent = path.parent
    with exclusive_rooted_directory_lock(
        repository, parent, require_private=True
    ) as descriptor:
        if os.path.lexists(path):
            raise _error(UNFINISHED_COLLECTION_REFUSAL)
        publish_private_directory_locked(
            descriptor,
            parent,
            path.name,
            {
                "intent.json": canonical_json(
                    _collection_intent(expected, collection, baseline, collector)
                )
            },
        )
    return path


def _append_collection_event(
    repository: Path,
    collection_path: Path,
    collection: dict[str, str],
    *,
    phase: str,
    step: str,
    command: list[str] | None = None,
    expected_sequence: int | None = None,
) -> None:
    # The collection holds only its intent and events, so each event is staged
    # in the unlocked acceptance root and renamed into the locked collection
    # only when complete; a crash can leave only an unread staging file there.
    with exclusive_rooted_directory_lock_with_parent(
        repository, collection_path, require_private=True
    ) as (staging_descriptor, descriptor):
        names = os.listdir(descriptor)
        events = sorted(name for name in names if re.fullmatch(r"event-[0-9]{3}\.json", name))
        if expected_sequence is not None and len(events) != expected_sequence:
            raise _error(
                f"GA runtime collection {phase} event requires sequence "
                f"{expected_sequence}, but the collection holds {len(events)} events"
            )
        name = f"event-{len(events):03d}.json"
        document = {
            "collection": collection,
            "command_sha256": (
                None if command is None else sha256_bytes(canonical_json(command))
            ),
            "document": COLLECTION_EVENT_DOCUMENT,
            "phase": phase,
            "schema_version": SCHEMA_VERSION,
            "sequence": len(events),
            "step": step,
        }
        publish_private_file_locked(
            staging_descriptor=staging_descriptor,
            staging_directory=collection_path.parent,
            destination_descriptor=descriptor,
            destination_directory=collection_path,
            name=name,
            data=canonical_json(document),
        )


def _append_raw_published_marker(
    repository: Path, collection_path: Path, collection: dict[str, str]
) -> None:
    # collect and resume-seal both write this marker; the sequence guard lets
    # only the first writer follow the fixed step events.
    _append_collection_event(
        repository,
        collection_path,
        collection,
        phase=RAW_PUBLISHED_PAIR[0],
        step=RAW_PUBLISHED_PAIR[1],
        expected_sequence=len(COLLECTION_STEP_PAIRS),
    )


# An operator note names at most this many entries that are not the log's own.
UNEXPECTED_ENTRY_NOTE_LIMIT: Final = 8


def _unexpected_entries_note(names: list[str]) -> str:
    """Name entries for a terminal: JSON escapes every control character."""

    shown = ", ".join(json.dumps(name) for name in names[:UNEXPECTED_ENTRY_NOTE_LIMIT])
    hidden = len(names) - UNEXPECTED_ENTRY_NOTE_LIMIT
    more = f" and {hidden} more" if hidden > 0 else ""
    return f"GA runtime collection holds unexpected entries: {shown}{more}"


def _read_collection_events(
    repository: Path, collection: dict[str, str], expected_intent: bytes
) -> tuple[tuple[tuple[Any, Any], ...], list[dict[str, Any]]]:
    path = repository.joinpath(*COLLECTION_RELATIVE.parts)
    with exclusive_rooted_directory_lock(
        repository, path, require_private=True
    ) as descriptor:
        names = os.listdir(descriptor)
        event_names = sorted(
            name for name in names if re.fullmatch(r"event-[0-9]{3}\.json", name)
        )
        expected_names = {"intent.json", *event_names}
        if set(names) != expected_names:
            error = _error("GA runtime collection contains an unexpected transaction file")
            unexpected = sorted(set(names) - expected_names)
            if unexpected:
                error.add_note(_unexpected_entries_note(unexpected))
            raise error
        intent_data = read_private_pending_locked(
            descriptor, path, "intent.json", MAX_JSON_BYTES
        )
        if intent_data != expected_intent:
            raise _error("GA runtime collection intent changed during verification")
        entries = [
            {
                "path": "intent.json",
                "sha256": sha256_bytes(intent_data),
                "size": len(intent_data),
                "type": "file",
            }
        ]
        events = []
        for index, name in enumerate(event_names):
            if name != f"event-{index:03d}.json":
                raise _error("GA runtime collection event sequence has a gap")
            data = read_private_pending_locked(
                descriptor, path, name, MAX_JSON_BYTES
            )
            entries.append(
                {
                    "path": name,
                    "sha256": sha256_bytes(data),
                    "size": len(data),
                    "type": "file",
                }
            )
            event = require_exact_keys(
                _strict_json(data, f"GA runtime {name}"),
                {
                    "collection",
                    "command_sha256",
                    "document",
                    "phase",
                    "schema_version",
                    "sequence",
                    "step",
                },
                f"GA runtime {name}",
            )
            if (
                event["collection"] != collection
                or event["document"] != COLLECTION_EVENT_DOCUMENT
                or type(event["schema_version"]) is not int
                or event["schema_version"] != SCHEMA_VERSION
                or type(event["sequence"]) is not int
                or event["sequence"] != index
            ):
                raise _error("GA runtime collection event identity is invalid")
            if event["command_sha256"] is not None:
                require_sha256(event["command_sha256"], "collection command digest")
            events.append(event)
    return tuple((event["phase"], event["step"]) for event in events), entries


def _validate_collection_receipt(
    repository: Path, collection: dict[str, str], expected_intent: bytes
) -> dict[str, str]:
    observed_pairs, entries = _read_collection_events(
        repository, collection, expected_intent
    )
    if observed_pairs != COMPLETED_COLLECTION_PAIRS:
        raise _error("GA runtime collection did not complete the fixed command registry")
    return {
        "path": COLLECTION_RELATIVE.as_posix(),
        "sha256": tree_digest(sorted(entries, key=lambda entry: str(entry["path"]))),
    }


def _raw_files_from_documents(
    documents: dict[str, dict[str, Any]], pcaps: dict[str, bytes]
) -> dict[str, bytes]:
    without_scan = {
        name: canonical_json(value)
        for name, value in documents.items()
        if name != "credential-leak-scan.json"
    }
    corpus_bytes = {**without_scan, **pcaps}
    documents["credential-leak-scan.json"] = {
        "check_id": "credential_leak_scan",
        "collection": next(iter(documents.values()))["collection"],
        "corpus": [
            {"path": name, "sha256": sha256_bytes(data), "size": len(data)}
            for name, data in sorted(corpus_bytes.items())
        ],
        "document": CHECK_DOCUMENT,
        "pattern_policy": SECRET_POLICY,
        "schema_version": SCHEMA_VERSION,
    }
    files = {name: canonical_json(value) for name, value in documents.items()}
    files.update(pcaps)
    if set(files) != set(RAW_FILE_NAMES):
        raise _error("collector did not produce the exact GA runtime raw file set")
    return files


def _snapshots_from_collector_bytes(files: dict[str, bytes]) -> dict[str, FileSnapshot]:
    if set(files) != set(RAW_FILE_NAMES):
        raise _error("collector bytes do not have the exact raw file set")
    return {
        name: FileSnapshot(
            relative=name,
            data=data,
            size=len(data),
            sha256=sha256_bytes(data),
            identity=(0, 0, len(data), 0, 0o100600, 1),
        )
        for name, data in sorted(files.items())
    }


def _publish_collected_raw(
    repository: Path,
    files: dict[str, bytes],
) -> Path:
    raw_root = repository.joinpath(*RAW_ROOT_RELATIVE.parts)
    parent = raw_root.parent
    with exclusive_rooted_directory_lock(
        repository, parent, require_private=True
    ) as descriptor:
        if os.path.lexists(raw_root):
            raise _error("refusing to replace an existing GA runtime raw-evidence tree")
        publish_private_directory_locked(descriptor, parent, raw_root.name, files)
    return raw_root


def _pause_before_next_observation(deadline: float, interval: float) -> None:
    """Sleep one interval, cut short so that no observation starts after deadline."""

    time.sleep(min(interval, max(0.0, deadline - time.monotonic())))


def _accepted_receipt(
    runtime: ProductionCollectorRuntime,
    argv: list[str],
    *,
    label: str,
    expected_exit: int,
    timeout: int,
    accept: Callable[[dict[str, Any]], object],
    ready_seconds: int,
) -> dict[str, Any]:
    """Return the first whole observation of ``argv`` that ``accept`` admits.

    A command that fails its own boundary, and any rejection other than
    ObservationNotReady, ends the step at once. While ``accept`` finds the
    observed state not ready yet, the command runs again every
    READINESS_POLL_SECONDS, and no run starts after ``ready_seconds``; the
    last rejection is then the step's failure, noted with the wait it ended.
    """

    deadline = time.monotonic() + ready_seconds
    observations = 0
    while True:
        receipt = _run_collector_command(
            runtime,
            argv,
            expected_exit=expected_exit,
            timeout=timeout,
            label=label,
        )
        observations += 1
        try:
            accept(receipt)
            return receipt
        except ObservationNotReady as error:
            if time.monotonic() >= deadline:
                error.add_note(
                    f"{label} was not ready after {observations} observation"
                    f"{'' if observations == 1 else 's'} within {ready_seconds} s"
                )
                raise
        _pause_before_next_observation(deadline, READINESS_POLL_SECONDS)


def _step_command(
    repository: Path,
    collection_path: Path,
    collection: dict[str, str],
    runtime: ProductionCollectorRuntime,
    *,
    step: str,
    argv: list[str],
    accept: Callable[[dict[str, Any]], object],
    expected_exit: int = 0,
    timeout: int = 900,
    ready_seconds: int = 0,
) -> dict[str, Any]:
    """Run one fixed command between its durable started and completed events.

    ``accept`` validates the receipt's contents before the step completes, so
    a rejected receipt ends the collection at its own step, and the one
    accepted observation is the step's receipt. Only a step that observes
    state, never one that changes it, passes ``ready_seconds``.
    """

    _append_collection_event(
        repository,
        collection_path,
        collection,
        phase="started",
        step=step,
        command=argv,
    )
    receipt = _accepted_receipt(
        runtime,
        argv,
        label=f"GA collection {step}",
        expected_exit=expected_exit,
        timeout=timeout,
        accept=accept,
        ready_seconds=ready_seconds,
    )
    _append_collection_event(
        repository,
        collection_path,
        collection,
        phase="completed",
        step=step,
        command=argv,
    )
    return receipt


def _step_host_absence(
    repository: Path,
    collection_path: Path,
    collection: dict[str, str],
    runtime: ProductionCollectorRuntime,
    *,
    step: str,
    timeout: int,
) -> dict[str, Any]:
    argv = list(PROCESS_OBSERVATION_COMMAND)
    _append_collection_event(
        repository,
        collection_path,
        collection,
        phase="started",
        step=step,
        command=argv,
    )
    receipt = runtime.await_host_absence(timeout=timeout)
    _host_absence_observation(receipt)
    _append_collection_event(
        repository,
        collection_path,
        collection,
        phase="completed",
        step=step,
        command=argv,
    )
    return receipt


def _step_operator_quit(
    repository: Path,
    collection_path: Path,
    collection: dict[str, str],
    runtime: ProductionCollectorRuntime,
    *,
    step: str,
) -> dict[str, str]:
    """After the durable started event, let the runtime ask once for the quit.

    The wait is bounded and no command is sent to the Host; only the process
    table is observed. The returned record is the instruction that was issued.
    """

    _append_collection_event(
        repository, collection_path, collection, phase="started", step=step
    )
    _host_absence_observation(runtime.await_operator_quit())
    _append_collection_event(
        repository, collection_path, collection, phase="completed", step=step
    )
    return dict(OPERATOR_QUIT_REQUEST)


def _settled_guard(
    runtime: ProductionCollectorRuntime,
    baseline: dict[str, Any],
    *,
    label: str,
    mismatch: str,
) -> dict[str, Any]:
    """Return the first observed guard that equals ``baseline``.

    A guard that differs is observed again once a second, and no observation
    starts after GUARD_SETTLE_SECONDS; the last one that still differs fails
    with ``mismatch``, noting which guard keys differ but none of their
    values. A malformed or unobservable guard fails at once.
    """

    deadline = time.monotonic() + GUARD_SETTLE_SECONDS
    while True:
        observed = runtime.capture_guard()
        _guard(observed, label)
        if observed == baseline:
            return observed
        if time.monotonic() >= deadline:
            error = _error(mismatch)
            differing = ", ".join(key for key in sorted(baseline) if observed[key] != baseline[key])
            error.add_note(
                f"{label} guard still differs from its baseline in {differing} after "
                f"{GUARD_SETTLE_SECONDS} s"
            )
            raise error
        _pause_before_next_observation(deadline, GUARD_SETTLE_INTERVAL_SECONDS)


# A guard keeps only digests, so recovery reads these raw observations itself
# when it judges a whole-system baseline by Clash for Mac remnants.
RECOVERY_NETWORK_OBSERVATIONS: Final = (
    ("interface", ("/sbin/ifconfig",)),
    ("IPv4 route", ("/usr/sbin/netstat", "-rn", "-f", "inet")),
    ("IPv6 route", ("/usr/sbin/netstat", "-rn", "-f", "inet6")),
    ("DNS", ("/usr/sbin/scutil", "--dns")),
    ("system proxy", ("/usr/sbin/scutil", "--proxy")),
)
SCUTIL_NAMESERVER_RE: Final = re.compile(r"\s*nameserver\[[0-9]+\]\s*:\s*(\S+)\s*")
# `scutil --proxy` prints one container opener, scalar or closing brace a
# line. The effective configuration nests a `__SCOPED__` dictionary of
# per-interface proxy dictionaries and a `__SUPPLEMENTAL__` array of proxy
# dictionaries, neither inside the other, as the product's own
# CurrentSystemProxySwitchObserver reads it.
SCUTIL_CONTAINER_RE: Final = re.compile(r"\s*(?:(\S+) : )?<(dictionary|array)> \{\s*")
SCUTIL_SCALAR_RE: Final = re.compile(r"\s*(\S+) :(?: .*)?")
PROXY_SCOPE_CONTAINERS: Final = {"__SCOPED__": "dictionary", "__SUPPLEMENTAL__": "array"}
PROXY_SCOPE_NAMES: Final = {
    "__SCOPED__": re.compile(r"[A-Za-z0-9]{1,32}"),
    "__SUPPLEMENTAL__": re.compile(r"[0-9]{1,3}"),
}


def _inert(token: str) -> str:
    """An observed token as printed when it is visible ASCII, else JSON-escaped."""

    return token if re.fullmatch(r"[!-~]+", token) else json.dumps(token)


def _observed_address(
    text: str, label: str
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(text.partition("%")[0])
    except ValueError as error:
        raise _error(
            f"runtime recovery {label} observation names a malformed address"
        ) from error


def _netstat_host(field: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The single host a netstat destination or gateway names, if it names one.

    ``default``, ``link#N``, link-layer addresses, abbreviated networks and
    any prefix shorter than a host's name no single host.
    """

    text, separator, prefix = field.partition("/")
    try:
        address = ipaddress.ip_address(text.partition("%")[0])
    except ValueError:
        return None
    if separator and prefix != str(address.max_prefixlen):
        return None
    return address


def _cfm_tunnel_remnants(observations: dict[str, str]) -> list[str]:
    """Name each utun, route and system resolver left with tunnel-plan state.

    A utun is the Packet Tunnel's when it carries a tunnel-plan local address;
    every route through it, the tunnel's own scoped defaults included, is a
    remnant, as is any route whose destination or gateway is a tunnel-plan
    host and any resolver at a tunnel DNS peer. The scoped IPv6 defaults of
    macOS's own link-local utuns are none of these.
    """

    remnants: list[str] = []
    utuns: set[str] = set()
    for name, lines in json.loads(tunnel_interfaces(observations["interface"])).items():
        for line in lines:
            fields = line.split()
            if not fields or fields[0] not in ("inet", "inet6"):
                continue
            if len(fields) < 2:
                raise NetworkObservationError(f"{name} has an address line without an address")
            address = _observed_address(fields[1], "interface")
            if address in CFM_TUNNEL_LOCAL_ADDRESSES:
                utuns.add(name)
                remnants.append(f"{name} carries the Clash for Mac tunnel address {address}")
    tunnel_addresses = CFM_TUNNEL_LOCAL_ADDRESSES | CFM_TUNNEL_DNS_PEERS
    for family in ("IPv4 route", "IPv6 route"):
        for row in json.loads(network_routes(observations[family])):
            destination, gateway, flags, interface = row[:4]
            if interface in utuns:
                remnants.append(
                    f"scoped default route through {interface}"
                    if destination == "default" and "I" in flags
                    else f"route {_inert(destination)} through {interface}"
                )
            elif {_netstat_host(destination), _netstat_host(gateway)} & tunnel_addresses:
                remnants.append(
                    f"route {_inert(destination)} via {_inert(gateway)} on "
                    f"{_inert(interface)} to a Clash for Mac tunnel address"
                )
    dns = observations["DNS"]
    dormant_app_install.require_dns_observation(dns)
    resolvers: list[str] = []
    for line in dns.splitlines():
        match = SCUTIL_NAMESERVER_RE.fullmatch(line)
        if match is None:
            if line.lstrip().startswith("nameserver["):
                raise NetworkObservationError("DNS observation has a malformed nameserver line")
            continue
        address = _observed_address(match[1], "DNS")
        if address in CFM_TUNNEL_DNS_PEERS:
            resolvers.append(f"DNS resolver at the Clash for Mac tunnel address {address}")
    # scutil lists each resolver again among the scoped ones.
    remnants.extend(dict.fromkeys(resolvers))
    return remnants


def _proxy_dictionary_path(path: tuple[str, ...]) -> bool:
    """Whether an admitted container path is a proxy dictionary.

    The global one is the root; each scoped or supplemental one sits directly
    in its scope container.
    """

    return not path or (len(path) == 2 and path[0] in PROXY_SCOPE_CONTAINERS)


def _proxy_container_admitted(path: tuple[str, ...], kind: str) -> bool:
    """Whether `scutil --proxy` nests a container of this kind at this path.

    Only the global proxy dictionary holds the `__SCOPED__` dictionary of
    per-interface proxy dictionaries and the `__SUPPLEMENTAL__` array of
    proxy dictionaries. A proxy dictionary nests nothing else but arrays of
    scalars, such as its ExceptionsList.
    """

    if not path:
        return kind == "dictionary"
    if len(path) == 1 and path[0] in PROXY_SCOPE_CONTAINERS:
        return kind == PROXY_SCOPE_CONTAINERS[path[0]]
    if len(path) == 2 and path[0] in PROXY_SCOPE_CONTAINERS:
        return (
            kind == "dictionary"
            and PROXY_SCOPE_NAMES[path[0]].fullmatch(path[1]) is not None
        )
    return (
        kind == "array"
        and path[-1] not in PROXY_SCOPE_CONTAINERS
        and _proxy_dictionary_path(path[:-1])
    )


def _system_proxy_dictionaries(proxy: str) -> list[tuple[str, str]]:
    """Split `scutil --proxy` into each proxy dictionary, after its scope.

    Each body keeps only its dictionary's own scalar lines, so the installer's
    field parser refuses a field repeated within one dictionary, never one a
    scoped or supplemental copy repeats. Any container that
    _proxy_container_admitted does not admit is malformed, so no proxy
    dictionary can sit where neither the pre-flight nor recovery reads it.
    """

    malformed = "system proxy observation nests its dictionaries in an unknown shape"
    frames: list[tuple[str, ...]] = []
    kinds: dict[tuple[str, ...], str] = {}
    bodies: dict[tuple[str, ...], list[str]] = {}
    closed = False
    for line in proxy.splitlines():
        if closed:
            raise NetworkObservationError(malformed)
        container = SCUTIL_CONTAINER_RE.fullmatch(line)
        if container is not None:
            key, kind = container[1], container[2]
            if (key is None) != (not kinds) or (key is not None and not frames):
                raise NetworkObservationError(malformed)
            path = () if key is None else (*frames[-1], key)
            if path in kinds or not _proxy_container_admitted(path, kind):
                raise NetworkObservationError(malformed)
            frames.append(path)
            kinds[path] = kind
            if kind == "dictionary":
                bodies[path] = []
            continue
        if line.strip() == "}" and frames:
            frames.pop()
            closed = not frames
            continue
        scalar = SCUTIL_SCALAR_RE.fullmatch(line)
        if scalar is None or not frames or scalar[1] in PROXY_SCOPE_CONTAINERS:
            raise NetworkObservationError(malformed)
        if len(frames[-1]) == 1 and frames[-1][0] in PROXY_SCOPE_CONTAINERS:
            raise NetworkObservationError(malformed)
        if kinds[frames[-1]] == "dictionary":
            bodies[frames[-1]].append(line)
    if not closed:
        raise NetworkObservationError(malformed)
    dictionaries: list[tuple[str, str]] = []
    for path, body in bodies.items():
        if not _proxy_dictionary_path(path):
            continue
        if not path:
            label = ""
        elif path[0] == "__SCOPED__":
            label = f" for {path[1]}"
        else:
            label = f" in supplemental entry {path[1]}"
        dictionaries.append((label, "\n".join(body)))
    return dictionaries


def _loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Any other host name is not where Clash for Mac's system proxy listens.
        return False


def _cfm_proxy_remnants(proxy: str, baseline_sha256: str) -> list[str]:
    """Name each loopback system proxy that differs from the baseline.

    The intent keeps only the baseline proxy's digest, so no field can be
    compared with it. The release owner's rule: the proxy is restored when it
    is byte-identical to the baseline, or when no HTTP, HTTPS or SOCKS proxy
    is enabled on a loopback host, where Clash for Mac's system proxy listens.
    The global, every per-interface and every supplemental proxy dictionary
    is judged; a switch other than 0 or 1 is malformed, as the product reads it.
    """

    dormant_app_install.require_system_proxy_observation(proxy)
    if dormant_app_install._observation_digest(proxy) == baseline_sha256:
        return []
    return _loopback_system_proxies(proxy, label="runtime recovery")


def _loopback_system_proxies(proxy: str, *, label: str) -> list[str]:
    """Name each enabled HTTP, HTTPS or SOCKS proxy on a loopback host.

    proxy is one complete `scutil --proxy` observation; its global, every
    per-interface and every supplemental dictionary is judged. A switch other
    than 0 or 1 is malformed, as the product reads it; label names the caller
    in the refusal of a switch on without a host.
    """

    found: list[str] = []
    for scope, body in _system_proxy_dictionaries(proxy):
        fields = dormant_app_install.parse_system_proxy_fields(body)
        for kind in ("HTTP", "HTTPS", "SOCKS"):
            switch = fields.get(f"{kind}Enable", "0")
            if switch not in ("0", "1"):
                raise NetworkObservationError(f"system proxy {kind}Enable is neither 0 nor 1")
            if switch == "0":
                continue
            host = fields.get(f"{kind}Proxy")
            if host is None:
                raise _error(
                    f"{label} system proxy observation enables {kind}{scope} "
                    "without a host"
                )
            if _loopback_host(host):
                port = fields.get(f"{kind}Port")
                shown = _inert(host)
                found.append(
                    f"{kind} system proxy{scope} on loopback host "
                    f"{f'[{shown}]' if ':' in host else shown}:"
                    f"{'unknown' if port is None else _inert(port)}"
                )
    return found


def _settle_without_cfm_remnants(
    runtime: ProductionCollectorRuntime, baseline: dict[str, Any]
) -> None:
    """Wait, within the guard's settle bound, until no Clash for Mac state is left.

    Without Clash for Windows the guard digests the whole system, which also
    changes for reasons of its own, so recovery requires only that no Clash
    for Mac network state remains. A malformed observation fails at once;
    remnants still present at the bound are each named.
    """

    deadline = time.monotonic() + GUARD_SETTLE_SECONDS
    while True:
        observations: dict[str, str] = {}
        for name, argv in RECOVERY_NETWORK_OBSERVATIONS:
            receipt = _run_collector_command(
                runtime,
                list(argv),
                timeout=30,
                label=f"runtime recovery {name} observation",
            )
            # The guard digests each command's whole output; so does this.
            observations[name] = receipt["stdout"] + receipt["stderr"]
        try:
            remnants = [
                *_cfm_tunnel_remnants(observations),
                *_cfm_proxy_remnants(observations["system proxy"], baseline["proxy_sha256"]),
            ]
        except (NetworkObservationError, dormant_app_install.InstallError) as error:
            raise _error("runtime recovery network observation is malformed") from error
        if not remnants:
            return
        if time.monotonic() >= deadline:
            # Another tool's loopback proxy or tunnel-plan address looks the same.
            raise _error(
                "runtime recovery found possible Clash for Mac network state after the "
                f"Off proof: {'; '.join(remnants)}"
            )
        _pause_before_next_observation(deadline, GUARD_SETTLE_INTERVAL_SECONDS)


def _require_before_collection_state(admission: Callable[[], None]) -> None:
    """Run one admission while nothing is recorded, so a refusal says to rerun."""

    try:
        admission()
    except GARuntimeAcceptanceError as error:
        error.add_note(PREFLIGHT_RETRY_GUIDANCE)
        raise


def _publish_intent_holding_capture_authority(
    runtime: ProductionCollectorRuntime,
    repository: Path,
    expected: dict[str, Any],
    collection: dict[str, str],
    baseline: dict[str, Any],
    collector: dict[str, Any],
) -> Path:
    """Prove the capture password, then publish the collection intent.

    The password is asked for and proven while nothing is recorded, so a run
    without a terminal, a mistyped password or an interrupt at the prompt
    leaves no attempt for recover to archive. It is released if either step
    fails; collect releases it on every later way out.
    """

    try:
        _require_before_collection_state(runtime.require_capture_authority)
        return _publish_collection_intent(
            repository, expected, collection, baseline, collector
        )
    except BaseException:
        runtime.release_capture_authority()
        raise


def collect_ga_runtime_acceptance(
    *,
    repository: Path,
    expected: object,
    prepackage_stage_verifier: PrepackageStageVerifier,
    runtime: ProductionCollectorRuntime | None = None,
    challenge_bytes: bytes | None = None,
    session_id: str | None = None,
) -> dict[str, dict[str, str]]:
    """Collect runtime evidence after the service and install owners close.

    No raw input path or raw byte payload is accepted.  The fresh CFW baseline
    and challenge are durably published before any runtime mutation. Raw
    documents are held by this process and the exact 15-file tree is atomically
    published only after the complete shutdown/restore boundary succeeds. A
    later failure leaves the runtime closed, so it is never marked for
    recovery; ``resume-seal`` completes the seal instead.
    """

    repository = _canonical_repository(repository)
    _acceptance_path, raw_root = _fixed_paths(repository)
    published = _published_runtime_outputs(repository)
    if published:
        raise _error(
            "GA runtime acceptance or raw evidence already exists "
            f"({', '.join(published)})"
        )
    # recover is the next step for an unfinished collection, whatever the Host
    # and VPN show; the intent's own publication checks this again, locked.
    if _fixed_path_present(repository.joinpath(*COLLECTION_RELATIVE.parts)):
        raise _error(UNFINISHED_COLLECTION_REFUSAL)
    initial = _validate_expected(expected)
    selected_runtime = runtime or ProductionCollectorRuntime(repository)
    _require_current_environment(
        repository,
        selected_runtime,
        initial["ga_environment_sha256"],
        label="GA runtime collection admission environment",
    )
    material = os.urandom(32) if challenge_bytes is None else challenge_bytes
    if not isinstance(material, bytes) or len(material) != 32:
        raise _error("GA runtime collection challenge must contain 32 CSPRNG bytes")
    selected_session = str(uuid.uuid4()) if session_id is None else session_id
    challenge = base64.urlsafe_b64encode(material).decode("ascii").rstrip("=")
    collection = _collection_binding(
        {
            "challenge": challenge,
            "ga_environment_sha256": initial["ga_environment_sha256"],
            "session_id": selected_session,
        },
        "GA runtime collection",
    )
    # Installation and collection are separate transactions. Validate the closed
    # installation history, then bind this run to the current complete CFW guard.
    _installed_guard_baseline(repository, initial)
    collector = _collector_identity(
        sys.executable, _operator_root(), platform.python_version()
    )
    # The baseline is the network without Clash for Mac, so a refusal here
    # leaves no collection state behind.
    _require_before_collection_state(
        selected_runtime.require_host_quit_and_tunnel_disconnected
    )
    before_guard = _guard(selected_runtime.capture_guard(), "collection baseline")
    collection_path = _publish_intent_holding_capture_authority(
        selected_runtime, repository, initial, collection, before_guard, collector
    )
    mutation_started = False
    raw_publication_started = False
    raw_published = False
    try:
        # Each step's receipt is validated as the step completes, so a bad
        # receipt before launch still ends the attempt before the mutation
        # boundary; the raw evidence is validated again in full at the end.
        gatekeeper = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="dmg-gatekeeper",
            argv=list(DMG_GATEKEEPER_COMMAND),
            accept=_dmg_gatekeeper_observation,
        )
        operator_root = Path(collector["operator_root"])
        dmg_verify = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="dmg-contained-app-byte-proof",
            argv=_dmg_verifier_command(operator_root, repository),
            timeout=DMG_BYTE_PROOF_TIMEOUT_SECONDS,
            accept=partial(
                _dmg_verifier_observation,
                repository=repository,
                operator_root=operator_root,
            ),
        )
        final_expected = initial
        installed_tree = _installed_candidate_tree(repository, final_expected)
        dmg_contained_tree = _dmg_contained_candidate_tree(
            repository,
            final_expected,
            prepackage_stage_verifier,
        )
        if installed_tree != dmg_contained_tree:
            raise _error("installed app differs from the byte-proven DMG-contained app")

        _require_current_environment(
            repository,
            selected_runtime,
            initial["ga_environment_sha256"],
            label="GA runtime pre-mutation environment",
        )
        # The restored guard must equal the baseline at the end, so a change
        # during the minutes of the DMG proof (a Clash for Windows restart,
        # another tool's proxy, DNS or route change) would otherwise fail the
        # run only after the launch, and need its full recovery. The guard is
        # judged here as the restored one is, settle included: a change still
        # being applied that settles back would pass at the end too, while one
        # that persists ends this attempt before its mutation boundary.
        _settled_guard(
            selected_runtime,
            before_guard,
            label="collection pre-launch",
            mismatch="CFW state changed after the collection baseline, before launch",
        )
        selected_runtime.require_host_quit_and_tunnel_disconnected()
        mutation_started = True
        launch = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step=MUTATION_BOUNDARY_STEP,
            argv=list(LAUNCH_COMMAND),
            timeout=120,
            accept=_launch_command_observation,
        )
        process_running = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="launch-process-observation",
            argv=list(PROCESS_OBSERVATION_COMMAND),
            timeout=60,
            accept=_running_host_observation,
            ready_seconds=LAUNCH_PROCESS_READY_SECONDS,
        )
        proxy = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="proxy-service-observation",
            argv=_proxy_agent_print_command(os.geteuid()),
            timeout=60,
            accept=_require_proxy_agent_running,
            ready_seconds=SERVICE_READY_SECONDS,
        )
        authority = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="authority-service-observation",
            argv=list(AUTHORITY_PRINT_COMMAND),
            timeout=60,
            accept=_require_global_authority_running,
            ready_seconds=SERVICE_READY_SECONDS,
        )
        rejections = [
            _step_command(
                repository,
                collection_path,
                collection,
                selected_runtime,
                step=f"high-risk-{probe[0]}",
                argv=list(probe[1]),
                expected_exit=probe[2],
                timeout=60,
                accept=partial(_high_risk_rejection_observation, probe=probe),
            )
            for probe in HIGH_RISK_PROBES
        ]
        documents: dict[str, dict[str, Any]] = {
            "exact-dmg-install.json": {
                "bindings": {
                    key: final_expected[key]
                    for key in (
                        "dmg_gatekeeper_sha256",
                        "dmg_set_seal_sha256",
                        "dmg_sha256",
                        "install_journal_sha256",
                        "service_journal_tree_sha256",
                    )
                },
                "check_id": "exact_dmg_install",
                "collection": collection,
                "commands": {
                    "dmg_gatekeeper": gatekeeper,
                    "dmg_set_verify": dmg_verify,
                },
                "document": CHECK_DOCUMENT,
                "dmg_contained_app_tree_sha256": dmg_contained_tree,
                "installed_app_tree_sha256": installed_tree,
                "schema_version": SCHEMA_VERSION,
            },
            "launch.json": {
                "check_id": "launch",
                "collection": collection,
                "document": CHECK_DOCUMENT,
                "launch_command": launch,
                "process_observation": process_running,
                "schema_version": SCHEMA_VERSION,
            },
            "service-registration.json": {
                "check_id": "service_registration",
                "collection": collection,
                "commands": {"global_authority": authority, "proxy_agent": proxy},
                "document": CHECK_DOCUMENT,
                "schema_version": SCHEMA_VERSION,
            },
            "high-risk-rejections.json": {
                "check_id": "high_risk_rejections",
                "collection": collection,
                "document": CHECK_DOCUMENT,
                "observations": rejections,
                "schema_version": SCHEMA_VERSION,
            },
        }
        pcaps: dict[str, bytes] = {}
        for check_id in TRAFFIC_CHECKS:
            tokens = {
                stage: _derive_capture_token(collection["challenge"], check_id, stage)
                for stage in PACKET_STAGES
            }
            _append_collection_event(
                repository,
                collection_path,
                collection,
                phase="started",
                step=f"traffic-{check_id}",
            )
            traffic, pcap = selected_runtime.capture_traffic(
                check_id, tokens, interpreter=collector["python"]["executable"]
            )
            _append_collection_event(
                repository,
                collection_path,
                collection,
                phase="completed",
                step=f"traffic-{check_id}",
            )
            pcap_name = f"{check_id.replace('_', '-')}.pcap"
            pcaps[pcap_name] = pcap
            documents[f"{check_id.replace('_', '-')}.json"] = {
                "capture": {
                    "kind": "packet-pcap",
                    "path": pcap_name,
                    "sha256": sha256_bytes(pcap),
                    "size": len(pcap),
                },
                "capture_command": traffic["capture_command"],
                "check_id": check_id,
                "collection": collection,
                "document": CHECK_DOCUMENT,
                "endpoint": traffic["endpoint"],
                "host_observation": traffic["host_observation"],
                "observation_ms": traffic["observation_ms"],
                "protocol": TRAFFIC_POLICY[check_id]["protocol"],
                "schema_version": SCHEMA_VERSION,
                "send_commands": traffic["send_commands"],
                "tokens": tokens,
            }
        selected_runtime.release_capture_authority()
        # The traffic transactions wait for the first macOS approval and
        # prove Tunnel readiness. Observe the enabled extension after that
        # boundary, while Tunnel is still active and before stop/restore.
        system_extension = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="system-extension-observation",
            argv=list(SYSTEM_EXTENSION_COMMAND),
            timeout=60,
            accept=_system_extension_observation,
        )
        documents["system-extension.json"] = {
            "check_id": "system_extension",
            "collection": collection,
            "command": system_extension,
            "document": CHECK_DOCUMENT,
            "schema_version": SCHEMA_VERSION,
        }
        _append_collection_event(
            repository,
            collection_path,
            collection,
            phase="started",
            step="network-extension-binding",
        )
        documents["network-extension.json"] = {
            "check_id": "network_extension",
            "collection": collection,
            "document": CHECK_DOCUMENT,
            "schema_version": SCHEMA_VERSION,
            "traffic_bindings": {
                check_id: {
                    "case_id": TRAFFIC_POLICY[check_id]["case_id"],
                    "host_observation_sha256": sha256_bytes(
                        canonical_json(
                            documents[f"{check_id.replace('_', '-')}.json"][
                                "host_observation"
                            ]
                        )
                    ),
                }
                for check_id in TRAFFIC_CHECKS
            },
        }
        _append_collection_event(
            repository,
            collection_path,
            collection,
            phase="completed",
            step="network-extension-binding",
        )
        _append_collection_event(
            repository,
            collection_path,
            collection,
            phase="started",
            step="shutdown-stop-restore",
        )
        stop_restore = selected_runtime.capture_stop_restore()
        _packet_host_receipt(
            stop_restore,
            expected_case_id="stop-cleanup",
            expected_test_phase="off",
        )
        _append_collection_event(
            repository,
            collection_path,
            collection,
            phase="completed",
            step="shutdown-stop-restore",
        )
        shutdown_request = _step_operator_quit(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="shutdown-request",
        )
        host_stopped = _step_host_absence(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="shutdown-host-process-observation",
            timeout=60,
        )
        off_proof = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="shutdown-off-proof",
            argv=list(OFF_PROOF_COMMAND),
            timeout=60,
            accept=partial(
                _validate_off_proof_receipt, label="candidate signed Host Off proof"
            ),
        )
        process_stopped = _step_host_absence(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="shutdown-process-observation",
            timeout=60,
        )
        after_guard = _settled_guard(
            selected_runtime,
            before_guard,
            label="collection restored",
            mismatch="collection did not restore the exact pre-run CFW state",
        )
        _require_current_environment(
            repository,
            selected_runtime,
            initial["ga_environment_sha256"],
            label="GA runtime post-restore environment",
        )
        documents["shutdown-restore.json"] = {
            "after_guard": after_guard,
            "before_guard": before_guard,
            "check_id": "shutdown_restore",
            "collection": collection,
            "document": CHECK_DOCUMENT,
            "host_process_observation": host_stopped,
            "off_proof_command": off_proof,
            "process_observation": process_stopped,
            "schema_version": SCHEMA_VERSION,
            "shutdown_request": shutdown_request,
            "stop_restore_observation": stop_restore,
        }
        documents["legacy-cfw-preserved.json"] = {
            "after_guard": after_guard,
            "before_guard": before_guard,
            "check_id": "legacy_cfw_preserved",
            "collection": collection,
            "document": CHECK_DOCUMENT,
            "install_journal_sha256": final_expected["install_journal_sha256"],
            "schema_version": SCHEMA_VERSION,
            "service_journal_tree_sha256": final_expected[
                "service_journal_tree_sha256"
            ],
        }
        files = _raw_files_from_documents(documents, pcaps)
        _validate_raw_evidence(
            repository,
            _snapshots_from_collector_bytes(files),
            final_expected,
            prepackage_stage_verifier,
        )
        raw_publication_started = True
        _publish_collected_raw(repository, files)
        # Shutdown, the Off proof, the exact CFW restore and the post-restore
        # environment were proven above and the complete raw tree is durable.
        # Nothing after this point needs runtime recovery; only sealing retries.
        raw_published = True
        _append_raw_published_marker(repository, collection_path, collection)
        result = seal_ga_runtime_acceptance(
            repository=repository,
            expected=final_expected,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        return result
    except (DurabilityOutcomeUnknown, RootedDirectoryChanged) as error:
        error.add_note(
            f"if runtime-evidence exists run {SEAL_RETRY_COMMAND}; otherwise run "
            f"{RECOVERY_COMMAND}; each command refuses the other's state"
        )
        raise
    except BaseException as error:
        try:
            # A publication that failed after its rename still left the tree.
            published = raw_published or (
                raw_publication_started and _fixed_path_present(raw_root)
            )
        except OSError as observation_error:
            unknown = DurabilityOutcomeUnknown(
                "GA runtime raw-evidence publication state is unobservable after a "
                "collection failure; inspect it before any retry"
            )
            unknown.add_note(
                "raw-evidence observation failed: "
                f"{type(observation_error).__name__}: {observation_error}"
            )
            raise unknown from error
        if published:
            raise GASealRetryRequired(
                "GA runtime raw evidence was published after the proven runtime "
                f"restore, but sealing did not complete; run {SEAL_RETRY_COMMAND} "
                "and never recover this collection"
            ) from error
        terminal = (
            RECOVERY_REQUIRED_PAIR if mutation_started else ABORTED_BEFORE_MUTATION_PAIR
        )
        try:
            _append_collection_event(
                repository,
                collection_path,
                collection,
                phase=terminal[0],
                step=terminal[1],
            )
        except BaseException as event_error:
            raise DurabilityOutcomeUnknown(
                "GA runtime collection failed and recovery state is unknown"
            ) from event_error
        if mutation_started:
            raise GACollectionRecoveryRequired(
                "GA runtime collection crossed the runtime boundary; run fixed recovery"
            ) from error
        error.add_note(PRE_MUTATION_ABORT_GUIDANCE)
        raise
    finally:
        selected_runtime.release_capture_authority()


def _load_collection_intent(
    repository: Path, collection_path: Path
) -> tuple[dict[str, Any], dict[str, str]]:
    with exclusive_rooted_directory_lock(
        repository, collection_path, require_private=True
    ) as descriptor:
        try:
            data = read_private_pending_locked(
                descriptor,
                collection_path,
                "intent.json",
                MAX_JSON_BYTES,
            )
        except PublicationError as error:
            raise _error("GA runtime collection intent cannot be reopened") from error
    intent = require_exact_keys(
        _strict_json(data, "GA runtime collection intent"),
        {
            "cfw_guard_baseline",
            "collection",
            "collector",
            "document",
            "journal_bindings",
            "package_bindings",
            "product",
            "schema_version",
        },
        "GA runtime collection intent",
    )
    collection = _collection_binding(intent["collection"], "collection intent")
    if (
        intent["document"] != COLLECTION_DOCUMENT
        or type(intent["schema_version"]) is not int
        or intent["schema_version"] != COLLECTION_INTENT_SCHEMA_VERSION
        or intent["product"]
        != {
            "from_build": FROM_BUILD,
            "to_build": TO_BUILD,
            "version": PRODUCT_VERSION,
        }
    ):
        raise _error("GA runtime collection intent identity is invalid")
    _guard(intent["cfw_guard_baseline"], "collection intent baseline")
    _collector(intent["collector"], "GA runtime collection intent collector")
    return intent, collection


def _collection_guard_baseline(
    repository: Path,
    intent: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any]:
    if intent["package_bindings"] != {
        key: expected[key]
        for key in ("dmg_gatekeeper_sha256", "dmg_set_seal_sha256", "dmg_sha256")
    }:
        raise _error("GA runtime collection intent binds different package evidence")
    _installed_guard_baseline(repository, expected)
    if intent["journal_bindings"] != {
        key: expected[key]
        for key in ("install_journal_sha256", "service_journal_tree_sha256")
    }:
        raise _error("GA runtime collection intent binds different migration journals")
    return _guard(intent["cfw_guard_baseline"], "collection intent baseline")


def _require_no_published_runtime_outputs(repository: Path) -> None:
    present = _published_runtime_outputs(repository)
    if present:
        raise _error(
            "GA runtime recovery refuses a collection whose evidence is already "
            f"published ({', '.join(present)}); recovery would orphan it, run "
            f"{SEAL_RETRY_COMMAND}"
        )


def _archive_recovered_collection(
    repository: Path,
    collection_path: Path,
    collection: dict[str, str],
) -> Path:
    parent = collection_path.parent
    destination = parent / f"runtime-collection-aborted-{collection['session_id']}"
    try:
        with exclusive_rooted_directory_lock(
            repository, parent, require_private=True
        ) as descriptor:
            # Raw publication and adapter promotion take this same parent lock.
            _require_no_published_runtime_outputs(repository)
            if os.path.lexists(destination):
                raise _error("recovered collection archive already exists")
            os.rename(
                collection_path.name,
                destination.name,
                src_dir_fd=descriptor,
                dst_dir_fd=descriptor,
            )
            try:
                from scripts.publication.durable_file import fsync_locked_directory

                fsync_locked_directory(descriptor, parent)
            except PublicationError as error:
                raise DurabilityOutcomeUnknown(
                    "recovered collection archive outcome is unknown"
                ) from error
    except OSError as error:
        raise _error("recovered collection could not be archived") from error
    return destination


def _aborted_before_mutation(observed: tuple[tuple[Any, Any], ...]) -> bool:
    """Whether a validated event log proves collect never crossed its boundary.

    A log that shows the boundary step started, or that holds no
    ``aborted_before_mutation`` event, may follow a runtime change, so it
    takes the full runtime recovery, which never archives anything unproven.
    Otherwise the log must be the one collect writes when it stops before its
    boundary: a prefix of the steps before it, then one abort, then at most
    recover's own archive marker. Any other log is refused, not guessed at.
    """

    if MUTATION_BOUNDARY_PAIR in observed:
        return False
    phases = [phase for phase, _step in observed]
    if ABORTED_BEFORE_MUTATION_PAIR[0] not in phases:
        return False
    # Any later abort falls in the suffix, which admits only the marker.
    abort = phases.index(ABORTED_BEFORE_MUTATION_PAIR[0])
    collected, recovered = observed[:abort], observed[abort + 1 :]
    if (
        observed[abort] == ABORTED_BEFORE_MUTATION_PAIR
        and collected == PRE_MUTATION_STEP_PAIRS[: len(collected)]
        and recovered in ((), (RECOVERED_BEFORE_MUTATION_PAIR,))
    ):
        return True
    raise _error(
        "GA runtime collection event log is not one fixed collect attempt; "
        "retain runtime-collection for review"
    )


def recover_ga_runtime_collection(
    *,
    repository: Path,
    expected: object,
    runtime: ProductionCollectorRuntime | None = None,
) -> Path:
    """Archive an unfinished collection, after runtime recovery if it may need it.

    A collection that aborted before its mutation boundary changed nothing,
    so it is archived without any runtime command or observation. Every other
    collection runs only the fixed runtime shutdown/CFW-restore recovery path.
    """

    repository = _canonical_repository(repository)
    _require_no_published_runtime_outputs(repository)
    collection_path = repository.joinpath(*COLLECTION_RELATIVE.parts)
    if not os.path.lexists(collection_path):
        raise _error("there is no active GA runtime collection to recover")
    intent, collection = _load_collection_intent(repository, collection_path)
    normalized_expected = _validate_expected(expected)
    if (
        collection["ga_environment_sha256"]
        != normalized_expected["ga_environment_sha256"]
    ):
        raise _error("recovery collection binds a different fixed GA environment")
    observed, _entries = _read_collection_events(
        repository, collection, canonical_json(intent)
    )
    if _aborted_before_mutation(observed):
        # Nothing was launched, so neither the environment nor the guard can
        # say anything about this attempt; only its own bindings are checked.
        _collection_guard_baseline(repository, intent, normalized_expected)
        if observed[-1] != RECOVERED_BEFORE_MUTATION_PAIR:
            _append_collection_event(
                repository,
                collection_path,
                collection,
                phase=RECOVERED_BEFORE_MUTATION_PAIR[0],
                step=RECOVERED_BEFORE_MUTATION_PAIR[1],
                expected_sequence=len(observed),
            )
        return _archive_recovered_collection(repository, collection_path, collection)
    selected_runtime = runtime or ProductionCollectorRuntime(repository)
    _require_current_environment(
        repository,
        selected_runtime,
        normalized_expected["ga_environment_sha256"],
        label="GA runtime recovery admission environment",
    )
    baseline = _collection_guard_baseline(repository, intent, normalized_expected)
    initial = _run_collector_command(
        selected_runtime,
        list(PROCESS_OBSERVATION_COMMAND),
        timeout=60,
        label="runtime recovery initial process observation",
    )
    try:
        initial_processes = dormant_app_install._parse_processes(initial["stdout"])
    except dormant_app_install.InstallError as error:
        raise _error("runtime recovery process table is malformed") from error
    app_processes = [
        process
        for process in initial_processes
        if process["path"] == INSTALLED_EXECUTABLE.as_posix()
    ]
    if len(app_processes) > 1:
        raise _error("runtime recovery found an ambiguous installed Host process set")
    if app_processes:
        try:
            _step_operator_quit(
                repository,
                collection_path,
                collection,
                selected_runtime,
                step="runtime-recovery-shutdown-request",
            )
        except GARuntimeAcceptanceError as error:
            error.add_note(RECOVERY_OPERATOR_QUIT_GUIDANCE)
            raise
    _step_host_absence(
        repository,
        collection_path,
        collection,
        selected_runtime,
        step="runtime-recovery-host-process-observation",
        timeout=60,
    )
    try:
        _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="runtime-recovery-off-proof",
            argv=list(OFF_PROOF_COMMAND),
            timeout=60,
            accept=partial(
                _validate_off_proof_receipt, label="runtime recovery signed Host Off proof"
            ),
        )
    except GARuntimeAcceptanceError as error:
        error.add_note(RECOVERY_OFF_PROOF_GUIDANCE)
        raise
    _step_host_absence(
        repository,
        collection_path,
        collection,
        selected_runtime,
        step="runtime-recovery-process-observation",
        timeout=60,
    )
    if baseline["cfw_processes"]:
        # Clash for Windows owns this guard's proxy, DNS, routes and utun, so
        # only their exact restoration counts.
        _settled_guard(
            selected_runtime,
            baseline,
            label="runtime recovery",
            mismatch="runtime recovery did not restore the collection's fixed CFW guard",
        )
    else:
        _settle_without_cfm_remnants(selected_runtime, baseline)
    _require_current_environment(
        repository,
        selected_runtime,
        normalized_expected["ga_environment_sha256"],
        label="GA runtime recovery post-restore environment",
    )
    _append_collection_event(
        repository,
        collection_path,
        collection,
        phase="recovered",
        step="runtime-cleanup",
    )
    return _archive_recovered_collection(repository, collection_path, collection)


def _durably_reopen_published_raw(
    repository: Path, raw_root: Path
) -> dict[str, FileSnapshot]:
    parent = raw_root.parent
    try:
        with exclusive_rooted_directory_lock(
            repository, parent, require_private=True
        ) as descriptor:
            # Fsyncs every file, the tree and its parent before the bytes are
            # trusted, because collect may have failed before its own barrier.
            files = read_private_directory_contents_locked(
                descriptor,
                parent,
                raw_root.name,
                {
                    name: MAX_PCAP_BYTES if name in PCAP_FILES else MAX_JSON_BYTES
                    for name in sorted(RAW_FILE_NAMES)
                },
            )
    except (DurabilityOutcomeUnknown, RootedDirectoryChanged):
        raise
    except PublicationError as error:
        raise _error("published GA runtime raw evidence cannot be durably reopened") from error
    if sum(len(data) for data in files.values()) > MAX_TOTAL_BYTES:
        raise _error("GA runtime evidence exceeds its aggregate byte bound")
    return _snapshots_from_collector_bytes(files)


def resume_ga_runtime_seal(
    *,
    repository: Path,
    expected: object,
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> dict[str, dict[str, str]]:
    """Seal the fixed collection whose raw evidence was published after restore.

    No runtime command, capture or CFW observation runs here. A missing
    raw_published marker is written only after the raw tree is durably
    reopened and fully revalidated against the collection intent. Sealing is
    the idempotent ``seal_ga_runtime_acceptance``.
    """

    repository = _canonical_repository(repository)
    acceptance_path, raw_root = _fixed_paths(repository)
    collection_path = repository.joinpath(*COLLECTION_RELATIVE.parts)
    normalized_expected = _validate_expected(expected)
    if not _fixed_path_present(raw_root):
        raise _error(
            "there is no published GA runtime raw evidence to seal; an unfinished "
            f"collection needs {RECOVERY_COMMAND}"
        )
    if not _fixed_path_present(collection_path):
        raise _error("published GA runtime raw evidence has no fixed collection receipt")
    intent, collection = _load_collection_intent(repository, collection_path)
    observed, _entries = _read_collection_events(
        repository, collection, canonical_json(intent)
    )
    if observed == COLLECTION_STEP_PAIRS:
        if _fixed_path_present(acceptance_path):
            raise _error(
                "GA runtime adapter exists before its raw_published marker; "
                "refusing an inconsistent collection"
            )
        # The full raw validation also binds every document to this durable
        # collection intent before the marker can claim publication.
        _validate_raw_evidence(
            repository,
            _durably_reopen_published_raw(repository, raw_root),
            normalized_expected,
            prepackage_stage_verifier,
        )
        _append_raw_published_marker(repository, collection_path, collection)
    elif observed != COMPLETED_COLLECTION_PAIRS:
        last = "/".join(map(str, observed[-1])) if observed else "none"
        raise _error(
            "GA runtime collection is not a completed collection with published "
            f"raw evidence (last event: {last}); retain runtime-collection and "
            "runtime-evidence for review"
        )
    return seal_ga_runtime_acceptance(
        repository=repository,
        expected=normalized_expected,
        prepackage_stage_verifier=prepackage_stage_verifier,
    )


def self_check() -> None:
    repository = _operator_root()
    runner = repository / "scripts/run_ga_runtime_acceptance.sh"
    try:
        runner_metadata = runner.lstat()
        runner_bytes = runner.read_bytes()
    except OSError as error:
        raise _error("GA runtime collector source/build registry is unavailable") from error
    if (
        (MAX_COMMAND_SECONDS, DMG_BYTE_PROOF_TIMEOUT_SECONDS)
        != (15 * 60, 30 * 60)
        or len(CHECKS) != 12
        or tuple(sorted(CHECKS)) != CHECKS
        or len(RAW_FILE_NAMES) != 15
        or (
            DOCUMENT,
            SCHEMA_VERSION,
            CHECK_DOCUMENT,
            COMMAND_DOCUMENT,
            COLLECTION_DOCUMENT,
            COLLECTION_INTENT_SCHEMA_VERSION,
            COLLECTION_EVENT_DOCUMENT,
        )
        != (
            "cfm-ga-runtime-acceptance-v2",
            2,
            "cfm-ga-runtime-check-v2",
            "cfm-ga-command-observation-v2",
            "cfm-ga-runtime-collection-intent-v4",
            4,
            "cfm-ga-runtime-collection-event-v2",
        )
        or ACCEPTANCE_RELATIVE
        != Path(
            f"target/candidates/{PRODUCT_VERSION}/ga/{TO_BUILD}/stage-inputs/ga-acceptance/"
            "runtime-acceptance.json"
        )
        or RAW_ROOT_RELATIVE
        != Path(
            f"target/candidates/{PRODUCT_VERSION}/ga/{TO_BUILD}/stage-inputs/ga-acceptance/"
            "runtime-evidence"
        )
        or ENVIRONMENT_RELATIVE
        != Path(
            f"target/candidates/{PRODUCT_VERSION}/ga/{TO_BUILD}/stage-inputs/ga-acceptance/"
            "migration-journals/service-transaction/environment.json"
        )
        or INSTALL_JOURNAL_RELATIVE
        != Path(
            f"target/candidates/{PRODUCT_VERSION}/ga/{TO_BUILD}/stage-inputs/ga-acceptance/"
            "migration-journals/dormant-install.json"
        )
        or not stat.S_ISREG(runner_metadata.st_mode)
        or stat.S_ISLNK(runner_metadata.st_mode)
        or runner_metadata.st_nlink != 1
        or runner_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(runner_metadata.st_mode) != 0o755
        or b"cfw_run_release_python_script" not in runner_bytes
        or b"ga_runtime_acceptance_cli.py" not in runner_bytes
    ):
        raise _error("GA runtime acceptance source contract is inconsistent")


def _repository() -> Path:
    return dormant_app_install.InstallPaths.production().repository


def _arguments(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("collect")
    subparsers.add_parser("recover")
    subparsers.add_parser("resume-seal")
    subparsers.add_parser("verify")
    subparsers.add_parser("self-check")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(
    expectation_deriver: Callable[[Path], dict[str, Any]],
    prepackage_stage_verifier: PrepackageStageVerifier,
) -> str:
    """Return the success diagnostic for the CLI's enclosing verifier lifetime."""

    arguments = _arguments()
    try:
        if arguments.command == "self-check":
            self_check()
            return "GA runtime acceptance source contract verified"
        repository = _repository()
        expected = expectation_deriver(repository)
        if arguments.command == "collect":
            result = collect_ga_runtime_acceptance(
                repository=repository,
                expected=expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            return (
                "GA runtime collection sealed: "
                f"{result['adapter']['sha256']} ({len(CHECKS)} raw-derived checks)"
            )
        if arguments.command == "recover":
            path = recover_ga_runtime_collection(
                repository=repository,
                expected=expected,
            )
            return f"GA runtime collection recovered and archived: {path}"
        if arguments.command == "resume-seal":
            result = resume_ga_runtime_seal(
                repository=repository,
                expected=expected,
                prepackage_stage_verifier=prepackage_stage_verifier,
            )
            return (
                "GA runtime collection sealed after seal retry: "
                f"{result['adapter']['sha256']} ({len(CHECKS)} raw-derived checks)"
            )
        acceptance, raw_root = _fixed_paths(repository)
        result = validate_ga_runtime_acceptance(
            repository=repository,
            acceptance_path=acceptance,
            raw_evidence_root=raw_root,
            expected=expected,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
    except (GARuntimeAcceptanceError, OSError, PublicationError, ValueError) as error:
        raise SystemExit(
            failure_diagnostic(f"error: GA runtime acceptance: {error}", error)
        ) from error
    return (
        "GA runtime acceptance verified: "
        f"{result['adapter']['sha256']} ({len(CHECKS)} raw-derived checks)"
    )
