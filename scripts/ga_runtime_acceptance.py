#!/usr/bin/env python3
"""Seal and verify raw runtime evidence for the single v0.4.0 GA build.

This module deliberately does not accept a caller-selected evidence path and it
does not accept a list of boolean outcomes. Collection starts only after the
existing dormant-install and current-service owners have closed their
40041 -> 40043 journals. ``collect`` creates a durable CSPRNG challenge intent,
owns every runtime command and packet byte, atomically publishes the exact
raw tree, and seals the adapter. ``recover`` owns only runtime shutdown/restore;
it never duplicates either installation state machine. ``verify`` reopens
every byte and journal.

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
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Final, Iterable
import uuid

if __package__:
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
        PacketCaptureError,
        StagedCaptureEndpoint,
        dns_stage_endpoints,
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
        canonical_json,
        read_regular,
        require_exact_keys,
        require_sha256,
        safe_relative,
        sha256_bytes,
        sha256_file,
        tree_digest,
    )
    from .publication.bounded_process import BoundedProcessError, run_bounded_process
    from .publication.durable_file import (
        DurabilityOutcomeUnknown,
        RootedDirectoryChanged,
        exclusive_rooted_directory_lock,
        publish_private_directory_locked,
        promote_private_pending,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from .publication.graph_model import load_pins
    from .publication.release_environment import release_tool_environment
    from .release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_root
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
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
        PacketCaptureError,
        StagedCaptureEndpoint,
        dns_stage_endpoints,
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
        canonical_json,
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
        run_bounded_process,
    )
    from scripts.publication.durable_file import (
        DurabilityOutcomeUnknown,
        RootedDirectoryChanged,
        exclusive_rooted_directory_lock,
        publish_private_directory_locked,
        promote_private_pending,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from scripts.publication.graph_model import load_pins
    from scripts.publication.release_environment import release_tool_environment
    from scripts.release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        ga_root,
    )


class GARuntimeAcceptanceError(ValueError):
    """The fixed GA runtime evidence is incomplete, drifted, or unobservable."""


PrepackageStageVerifier = Callable[[Path], dict[str, Any]]


PRODUCT_VERSION: Final = ACTIVE_RELEASE_IDENTITY.product_version
TO_BUILD: Final = ACTIVE_RELEASE_IDENTITY.ga_build
FROM_BUILD: Final = "40041"
TEAM_ID: Final = "YKUPL7Z869"
APP_BUNDLE_ID: Final = "com.bill.clashformac"
PACKET_EXTENSION_BUNDLE_ID: Final = "com.bill.clashformac.packet-tunnel"
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
TRAFFIC_DOCUMENT: Final = "cfm-ga-traffic-capture-v1"
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
MAX_COMMAND_SECONDS: Final = 15 * 60
DMG_BYTE_PROOF_TIMEOUT_SECONDS: Final = 30 * 60
PACKET_HOST_READY_SECONDS: Final = 10 * 60
MAX_RUNTIME_FILES: Final = 32
ADAPTER_PENDING_NAME: Final = ".runtime-acceptance.json.pending"
TOKEN_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,63}$")
INTERFACE_RE: Final = re.compile(r"^(?:utun[0-9]{1,3}|en[0-9]{1,2}|pktap,all)$")

TRAFFIC_POLICY: Final = {
    "dns_traffic": {
        "case_id": "dns-a-primary",
        "protocol": "dns",
        "remote_address": "34.80.107.183",
        "remote_port": 53,
        "expected_records": 6,
    },
    "tcp_traffic": {
        "case_id": "tcp-ipv4",
        "protocol": "tcp",
        "remote_address": "35.194.216.98",
        "remote_port": PACKET_TRANSPORT_PORT,
        "expected_records": 3,
    },
    "udp_traffic": {
        "case_id": "udp",
        "protocol": "udp",
        "remote_address": "35.194.216.98",
        "remote_port": PACKET_TRANSPORT_PORT,
        "expected_records": 3,
    },
}
PACKET_SENDER_PREFIX: Final = (
    sys.executable,
    "-I",
    "-S",
    "-B",
    "-W",
    "error",
    "scripts/physical_capture/packet_sender.py",
)
PACKET_STAGES: Final = ("start", "target", "end")
PACKET_EVIDENCE_FLAG: Final = "--physical-packet-evidence-v5"
SERVICE_MAINTENANCE_FLAG: Final = "--service-maintenance-v2"
PACKET_HOST_DOCUMENT: Final = "cfw-packet-host-completed-v5"
PACKET_HOST_SCHEMA_VERSION: Final = 5
SHUTDOWN_APPLE_EVENT: Final = (
    "/usr/bin/osascript",
    "-e",
    'tell application id "com.bill.clashformac" to quit',
)
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
    identity: tuple[int, int, int, int, int, int, int]

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


def _dmg_verifier_command(repository: Path) -> list[str]:
    operator_repository = Path(__file__).resolve().parent.parent
    return [
        "/bin/bash",
        "-p",
        "-c",
        "set -euo pipefail; "
        'source "$1/scripts/release_python_launcher.sh"; '
        'cfw_run_release_python_script "$1" '
        '"$1/scripts/release_artifact_set_cli.py" "${@:2}"',
        "ga-dmg-verification",
        str(operator_repository),
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
        raise _error("GA runtime adapter path is not the fixed 40043 path")
    if Path(raw_evidence_root).absolute() != expected_raw:
        raise _error("GA runtime raw-evidence path is not the fixed 40043 path")


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


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
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
        raise _error("GA runtime expected identity or check set differs from 0.4.0/40043")
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
    if (
        receipt["document"] != COMMAND_DOCUMENT
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt["argv"] != expected_argv
        or type(receipt["exit_code"]) is not int
        or receipt["exit_code"] != expected_exit
        or not started < finished
        or (finished - started).total_seconds() > maximum_seconds
    ):
        raise _error(f"{label} command identity, exit, or duration is invalid")
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
        raise _error("GA install journal is not the completed 40041 to 40043 install")
    try:
        installed = dormant_app_install.read_app_identity(INSTALLED_APP)
    except dormant_app_install.InstallError as error:
        raise _error("installed 40043 application tree cannot be identified") from error
    if installed.document() != normalized["candidate"]:
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


def _validate_exact_dmg_install(
    value: dict[str, Any],
    repository: Path,
    expected: dict[str, Any],
    prepackage_stage_verifier: PrepackageStageVerifier,
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
        raise _error("DMG-contained app and installed 40043 app are not the same tree")
    commands = require_exact_keys(
        document["commands"],
        {"dmg_gatekeeper", "dmg_set_verify"},
        "DMG install commands",
    )
    gatekeeper = _command(
        commands["dmg_gatekeeper"],
        expected_argv=[
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "open",
            "--context",
            "context:primary-signature",
            "-vv",
            DMG_RELATIVE.as_posix(),
        ],
        expected_exit=0,
        label="DMG Gatekeeper observation",
    )
    gatekeeper_output = gatekeeper["stdout"] + gatekeeper["stderr"]
    if "accepted" not in gatekeeper_output or "Notarized Developer ID" not in gatekeeper_output:
        raise _error("raw DMG Gatekeeper output is not notarized acceptance")
    verification = _command(
        commands["dmg_set_verify"],
        expected_argv=_dmg_verifier_command(repository),
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


def _running_host_observation(value: object) -> list[dict[str, Any]]:
    receipt = _command(
        value,
        expected_argv=["/bin/ps", "-axo", "pid=,uid=,lstart=,comm="],
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
    if len(app_processes) != 1:
        raise _error("raw process table does not contain exactly one installed 40043 Host")
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
        raise _error("normal shutdown evidence still contains the installed 40043 Host")
    return processes


def _validate_launch(value: dict[str, Any]) -> None:
    document = _check_document(
        value, "launch", {"launch_command", "process_observation"}
    )
    launch = _command(
        document["launch_command"],
        expected_argv=["/usr/bin/open", "-a", INSTALLED_APP.as_posix()],
        expected_exit=0,
        label="installed 40043 launch command",
    )
    if launch["stderr"]:
        raise _error("installed 40043 launch command emitted an error")
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
    inside the installed 40043 bundle, registered through ServiceManagement,
    and signed under the fixed team and service identifiers.
    """

    try:
        relative = program.relative_to(INSTALLED_APP)
    except ValueError as error:
        raise _error(
            f"fixed {label} executable is outside the installed 40043 bundle"
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
    if any(lines.count(value) != 1 for value in required):
        raise _error(f"raw launchctl output does not show the fixed running {label}")


def _validate_service_registration(value: dict[str, Any]) -> None:
    document = _check_document(value, "service_registration", {"commands"})
    commands = require_exact_keys(
        document["commands"], {"global_authority", "proxy_agent"}, "service commands"
    )
    uid = os.geteuid()
    proxy = _command(
        commands["proxy_agent"],
        expected_argv=["/bin/launchctl", "print", f"gui/{uid}/{PROXY_LABEL}"],
        expected_exit=0,
        label="ProxyAgent launchctl observation",
    )
    authority = _command(
        commands["global_authority"],
        expected_argv=["/bin/launchctl", "print", f"system/{AUTHORITY_LABEL}"],
        expected_exit=0,
        label="GlobalAuthority launchctl observation",
    )
    _require_launchctl_running(
        proxy["stdout"],
        PROXY_EXECUTABLE,
        "ProxyAgent",
        service_label=PROXY_LABEL,
    )
    _require_launchctl_running(
        authority["stdout"],
        AUTHORITY_EXECUTABLE,
        "GlobalAuthority",
        service_label=AUTHORITY_LABEL,
    )


def _validate_system_extension(value: dict[str, Any]) -> None:
    document = _check_document(value, "system_extension", {"command"})
    receipt = _command(
        document["command"],
        expected_argv=["/usr/bin/systemextensionsctl", "list"],
        expected_exit=0,
        label="system extension observation",
    )
    try:
        identities = dormant_app_install._parse_system_extension_identities(
            receipt["stdout"]
        )
    except dormant_app_install.InstallError as error:
        raise _error("raw systemextensionsctl output is malformed") from error
    if (TEAM_ID, PACKET_EXTENSION_BUNDLE_ID) not in identities:
        raise _error("raw system extension output lacks the fixed 40043 extension")
    matching = [
        line
        for line in receipt["stdout"].splitlines()
        if TEAM_ID in line and PACKET_EXTENSION_BUNDLE_ID in line
    ]
    if len(matching) != 1 or not matching[0].endswith("[activated enabled]"):
        raise _error("fixed system extension is not both activated and enabled")


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


def _validate_high_risk_rejections(value: dict[str, Any]) -> None:
    document = _check_document(value, "high_risk_rejections", {"observations"})
    observations = document["observations"]
    if not isinstance(observations, list) or len(observations) != len(HIGH_RISK_PROBES):
        raise _error("high-risk rejection evidence must contain every fixed denial")
    for index, (probe_id, argv, exit_code, expected_stderr) in enumerate(
        HIGH_RISK_PROBES
    ):
        receipt = _command(
            observations[index],
            expected_argv=list(argv),
            expected_exit=exit_code,
            label=f"{probe_id} rejection observation",
        )
        if receipt["stdout"] or receipt["stderr"] != expected_stderr:
            raise _error(f"{probe_id} did not produce the fixed candidate rejection")


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
            "shutdown_command",
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
    command = _command(
        document["shutdown_command"],
        expected_argv=list(SHUTDOWN_APPLE_EVENT),
        expected_exit=0,
        label="candidate normal shutdown request",
    )
    if command["stdout"] or command["stderr"]:
        raise _error("candidate normal shutdown request emitted unexpected output")
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
        timestamp_fraction(command["finished_at"])
        <= timestamp_fraction(host_process["started_at"])
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
    journal_baseline = _installed_guard_baseline(repository, expected)
    if before != journal_baseline:
        raise _error("runtime CFW baseline differs from the closed install journal")
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


def _endpoint(value: object, check_id: str) -> dict[str, Any]:
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
        local = ipaddress.ip_address(endpoint["local_address"])
        remote = ipaddress.ip_address(endpoint["remote_address"])
    except (TypeError, ValueError) as error:
        raise _error(f"{check_id} endpoint address is invalid") from error
    if (
        endpoint["family"] != "ipv4"
        or local.version != 4
        or local.is_unspecified
        or local.is_multicast
        or remote.version != 4
        or str(remote) != policy["remote_address"]
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
    *,
    check_id: str,
    stage: str,
    token: str,
    local_address: str,
) -> list[str]:
    policy = TRAFFIC_POLICY[check_id]
    command = [
        *PACKET_SENDER_PREFIX,
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
            or not isinstance(query["addresses"], list)
            or not query["addresses"]
        ):
            raise _error(f"{check_id} {stage} DNS result is incomplete")
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


def _validate_traffic(
    check_id: str,
    value: dict[str, Any],
    pcap: FileSnapshot,
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
    filter_argv = packet_capture_filter_argv(
        case_id=policy["case_id"],
        tokens=(tokens["start"], tokens["target"], tokens["end"]),
    )
    capture_argv = [
        "/usr/sbin/tcpdump",
        "-U",
        "-n",
        "-i",
        endpoint["interface_name"],
        "-c",
        str(policy["expected_records"]),
        "-w",
        "-",
        *filter_argv,
    ]
    capture_command = _command(
        document["capture_command"],
        expected_argv=capture_argv,
        expected_exit=0,
        label=f"{check_id} packet capture command",
    )
    if "packets captured" not in capture_command["stderr"]:
        raise _error(f"{check_id} tcpdump output lacks a capture receipt")
    send_values = document["send_commands"]
    if not isinstance(send_values, list) or len(send_values) != 3:
        raise _error(f"{check_id} must retain start/target/end sender commands")
    send_commands: list[dict[str, Any]] = []
    send_results: list[dict[str, Any]] = []
    for index, stage in enumerate(PACKET_STAGES):
        receipt = _command(
            send_values[index],
            expected_argv=_packet_sender_argv(
                check_id=check_id,
                stage=stage,
                token=tokens[stage],
                local_address=endpoint["local_address"],
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
                local_address=endpoint["local_address"],
            )
        )
    if document["protocol"] == "dns":
        try:
            endpoints = dns_stage_endpoints(
                pcap.data,
                "packet-pcap",
                family="ipv4",
                remote_address=endpoint["remote_address"],
                tokens=(
                    tokens["start"].encode("ascii"),
                    tokens["target"].encode("ascii"),
                    tokens["end"].encode("ascii"),
                ),
            )
        except PacketCaptureError as error:
            raise _error(f"{check_id} DNS capture endpoints are invalid") from error
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
            pcap.data,
            "packet-pcap",
            protocol=document["protocol"],
            family=endpoint["family"],
            endpoints=endpoints,
            expected_link_type=endpoint["link_type"],
            expected_interface_name=endpoint["interface_name"],
            expected_quic_version=None,
            token=tokens["target"].encode("ascii"),
            start_marker=tokens["start"].encode("ascii"),
            end_marker=tokens["end"].encode("ascii"),
            expect_token=True,
            declared_observation_ms=observation_ms,
        )
    except PacketCaptureError as error:
        raise _error(f"{check_id} packet bytes do not prove the required traffic") from error
    if (
        proof.total_record_count != policy["expected_records"]
        or proof.token_occurrences < 1
        or (document["protocol"] == "dns" and proof.dns_response_count != 3)
    ):
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
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
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
    _validate_exact_dmg_install(
        documents["exact-dmg-install.json"],
        repository,
        expected,
        prepackage_stage_verifier,
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
    )
    seen_tokens: set[str] = set()
    host_sessions = {
        documents["shutdown-restore.json"]["stop_restore_observation"]["session_id"]
    }
    for check_id in TRAFFIC_CHECKS:
        filename = f"{check_id.replace('_', '-')}.json"
        pcap_name = f"{check_id.replace('_', '-')}.pcap"
        tokens = _validate_traffic(check_id, documents[filename], snapshots[pcap_name])
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
    return artifacts, collection


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
    artifacts, collection = _validate_raw_evidence(
        repository,
        snapshots,
        normalized_expected,
        prepackage_stage_verifier,
    )
    collection_receipt = _validate_collection_receipt(repository, collection)
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
    if _validate_collection_receipt(repository, collection) != collection_receipt:
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
    artifacts, collection = _validate_raw_evidence(
        repository,
        snapshots,
        normalized_expected,
        prepackage_stage_verifier,
    )
    collection_receipt = _validate_collection_receipt(repository, collection)
    document = _adapter_document(
        normalized_expected,
        snapshots,
        artifacts,
        collection,
        collection_receipt,
    )
    encoded = canonical_json(document)
    parent = acceptance_path.parent
    pending = parent / ADAPTER_PENDING_NAME
    try:
        with exclusive_rooted_directory_lock(
            repository,
            parent,
            require_private=True,
        ) as descriptor:
            destination_exists = os.path.lexists(acceptance_path)
            pending_exists = os.path.lexists(pending)
            if destination_exists and pending_exists:
                raise _error("GA runtime adapter and pending adapter both exist")
            if destination_exists:
                _private_regular_metadata(acceptance_path)
                try:
                    observed = read_regular(acceptance_path, MAX_JSON_BYTES)
                except PublicationError as error:
                    raise _error("existing GA runtime adapter cannot be reopened") from error
                if observed != encoded:
                    raise _error(
                        "refusing to replace a different immutable GA runtime adapter"
                    )
            else:
                if pending_exists:
                    try:
                        observed = read_private_pending_locked(
                            descriptor,
                            parent,
                            ADAPTER_PENDING_NAME,
                            len(encoded),
                        )
                    except PublicationError as error:
                        raise _error("pending GA runtime adapter cannot be recovered") from error
                    if observed != encoded:
                        raise _error("pending GA runtime adapter binds different evidence")
                else:
                    write_private_pending_locked(
                        descriptor,
                        parent,
                        ADAPTER_PENDING_NAME,
                        encoded,
                    )
                promote_private_pending(pending, acceptance_path)
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


COLLECTION_DOCUMENT: Final = "cfm-ga-runtime-collection-intent-v2"
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
class GACollectionRecoveryRequired(GARuntimeAcceptanceError):
    """A collection entered the mutation boundary and requires fixed recovery."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


class ProductionCollectorRuntime:
    """Bounded production runner for the fixed GA collection registry."""

    def __init__(self, repository: Path) -> None:
        self.repository = _canonical_repository(repository)
        pins = load_pins(self.repository / "scripts/dependency_pins.env")
        self.environment = release_tool_environment(self.repository, pins)

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
        except (OSError, BoundedProcessError) as error:
            raise _error(
                "fixed GA collection command failed its bounded process boundary"
            ) from error
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
                waiting_for_operator = error.code in {
                    "baseline_mismatch",
                    "baseline_unavailable",
                    "tunnel_unavailable",
                }
                retryable = waiting_for_operator or error.code == "app_control_unavailable"
                if not retryable or time.monotonic() >= deadline:
                    raise
                if waiting_for_operator and not announced_operator_boundary:
                    print(
                        "GA runtime collection is waiting for macOS approval and "
                        "Tunnel mode in the installed 40043 dashboard",
                        file=sys.stderr,
                        flush=True,
                    )
                    announced_operator_boundary = True
                time.sleep(1.0 if waiting_for_operator else 0.25)

    def _tunnel_interface(self) -> str:
        receipt = self.run(["/sbin/ifconfig"], timeout=60)
        _command(
            receipt,
            expected_argv=["/sbin/ifconfig"],
            expected_exit=0,
            label="GA tunnel interface observation",
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
            except OSError as error:
                raise _error(
                    "tcpdump capture process group could not be terminated"
                ) from error
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise _error("tcpdump capture process group could not be cleaned up") from error
        except OSError as error:
            raise _error("tcpdump capture process exit could not be observed") from error

    def _capture_traffic_bytes(
        self,
        check_id: str,
        tokens: dict[str, str],
    ) -> tuple[dict[str, Any], bytes]:
        policy = TRAFFIC_POLICY[check_id]
        interface = self._tunnel_interface()
        filter_argv = packet_capture_filter_argv(
            case_id=policy["case_id"],
            tokens=(tokens["start"], tokens["target"], tokens["end"]),
        )
        capture_argv = [
            "/usr/sbin/tcpdump",
            "-U",
            "-n",
            "-i",
            interface,
            "-c",
            str(policy["expected_records"]),
            "-w",
            "-",
            *filter_argv,
        ]
        started_at = _utc_now()
        try:
            process = subprocess.Popen(
                capture_argv,
                cwd=self.repository,
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as error:
            raise _error("fixed tcpdump capture could not start") from error
        prefix = bytearray()
        selector: selectors.BaseSelector | None = None
        primary: BaseException | None = None
        cleanup_failure: GARuntimeAcceptanceError | None = None
        result: tuple[dict[str, Any], bytes] | None = None
        try:
            if process.stdout is None or process.stderr is None:
                raise _error("fixed tcpdump capture pipes are unavailable")
            try:
                selector = selectors.DefaultSelector()
            except OSError as error:
                raise _error("tcpdump output selector is unavailable") from error
            os.set_blocking(process.stderr.fileno(), False)
            selector.register(process.stderr, selectors.EVENT_READ)
            deadline = time.monotonic() + 10
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
            send_commands = []
            for index, stage in enumerate(PACKET_STAGES):
                send_commands.append(self.run(
                    _packet_sender_argv(
                        check_id=check_id,
                        stage=stage,
                        token=tokens[stage],
                        local_address=TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"],
                    ),
                    timeout=60,
                ))
                if index < len(PACKET_STAGES) - 1:
                    time.sleep(1.1)
            try:
                capture_bytes, remaining_stderr = process.communicate(timeout=30)
            except subprocess.TimeoutExpired as error:
                raise _error("tcpdump did not finish the exact packet count") from error
            finished_at = _utc_now()
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
            parsed = parse_packet_capture(capture_bytes, "packet-pcap")
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
            endpoint = {
                "family": "ipv4",
                "interface_name": interface,
                "link_type": next(iter(link_types)),
                "local_address": TUNNEL_CAPTURE_LOCAL_ADDRESSES["ipv4"],
                "remote_address": policy["remote_address"],
                "remote_port": policy["remote_port"],
            }
            send_results = [
                _packet_send_result(
                    _command(
                        receipt,
                        expected_argv=_packet_sender_argv(
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
            if policy["protocol"] == "dns":
                staged_endpoints = dns_stage_endpoints(
                    capture_bytes,
                    "packet-pcap",
                    family="ipv4",
                    remote_address=policy["remote_address"],
                    tokens=tuple(tokens[stage].encode("ascii") for stage in PACKET_STAGES),
                )
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
            window_start, window_end = staged_marker_window(
                capture_bytes,
                "packet-pcap",
                protocol=policy["protocol"],
                family="ipv4",
                endpoints=staged_endpoints,
                start_marker=tokens["start"].encode("ascii"),
                end_marker=tokens["end"].encode("ascii"),
            )
            duration = (window_end - window_start) * 1000
            observation_ms = duration.numerator // duration.denominator
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
            if selector is not None:
                try:
                    selector.close()
                except OSError as error:
                    if cleanup_failure is None:
                        cleanup_failure = _error(
                            "tcpdump output selector could not be closed"
                        )
                        cleanup_failure.__cause__ = error
            for stream in (process.stdout, process.stderr):
                if stream is None:
                    continue
                try:
                    stream.close()
                except OSError as error:
                    if cleanup_failure is None:
                        cleanup_failure = _error(
                            "tcpdump capture pipes could not be closed"
                        )
                        cleanup_failure.__cause__ = error
        if cleanup_failure is not None:
            if primary is not None:
                raise cleanup_failure from primary
            raise cleanup_failure
        if primary is not None:
            raise primary
        if result is not None:
            return result
        raise _error("tcpdump capture ended without a result")

    def capture_traffic(
        self,
        check_id: str,
        tokens: dict[str, str],
    ) -> tuple[dict[str, Any], bytes]:
        """Capture traffic only while the authenticated signed Host reports test state."""

        captured: dict[str, object] = {}

        def begin_capture(_baseline: object) -> PacketCaptureDisposition:
            return PacketCaptureDisposition.COMPLETE

        def exercise_test(_test: object) -> PacketCaptureDisposition:
            traffic, capture = self._capture_traffic_bytes(check_id, tokens)
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
        """Poll until the dashboard Host exits; registered services may still drain."""

        if type(timeout) is not int or not 1 <= timeout <= 120:
            raise _error("installed Host absence timeout is outside 1..120 seconds")
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
                raise _error("installed Host did not exit after its normal shutdown request")
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


def _collection_intent(
    expected: dict[str, Any],
    collection: dict[str, str],
) -> dict[str, Any]:
    return {
        "collection": collection,
        "document": COLLECTION_DOCUMENT,
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
        "schema_version": SCHEMA_VERSION,
    }


def _publish_collection_intent(
    repository: Path,
    expected: dict[str, Any],
    collection: dict[str, str],
) -> Path:
    path = repository.joinpath(*COLLECTION_RELATIVE.parts)
    parent = path.parent
    with exclusive_rooted_directory_lock(
        repository, parent, require_private=True
    ) as descriptor:
        if os.path.lexists(path):
            raise _error("an unfinished GA runtime collection already exists; recover it")
        publish_private_directory_locked(
            descriptor,
            parent,
            path.name,
            {"intent.json": canonical_json(_collection_intent(expected, collection))},
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
) -> None:
    with exclusive_rooted_directory_lock(
        repository, collection_path, require_private=True
    ) as descriptor:
        names = os.listdir(descriptor)
        events = sorted(name for name in names if re.fullmatch(r"event-[0-9]{3}\.json", name))
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
        write_private_pending_locked(
            descriptor,
            collection_path,
            name,
            canonical_json(document),
        )


def _validate_collection_receipt(
    repository: Path, collection: dict[str, str]
) -> dict[str, str]:
    path = repository.joinpath(*COLLECTION_RELATIVE.parts)
    _intent, observed_collection = _load_collection_intent(repository, path)
    if observed_collection != collection:
        raise _error("raw evidence collection differs from its durable intent")
    with exclusive_rooted_directory_lock(
        repository, path, require_private=True
    ) as descriptor:
        names = os.listdir(descriptor)
        event_names = sorted(
            name for name in names if re.fullmatch(r"event-[0-9]{3}\.json", name)
        )
        if set(names) != {"intent.json", *event_names}:
            raise _error("GA runtime collection contains an unexpected transaction file")
        intent_data = read_private_pending_locked(
            descriptor, path, "intent.json", MAX_JSON_BYTES
        )
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
    expected_pairs = [
        (phase, step)
        for step in COLLECTION_SUCCESS_STEPS
        for phase in ("started", "completed")
    ]
    expected_pairs.append(("raw_published", "collection"))
    observed_pairs = [(event["phase"], event["step"]) for event in events]
    if observed_pairs != expected_pairs:
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
            identity=(0, 0, len(data), 0, 0, 0o100600, 1),
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


def _step_command(
    repository: Path,
    collection_path: Path,
    collection: dict[str, str],
    runtime: ProductionCollectorRuntime,
    *,
    step: str,
    argv: list[str],
    expected_exit: int = 0,
    timeout: int = 900,
) -> dict[str, Any]:
    _append_collection_event(
        repository,
        collection_path,
        collection,
        phase="started",
        step=step,
        command=argv,
    )
    receipt = _run_collector_command(
        runtime,
        argv,
        expected_exit=expected_exit,
        timeout=timeout,
        label=f"GA collection {step}",
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

    No raw input path or raw byte payload is accepted.  A durable challenge
    intent is published before observation; all raw documents are held by this
    process and the exact 15-file tree is atomically published only after the
    complete shutdown/restore boundary succeeds.
    """

    repository = _canonical_repository(repository)
    acceptance_path, raw_root = _fixed_paths(repository)
    if os.path.lexists(acceptance_path) or os.path.lexists(raw_root):
        raise _error("GA runtime acceptance or raw evidence already exists")
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
    collection_path = _publish_collection_intent(repository, initial, collection)
    mutation_started = False
    try:
        before_guard = selected_runtime.capture_guard()
        _guard(before_guard, "collection baseline")
        if before_guard != _installed_guard_baseline(repository, initial):
            raise _error("current CFW guard differs from the closed install journal")
        gatekeeper_argv = [
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "open",
            "--context",
            "context:primary-signature",
            "-vv",
            DMG_RELATIVE.as_posix(),
        ]
        gatekeeper = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="dmg-gatekeeper",
            argv=gatekeeper_argv,
        )
        dmg_verify_argv = _dmg_verifier_command(repository)
        dmg_verify = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="dmg-contained-app-byte-proof",
            argv=dmg_verify_argv,
            timeout=DMG_BYTE_PROOF_TIMEOUT_SECONDS,
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
        mutation_started = True
        launch = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="launch",
            argv=["/usr/bin/open", "-a", INSTALLED_APP.as_posix()],
            timeout=120,
        )
        process_running = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="launch-process-observation",
            argv=["/bin/ps", "-axo", "pid=,uid=,lstart=,comm="],
            timeout=60,
        )
        uid = os.geteuid()
        proxy = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="proxy-service-observation",
            argv=["/bin/launchctl", "print", f"gui/{uid}/{PROXY_LABEL}"],
            timeout=60,
        )
        authority = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="authority-service-observation",
            argv=["/bin/launchctl", "print", f"system/{AUTHORITY_LABEL}"],
            timeout=60,
        )
        rejections = [
            _step_command(
                repository,
                collection_path,
                collection,
                selected_runtime,
                step=f"high-risk-{probe_id}",
                argv=list(argv),
                expected_exit=exit_code,
                timeout=60,
            )
            for probe_id, argv, exit_code, _expected_stderr in HIGH_RISK_PROBES
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
            traffic, pcap = selected_runtime.capture_traffic(check_id, tokens)
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
        # The traffic transactions wait for the first macOS approval and
        # prove Tunnel readiness. Observe the enabled extension after that
        # boundary, while Tunnel is still active and before stop/restore.
        system_extension = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="system-extension-observation",
            argv=["/usr/bin/systemextensionsctl", "list"],
            timeout=60,
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
        shutdown = _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="shutdown-request",
            argv=list(SHUTDOWN_APPLE_EVENT),
            timeout=60,
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
        )
        process_stopped = _step_host_absence(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="shutdown-process-observation",
            timeout=60,
        )
        after_guard = selected_runtime.capture_guard()
        _guard(after_guard, "collection restored")
        if after_guard != before_guard:
            raise _error("collection did not restore the exact pre-run CFW state")
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
            "shutdown_command": shutdown,
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
        _publish_collected_raw(repository, files)
        _append_collection_event(
            repository,
            collection_path,
            collection,
            phase="raw_published",
            step="collection",
        )
        result = seal_ga_runtime_acceptance(
            repository=repository,
            expected=final_expected,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
        return result
    except (DurabilityOutcomeUnknown, RootedDirectoryChanged):
        raise
    except BaseException as error:
        try:
            _append_collection_event(
                repository,
                collection_path,
                collection,
                phase=("recovery_required" if mutation_started else "aborted_before_mutation"),
                step="collection",
            )
        except BaseException as event_error:
            raise DurabilityOutcomeUnknown(
                "GA runtime collection failed and recovery state is unknown"
            ) from event_error
        if mutation_started:
            raise GACollectionRecoveryRequired(
                "GA runtime collection crossed the runtime boundary; run fixed recovery"
            ) from error
        raise


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
            "collection",
            "document",
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
        or intent["schema_version"] != SCHEMA_VERSION
        or intent["product"]
        != {
            "from_build": FROM_BUILD,
            "to_build": TO_BUILD,
            "version": PRODUCT_VERSION,
        }
    ):
        raise _error("GA runtime collection intent identity is invalid")
    return intent, collection


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


def recover_ga_runtime_collection(
    *,
    repository: Path,
    expected: object,
    runtime: ProductionCollectorRuntime | None = None,
) -> Path:
    """Run only the fixed runtime shutdown/CFW-restore recovery path."""

    repository = _canonical_repository(repository)
    collection_path = repository.joinpath(*COLLECTION_RELATIVE.parts)
    if not os.path.lexists(collection_path):
        raise _error("there is no active GA runtime collection to recover")
    _intent, collection = _load_collection_intent(repository, collection_path)
    normalized_expected = _validate_expected(expected)
    if (
        collection["ga_environment_sha256"]
        != normalized_expected["ga_environment_sha256"]
    ):
        raise _error("recovery collection binds a different fixed GA environment")
    selected_runtime = runtime or ProductionCollectorRuntime(repository)
    _require_current_environment(
        repository,
        selected_runtime,
        normalized_expected["ga_environment_sha256"],
        label="GA runtime recovery admission environment",
    )
    baseline = _installed_guard_baseline(repository, normalized_expected)
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
        _step_command(
            repository,
            collection_path,
            collection,
            selected_runtime,
            step="runtime-recovery-shutdown-request",
            argv=list(SHUTDOWN_APPLE_EVENT),
            timeout=60,
        )
    _step_host_absence(
        repository,
        collection_path,
        collection,
        selected_runtime,
        step="runtime-recovery-host-process-observation",
        timeout=60,
    )
    off_proof = _step_command(
        repository,
        collection_path,
        collection,
        selected_runtime,
        step="runtime-recovery-off-proof",
        argv=list(OFF_PROOF_COMMAND),
        timeout=60,
    )
    _validate_off_proof_receipt(
        off_proof,
        label="runtime recovery signed Host Off proof",
    )
    _step_host_absence(
        repository,
        collection_path,
        collection,
        selected_runtime,
        step="runtime-recovery-process-observation",
        timeout=60,
    )
    restored = selected_runtime.capture_guard()
    _guard(restored, "runtime recovery")
    if restored != baseline:
        raise _error("runtime recovery did not restore the install-journal CFW guard")
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


def self_check() -> None:
    repository = Path(__file__).resolve().parent.parent
    runner = repository / "scripts/run_ga_runtime_acceptance.sh"
    try:
        runner_metadata = runner.lstat()
        runner_bytes = runner.read_bytes()
    except OSError as error:
        raise _error("GA runtime collector source/build registry is unavailable") from error
    if (
        (PRODUCT_VERSION, FROM_BUILD, TO_BUILD) != ("0.4.0", "40041", "40043")
        or (MAX_COMMAND_SECONDS, DMG_BYTE_PROOF_TIMEOUT_SECONDS)
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
            COLLECTION_EVENT_DOCUMENT,
        )
        != (
            "cfm-ga-runtime-acceptance-v2",
            2,
            "cfm-ga-runtime-check-v2",
            "cfm-ga-command-observation-v2",
            "cfm-ga-runtime-collection-intent-v2",
            "cfm-ga-runtime-collection-event-v2",
        )
        or ACCEPTANCE_RELATIVE
        != Path(
            "target/candidates/0.4.0/ga/40043/stage-inputs/ga-acceptance/"
            "runtime-acceptance.json"
        )
        or RAW_ROOT_RELATIVE
        != Path(
            "target/candidates/0.4.0/ga/40043/stage-inputs/ga-acceptance/"
            "runtime-evidence"
        )
        or ENVIRONMENT_RELATIVE
        != Path(
            "target/candidates/0.4.0/ga/40043/stage-inputs/ga-acceptance/"
            "migration-journals/service-transaction/environment.json"
        )
        or INSTALL_JOURNAL_RELATIVE
        != Path(
            "target/candidates/0.4.0/ga/40043/stage-inputs/ga-acceptance/"
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
        acceptance, raw_root = _fixed_paths(repository)
        result = validate_ga_runtime_acceptance(
            repository=repository,
            acceptance_path=acceptance,
            raw_evidence_root=raw_root,
            expected=expected,
            prepackage_stage_verifier=prepackage_stage_verifier,
        )
    except (GARuntimeAcceptanceError, OSError, PublicationError, ValueError) as error:
        raise SystemExit(f"error: GA runtime acceptance: {error}") from error
    return (
        "GA runtime acceptance verified: "
        f"{result['adapter']['sha256']} ({len(CHECKS)} raw-derived checks)"
    )
