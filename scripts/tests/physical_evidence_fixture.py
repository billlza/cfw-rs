"""Deterministic proof-to-byte fixtures for physical-evidence tests only.

The RSA key is the public example key from RFC 7515 Appendix A.2. It is
intentionally public and must never be used as a production collector key.
"""

from __future__ import annotations

import base64
import calendar
import copy
from datetime import datetime, timezone
import hashlib
import ipaddress
from pathlib import Path
import struct
from typing import Any

from scripts.harness.adversarial_clients import (
    HARNESS_VERSION as ADVERSARIAL_VERSION,
    REQUIRED_CASES as ADVERSARIAL_CASES,
)
from scripts.harness.lifecycle_matrix import (
    HARNESS_VERSION as LIFECYCLE_VERSION,
    PROBE_SPECS,
)
from scripts.harness.packet_evidence import (
    HARNESS_VERSION as PACKET_VERSION,
    REQUIRED_CASES as PACKET_CASES,
)
from scripts.harness.performance_gates import (
    HARNESS_VERSION as PERFORMANCE_VERSION,
    WEAK_NETWORK_PROFILES,
    percentiles,
)
from scripts.harness.physical_evidence_aggregator import (
    AGGREGATOR_VERSION,
    GRANTED_LEVEL,
    _receipt_payload,
)
from scripts.harness.raw_artifacts import (
    CollectorTrustPolicy,
    canonical_json,
    parse_trust_policy_bytes,
)


APP_MANIFEST = "a" * 64
SIGNED_TREE = "b" * 64
BUILD_NUMBER = "40000"
BUILT_AT = "2026-07-01T00:00:00Z"
CAPTURED_AT = "2026-07-27T12:00:00Z"
PERFORMANCE_COMPLETED_AT = "2026-07-28T12:00:00Z"
REPORT_SIGNED_AT = "2026-07-28T12:30:00Z"
RUN_CAPTURED_AT = CAPTURED_AT
RUN_COMPLETED_AT = PERFORMANCE_COMPLETED_AT
RUN_SIGNED_AT = "2026-07-28T13:00:00Z"
COLLECTOR_VERSION = "physical-collector-v1"
COLLECTOR_SOURCE = "c" * 64
COLLECTOR_EXECUTABLE = "d" * 64
TEST_KEY_ID = "rfc7515-test-only"

# RFC 7515 Appendix A.2 example key, display whitespace removed.
RFC7515_N = (
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
    "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
    "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
    "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
    "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
    "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
)
RFC7515_E = "AQAB"
RFC7515_D = (
    "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
    "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
    "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
    "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
    "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
    "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
)

_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


RFC_MODULUS = int.from_bytes(_b64url_decode(RFC7515_N), "big")
RFC_EXPONENT = int.from_bytes(_b64url_decode(RFC7515_E), "big")
RFC_PRIVATE_EXPONENT = int.from_bytes(_b64url_decode(RFC7515_D), "big")


def rs256_sign(message: bytes) -> str:
    width = (RFC_MODULUS.bit_length() + 7) // 8
    digest_info = _DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    encoded = (
        b"\x00\x01"
        + b"\xff" * (width - len(digest_info) - 3)
        + b"\x00"
        + digest_info
    )
    signature = pow(
        int.from_bytes(encoded, "big"), RFC_PRIVATE_EXPONENT, RFC_MODULUS
    ).to_bytes(width, "big")
    return _b64url_encode(signature)


def test_policy() -> CollectorTrustPolicy:
    value = {
        "alg": "RS256",
        "collector_executable_sha256": COLLECTOR_EXECUTABLE,
        "collector_source_sha256": COLLECTOR_SOURCE,
        "collector_version": COLLECTOR_VERSION,
        "e": RFC7515_E,
        "key_id": TEST_KEY_ID,
        "kty": "RSA",
        "n": RFC7515_N,
        "schema_version": 1,
        "state": "configured",
    }
    data = canonical_json(value) + b"\n"
    return parse_trust_policy_bytes(
        data, expected_sha256=hashlib.sha256(data).hexdigest()
    )


TEST_POLICY = test_policy()


def sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def descriptor(kind: str, path: str, data: bytes) -> dict[str, Any]:
    return {
        "kind": kind,
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def pcap_bytes(
    *,
    start_marker: bytes,
    token: bytes,
    end_marker: bytes,
    include_token: bool,
    malformed: bool = False,
    protocol: str = "tcp",
    family: str = "ipv4",
    local_address: str | None = None,
    remote_address: str | None = None,
    local_port: int = 41000,
    remote_port: int | None = None,
    link_type: int = 1,
    vlan_tags: int = 0,
    include_tcp_fallback: bool = False,
) -> bytes:
    """Build a structurally valid transport capture for v3 packet fixtures."""

    if family not in {"ipv4", "ipv6"}:
        raise ValueError("fixture packet family is invalid")
    local_address = local_address or ("192.0.2.10" if family == "ipv4" else "2001:db8:1::10")
    remote_address = remote_address or (
        "198.51.100.20" if family == "ipv4" else "2001:db8:2::20"
    )
    remote_port = remote_port or (53 if protocol == "dns" else 443)
    epoch = calendar.timegm(datetime(2026, 7, 27, 12, tzinfo=timezone.utc).timetuple())
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)

    def dns_query(label: bytes, identifier: int) -> bytes:
        qtype = 1 if family == "ipv4" else 28
        suffix = (b"evidence", b"test")
        qname = bytes([len(label)]) + label
        for component in suffix:
            qname += bytes([len(component)]) + component
        qname += b"\x00"
        return struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + qname + struct.pack(
            "!HH", qtype, 1
        )

    def quic_packet(connection_id: bytes) -> bytes:
        source_id = b"fixture1"
        return (
            b"\xc0"
            + (1).to_bytes(4, "big")
            + bytes([len(connection_id)])
            + connection_id
            + bytes([len(source_id)])
            + source_id
        )

    def transport(payload: bytes, sequence: int, identifier: int) -> bytes:
        if protocol == "tcp":
            return struct.pack(
                "!HHIIBBHHH",
                local_port,
                remote_port,
                sequence,
                0,
                5 << 4,
                0x18,
                65535,
                0,
                0,
            ) + payload
        application = (
            dns_query(payload, identifier)
            if protocol == "dns"
            else quic_packet(payload)
            if protocol == "quic"
            else payload
        )
        return struct.pack(
            "!HHHH", local_port, remote_port, len(application) + 8, 0
        ) + application

    def network(payload: bytes, protocol_number: int, identifier: int) -> bytes:
        source = ipaddress.ip_address(local_address).packed
        destination = ipaddress.ip_address(remote_address).packed
        if family == "ipv4":
            total = 20 + len(payload)
            return (
                struct.pack(
                    "!BBHHHBBH4s4s",
                    0x45,
                    0,
                    total,
                    identifier,
                    0x4000,
                    64,
                    protocol_number,
                    0,
                    source,
                    destination,
                )
                + payload
            )
        return struct.pack(
            "!IHBB16s16s",
            6 << 28,
            len(payload),
            protocol_number,
            64,
            source,
            destination,
        ) + payload

    def link_frame(payload: bytes) -> bytes:
        ether_type = 0x0800 if family == "ipv4" else 0x86DD
        if link_type == 1:
            frame = b"\x02" * 6 + b"\x04" * 6
            for _ in range(vlan_tags):
                frame += (0x8100).to_bytes(2, "big") + b"\x00\x01"
            return frame + ether_type.to_bytes(2, "big") + payload
        if link_type == 101:
            return payload
        if link_type == 0:
            return (2 if family == "ipv4" else 30).to_bytes(4, "little") + payload
        if link_type == 108:
            return (2 if family == "ipv4" else 30).to_bytes(4, "big") + payload
        if link_type == 113:
            return struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, ether_type) + payload
        if link_type == 276:
            return struct.pack("!HHIHBB8s", ether_type, 0, 1, 1, 0, 6, b"\x00" * 8) + payload
        raise ValueError("fixture link type is unsupported")

    tokens = [start_marker]
    if include_token:
        tokens.append(token)
    tokens.append(end_marker)
    body = bytearray()
    sequence = 1000
    for packet_index, application in enumerate(tokens):
        protocol_number = 6 if protocol == "tcp" else 17
        transport_bytes = transport(application, sequence, packet_index + 1)
        frame = link_frame(network(transport_bytes, protocol_number, packet_index + 1))
        timestamp = epoch + (5 if packet_index == len(tokens) - 1 else packet_index)
        body.extend(struct.pack("<IIII", timestamp, 0, len(frame), len(frame)))
        body.extend(frame)
        sequence += len(application)
    if include_tcp_fallback:
        tcp_header = struct.pack(
            "!HHIIBBHHH", local_port, remote_port, sequence, 0, 5 << 4, 0x18, 65535, 0, 0
        )
        frame = link_frame(network(tcp_header + b"fallback", 6, 99))
        body.extend(struct.pack("<IIII", epoch + 2, 0, len(frame), len(frame)))
        body.extend(frame)
    result = header + bytes(body)
    return result[:-1] if malformed else result


def _summary(samples: list[float]) -> dict[str, float]:
    return percentiles([float(value) for value in samples])


class PhysicalEvidenceFixture:
    """Materialize one complete two-run aggregate and all referenced bytes."""

    def __init__(self, root: Path, prefix: str = "evidence") -> None:
        self.root = root.absolute()
        self.prefix = prefix.strip("/")
        self.policy = TEST_POLICY
        self.candidate = {
            "version": "0.4.0",
            "build_number": BUILD_NUMBER,
            "app_manifest_sha256": APP_MANIFEST,
            "signed_app_tree_sha256": SIGNED_TREE,
            "built_at": BUILT_AT,
        }
        self.aggregate: dict[str, Any] = {
            "schema_version": 2,
            "aggregator_version": AGGREGATOR_VERSION,
            "granted_level": GRANTED_LEVEL,
            "trust_policy_sha256": self.policy.policy_sha256,
            "candidate": self.candidate,
            "runs": [],
        }
        self.report_documents: list[dict[str, dict[str, Any]]] = []
        self.report_bindings: list[list[dict[str, Any]]] = []
        self.raw_bindings: list[list[dict[str, Any]]] = []
        for index, (os_label, version, build) in enumerate(
            (("macos15", "15.7.8", "24G824"), ("current-macos", "26.6", "25G72"))
        ):
            self._build_run(index, os_label, version, build)

    def _write(self, relative: str, data: bytes, kind: str) -> dict[str, Any]:
        path = f"{self.prefix}/{relative}"
        absolute = self.root / path
        absolute.parent.mkdir(parents=True, exist_ok=True)
        absolute.write_bytes(data)
        return descriptor(kind, path, data)

    def _write_json(self, relative: str, value: Any, kind: str) -> dict[str, Any]:
        return self._write(relative, canonical_json(value) + b"\n", kind)

    def rewrite(self, artifact: dict[str, Any], data: bytes) -> None:
        absolute = self.root / artifact["path"]
        absolute.write_bytes(data)
        artifact["size"] = len(data)
        artifact["sha256"] = hashlib.sha256(data).hexdigest()

    def rewrite_json(self, artifact: dict[str, Any], value: Any) -> None:
        self.rewrite(artifact, canonical_json(value) + b"\n")

    def _proof(self, run_id: str, run_nonce: str) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "run_nonce": run_nonce,
            "candidate": {
                key: self.candidate[key]
                for key in (
                    "version",
                    "build_number",
                    "app_manifest_sha256",
                    "signed_app_tree_sha256",
                )
            },
            "collector": {
                "version": COLLECTOR_VERSION,
                "source_sha256": COLLECTOR_SOURCE,
                "executable_sha256": COLLECTOR_EXECUTABLE,
            },
        }

    def _packet_report(
        self, run_name: str, proof: dict[str, Any], macos_version: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        cases: list[dict[str, Any]] = []
        bindings: list[dict[str, Any]] = []
        for index, (case_id, spec) in enumerate(PACKET_CASES.items()):
            token = "t" + sha(f"{run_name}-{case_id}-target")[:19]
            start = "s" + sha(f"{run_name}-{case_id}-start")[:19]
            end = "e" + sha(f"{run_name}-{case_id}-finish")[:19]
            local_address = "192.0.2.10" if spec.family == "ipv4" else "2001:db8:1::10"
            remote_address = (
                f"198.51.100.{index + 1}"
                if spec.family == "ipv4"
                else f"2001:db8:2::{index + 1}"
            )
            remote_port = 53 if spec.protocol == "dns" else 5300 if spec.protocol == "udp" else 443
            capture = pcap_bytes(
                start_marker=start.encode("ascii"),
                token=token.encode("ascii"),
                end_marker=end.encode("ascii"),
                include_token=spec.token_observed,
                protocol=spec.protocol,
                family=spec.family,
                local_address=local_address,
                remote_address=remote_address,
                remote_port=remote_port,
            )
            artifact = self._write(
                f"{run_name}/packet/{case_id}.pcap", capture, "packet-pcap"
            )
            interface_name = (
                "en1"
                if spec.vantage == "lan_segment"
                else "en0"
                if spec.vantage in {"direct_wan", "independent_server"}
                else "utun5"
            )
            provenance = {
                "schema_version": 1,
                "proof": copy.deepcopy(proof),
                "case_id": case_id,
                "interface": {"name": interface_name, "index": 5, "link_type": 1},
                "capture_point": spec.vantage,
                "resolver_role": spec.resolver_role,
                "capture_filter_sha256": sha(f"{run_name}-{case_id}-capture-filter"),
                "capture_command_sha256": sha(f"{run_name}-{case_id}-capture-command"),
                "quic_version": 1 if spec.protocol == "quic" else None,
                "endpoint_set": [
                    {
                        "role": "local",
                        "address": local_address,
                        "port": 41000,
                        "transport": "tcp" if spec.protocol == "tcp" else "udp",
                    },
                    {
                        "role": "remote",
                        "address": remote_address,
                        "port": remote_port,
                        "transport": "tcp" if spec.protocol == "tcp" else "udp",
                    },
                ],
                "started_at": CAPTURED_AT,
                "completed_at": "2026-07-27T12:00:05Z",
                "signed_at": "2026-07-27T12:00:10Z",
            }
            provenance_artifact = self._write_json(
                f"{run_name}/packet/{case_id}-provenance.json",
                provenance,
                "packet-capture-provenance",
            )
            attempt_artifact = None
            if not spec.token_observed:
                attempt = {
                    "schema_version": 1,
                    "proof": copy.deepcopy(proof),
                    "case_id": case_id,
                    "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
                    "send_command_sha256": sha(f"{run_name}-{case_id}-send-command"),
                    "capture_provenance_sha256": provenance_artifact["sha256"],
                    "endpoint_set": copy.deepcopy(provenance["endpoint_set"]),
                    "started_at": "2026-07-27T12:00:01Z",
                    "completed_at": "2026-07-27T12:00:02Z",
                    "recorded_at": "2026-07-27T12:00:11Z",
                    "exit_code": 0,
                    "bytes_submitted": len(token.encode("ascii")),
                }
                attempt_artifact = self._write_json(
                    f"{run_name}/packet/{case_id}-send-attempt.json",
                    attempt,
                    "packet-send-attempt",
                )
            cases.append(
                {
                    "id": case_id,
                    "protocol": spec.protocol,
                    "family": spec.family,
                    "resolver_role": spec.resolver_role,
                    "vantage": spec.vantage,
                    "token": token,
                    "window_start_token": start,
                    "window_end_token": end,
                    "token_observed": spec.token_observed,
                    "observation_ms": 5_000,
                    "quic_version": 1 if spec.protocol == "quic" else None,
                    "capture_filter_sha256": provenance["capture_filter_sha256"],
                    "capture_command_sha256": provenance["capture_command_sha256"],
                    "send_command_sha256": sha(f"{run_name}-{case_id}-send-command"),
                    "artifact": artifact,
                    "provenance_artifact": provenance_artifact,
                    "attempt_artifact": attempt_artifact,
                }
            )
            bindings.append({"harness": "packet", "subject": case_id, "descriptor": artifact})
            bindings.append(
                {
                    "harness": "packet",
                    "subject": f"{case_id}:capture-provenance",
                    "descriptor": provenance_artifact,
                }
            )
            if attempt_artifact is not None:
                bindings.append(
                    {
                        "harness": "packet",
                        "subject": f"{case_id}:send-attempt",
                        "descriptor": attempt_artifact,
                    }
                )
        return (
            {
                "schema_version": 3,
                "harness_version": PACKET_VERSION,
                "proof": copy.deepcopy(proof),
                "platform": {
                    "architecture": "arm64",
                    "macos_version": macos_version,
                    "hardware_model": "Mac16,1 fixture",
                    "clean_install": True,
                },
                "captured_at": CAPTURED_AT,
                "completed_at": "2026-07-27T12:00:05Z",
                "signed_at": "2026-07-27T12:00:12Z",
                "cases": cases,
            },
            bindings,
        )

    def _lifecycle_report(
        self,
        run_name: str,
        proof: dict[str, Any],
        machine: str,
        macos_build: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        environment = {
            "machine_sha256": machine,
            "macos_build": macos_build,
            "architecture": "arm64",
            "operation_context": {
                "operation_id": f"operation-{run_name}",
                "installation_id": f"installation-{run_name}",
                "epoch": 3,
                "generation": 7,
            },
        }
        probes: list[dict[str, Any]] = []
        bindings: list[dict[str, Any]] = []
        for index, probe_id in enumerate(sorted(PROBE_SPECS)):
            category, exit_code, observation, checks = PROBE_SPECS[probe_id]
            attributes: dict[str, Any] = {}
            if "user_count" in checks:
                attributes["user_count"] = 2
            if "concurrent_start_count" in checks:
                attributes["concurrent_start_count"] = 2
            started = datetime(2026, 7, 27, 12, index, tzinfo=timezone.utc)
            finished = datetime(2026, 7, 27, 12, index, 1, tzinfo=timezone.utc)
            raw = {
                "schema_version": 1,
                "proof": copy.deepcopy(proof),
                "environment": copy.deepcopy(environment),
                "probe_id": probe_id,
                "category": category,
                "command": [COLLECTOR_VERSION, "lifecycle", probe_id],
                "started_at": started.isoformat().replace("+00:00", "Z"),
                "finished_at": finished.isoformat().replace("+00:00", "Z"),
                "exit_code": exit_code,
                "events": [
                    {
                        "sequence": 0,
                        "type": "probe-started",
                        "probe_id": probe_id,
                        "observation": "",
                    },
                    {
                        "sequence": 1,
                        "type": "probe-observation",
                        "probe_id": probe_id,
                        "observation": observation,
                    },
                    {
                        "sequence": 2,
                        "type": "probe-finished",
                        "probe_id": probe_id,
                        "observation": "",
                    },
                ],
                "attributes": attributes,
            }
            artifact = self._write_json(
                f"{run_name}/lifecycle/{probe_id}.json", raw, "lifecycle-event"
            )
            probes.append({"id": probe_id, "attributes": attributes, "artifact": artifact})
            bindings.append(
                {"harness": "lifecycle", "subject": probe_id, "descriptor": artifact}
            )
        completed_at = datetime(
            2026, 7, 27, 12, len(PROBE_SPECS) - 1, 1, tzinfo=timezone.utc
        )
        return (
            {
                "schema_version": 2,
                "harness_version": LIFECYCLE_VERSION,
                "proof": copy.deepcopy(proof),
                "environment": environment,
                "captured_at": CAPTURED_AT,
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "signed_at": "2026-07-27T12:30:00Z",
                "probes": probes,
            },
            bindings,
        )

    def _performance_report(
        self,
        run_name: str,
        proof: dict[str, Any],
        machine: str,
        macos_version: str,
        macos_build: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        parameters = {
            "machine": {
                "architecture": "arm64",
                "macos_version": macos_version,
                "macos_build": macos_build,
                "hardware_model": "Mac16,1 fixture",
                "machine_sha256": machine,
                "clean_install": True,
            },
            "network": {"description": "isolated shaping bridge", "uplink_mbps": 1000},
            "power": {"source": "ac", "low_power_mode": False},
        }
        weak_declared: list[dict[str, Any]] = []
        weak_raw: list[dict[str, Any]] = []
        for profile_id, expected in WEAK_NETWORK_PROFILES.items():
            control = {"applied": True, **expected}
            samples = [4_000.0 + (index % 3) * 500.0 for index in range(20)]
            weak_declared.append(
                {"id": profile_id, "control": control, "recovery_ms": _summary(samples)}
            )
            weak_raw.append(
                {
                    "id": profile_id,
                    "control": {
                        **control,
                        "applied_at": CAPTURED_AT,
                        "command_exit_code": 0,
                    },
                    "recovery_ms": samples,
                }
            )
        latency_raw = {
            "connect_ms": [1000.0 + (index % 4) * 250.0 for index in range(20)],
            "disconnect_ms": [500.0 + (index % 4) * 125.0 for index in range(20)],
            "added_latency_percent": [2.0 + (index % 4) * 0.5 for index in range(20)],
        }
        resources_raw = {
            "active_idle_cpu_percent": [0.2 + (index % 4) * 0.1 for index in range(20)],
            "active_rss_mib": [60.0 + (index % 4) * 5.0 for index in range(20)],
        }
        switch_records = [
            {
                "index": index,
                "rss_mib": 50.0 + (1.0 if index else 0.0),
                "fd_count": 10 + (1 if index else 0),
            }
            for index in range(101)
        ]
        raw = {
            "schema_version": 1,
            "captured_at": CAPTURED_AT,
            "completed_at": PERFORMANCE_COMPLETED_AT,
            "proof": copy.deepcopy(proof),
            "parameters": copy.deepcopy(parameters),
            "weak_network": weak_raw,
            "latency": latency_raw,
            "throughput": {
                "baseline_mbps": [100.0] * 20,
                "measured_mbps": [95.0] * 20,
            },
            "resources": resources_raw,
            "switch_cycle": {"records": switch_records},
            "soak": {
                "started_at": CAPTURED_AT,
                "ended_at": PERFORMANCE_COMPLETED_AT,
                "crash_events": [],
            },
        }
        artifact = self._write_json(
            f"{run_name}/performance/samples.json", raw, "performance-samples"
        )
        report = {
            "schema_version": 2,
            "harness_version": PERFORMANCE_VERSION,
            "captured_at": CAPTURED_AT,
            "completed_at": PERFORMANCE_COMPLETED_AT,
            "signed_at": REPORT_SIGNED_AT,
            "proof": copy.deepcopy(proof),
            "parameters": parameters,
            "weak_network": weak_declared,
            "latency": {key: _summary(value) for key, value in latency_raw.items()},
            "throughput": {
                "baseline_mbps": 100.0,
                "measured_mbps": 95.0,
                "ratio_percent": 95.0,
            },
            "resources": {key: _summary(value) for key, value in resources_raw.items()},
            "switch_cycle": {"switch_count": 100, "rss_growth_mib": 1.0, "fd_growth": 1},
            "soak": {"duration_hours": 24.0, "crash_count": 0},
            "samples_artifact": artifact,
        }
        return report, [
            {"harness": "performance", "subject": "measurements", "descriptor": artifact}
        ]

    def _adversarial_report(
        self, run_name: str, proof: dict[str, Any], macos_version: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        identities = {
            "allowed": {
                "signing_id": "com.bill.clashformac",
                "cdhash": sha(f"{run_name}-allowed-cdhash")[:40],
                "designated_requirement_sha256": sha(f"{run_name}-allowed-requirement"),
                "binary_sha256": sha(f"{run_name}-allowed-binary"),
            },
            "denied": {
                "signing_id": "com.bill.clashformac.adversary",
                "cdhash": sha(f"{run_name}-denied-cdhash")[:40],
                "designated_requirement_sha256": sha(f"{run_name}-denied-requirement"),
                "binary_sha256": sha(f"{run_name}-denied-binary"),
            },
        }
        bindings: list[dict[str, Any]] = []
        signing: dict[str, Any] = {"team_id": "YKUPL7Z869"}
        for client, identity in identities.items():
            raw = {
                "schema_version": 1,
                "proof": copy.deepcopy(proof),
                "client": client,
                "team_id": "YKUPL7Z869",
                **identity,
                "command": [COLLECTOR_VERSION, "client-signature", client],
                "exit_code": 0,
                "assessed_at": CAPTURED_AT,
            }
            artifact = self._write_json(
                f"{run_name}/adversarial/{client}-signature.json",
                raw,
                "client-signature-evidence",
            )
            signing[f"{client}_client"] = {**identity, "evidence_artifact": artifact}
            bindings.append(
                {
                    "harness": "adversarial",
                    "subject": f"client-signature:{client}",
                    "descriptor": artifact,
                }
            )

        transcript_finishes: list[datetime] = []

        def transcript(
            case_id: str,
            category: str,
            client: str,
            outcome: str,
            denial_code: str,
            cleanup: str,
            offset: int,
        ) -> dict[str, Any]:
            started = datetime(2026, 7, 27, 12, 0, offset, tzinfo=timezone.utc)
            finished = datetime(2026, 7, 27, 12, 0, offset + 1, tzinfo=timezone.utc)
            transcript_finishes.append(finished)
            raw = {
                "schema_version": 1,
                "proof": copy.deepcopy(proof),
                "case_id": case_id,
                "category": category,
                "client": client,
                "client_binary_sha256": identities[client]["binary_sha256"],
                "request_nonce": sha(f"{run_name}-{case_id}-request"),
                "command": [COLLECTOR_VERSION, "adversarial", case_id],
                "started_at": started.isoformat().replace("+00:00", "Z"),
                "finished_at": finished.isoformat().replace("+00:00", "Z"),
                "exit_code": 0 if outcome == "authorized" else 77,
                "events": [
                    {
                        "sequence": 0,
                        "type": "attack-started",
                        "case_id": case_id,
                        "outcome": "",
                        "denial_code": "",
                        "cleanup": "",
                        "secret_observed": False,
                    },
                    {
                        "sequence": 1,
                        "type": "authorization-decision",
                        "case_id": case_id,
                        "outcome": outcome,
                        "denial_code": denial_code,
                        "cleanup": cleanup,
                        "secret_observed": False,
                    },
                    {
                        "sequence": 2,
                        "type": "attack-finished",
                        "case_id": case_id,
                        "outcome": "",
                        "denial_code": "",
                        "cleanup": "",
                        "secret_observed": False,
                    },
                ],
            }
            artifact = self._write_json(
                f"{run_name}/adversarial/{case_id}.json",
                raw,
                "adversarial-transcript",
            )
            bindings.append(
                {"harness": "adversarial", "subject": case_id, "descriptor": artifact}
            )
            return artifact

        baseline_artifact = transcript(
            "baseline", "baseline", "allowed", "authorized", "", "off", 0
        )
        cases: list[dict[str, Any]] = []
        for index, (case_id, spec) in enumerate(sorted(ADVERSARIAL_CASES.items()), start=2):
            category, client, denial_code, cleanup = spec
            artifact = transcript(
                case_id, category, client, "denied", denial_code, cleanup, index
            )
            cases.append(
                {"id": case_id, "category": category, "client": client, "artifact": artifact}
            )
        return (
            {
                "schema_version": 2,
                "harness_version": ADVERSARIAL_VERSION,
                "proof": copy.deepcopy(proof),
                "captured_at": CAPTURED_AT,
                "completed_at": max(transcript_finishes).isoformat().replace(
                    "+00:00", "Z"
                ),
                "signed_at": "2026-07-27T12:01:00Z",
                "platform": {
                    "architecture": "arm64",
                    "macos_version": macos_version,
                    "hardware_model": "Mac16,1 fixture",
                    "clean_install": True,
                },
                "signing": signing,
                "baseline": {"client": "allowed", "artifact": baseline_artifact},
                "cases": cases,
            },
            bindings,
        )

    def _build_run(self, index: int, os_label: str, version: str, build: str) -> None:
        run_name = f"run-{index}"
        run_id = f"physical-{run_name}"
        run_nonce = sha(f"{run_name}-nonce")
        machine = sha(f"{run_name}-machine")
        proof = self._proof(run_id, run_nonce)
        documents: dict[str, dict[str, Any]] = {}
        raw_bindings: list[dict[str, Any]] = []
        documents["packet"], packet_raw = self._packet_report(run_name, proof, version)
        documents["lifecycle"], lifecycle_raw = self._lifecycle_report(
            run_name, proof, machine, build
        )
        documents["performance"], performance_raw = self._performance_report(
            run_name, proof, machine, version, build
        )
        documents["adversarial"], adversarial_raw = self._adversarial_report(
            run_name, proof, version
        )
        raw_bindings.extend(packet_raw + lifecycle_raw + performance_raw + adversarial_raw)

        reports: dict[str, Any] = {}
        report_bindings: list[dict[str, Any]] = []
        versions = {
            "packet": PACKET_VERSION,
            "lifecycle": LIFECYCLE_VERSION,
            "performance": PERFORMANCE_VERSION,
            "adversarial": ADVERSARIAL_VERSION,
        }
        kinds = {
            "packet": "packet-report",
            "lifecycle": "lifecycle-report",
            "performance": "performance-report",
            "adversarial": "adversarial-report",
        }
        for harness, document in documents.items():
            artifact = self._write_json(
                f"{run_name}/reports/{harness}.json", document, kinds[harness]
            )
            reports[harness] = {
                "tool_version": versions[harness],
                "captured_at": CAPTURED_AT,
                "completed_at": document["completed_at"],
                "signed_at": document["signed_at"],
                "artifact": artifact,
            }
            report_bindings.append(
                {
                    "harness": harness,
                    "tool_version": versions[harness],
                    "captured_at": CAPTURED_AT,
                    "completed_at": document["completed_at"],
                    "signed_at": document["signed_at"],
                    "descriptor": artifact,
                }
            )
        collector = {
            "version": COLLECTOR_VERSION,
            "source_sha256": COLLECTOR_SOURCE,
            "executable_sha256": COLLECTOR_EXECUTABLE,
            "key_id": TEST_KEY_ID,
            "algorithm": "RS256",
            "signature": "pending",
        }
        run = {
            "os": os_label,
            "macos_version": version,
            "macos_build": build,
            "machine_sha256": machine,
            "clean_install": True,
            "captured_at": RUN_CAPTURED_AT,
            "completed_at": RUN_COMPLETED_AT,
            "signed_at": RUN_SIGNED_AT,
            "run_id": run_id,
            "run_nonce": run_nonce,
            "collector": collector,
            "reports": reports,
        }
        payload = _receipt_payload(
            policy_sha256=self.policy.policy_sha256,
            candidate=self.candidate,
            run=run,
            collector=collector,
            report_bindings=report_bindings,
            raw_bindings=raw_bindings,
        )
        collector["signature"] = rs256_sign(canonical_json(payload))
        self.aggregate["runs"].append(run)
        self.report_documents.append(documents)
        self.report_bindings.append(report_bindings)
        self.raw_bindings.append(raw_bindings)

    def resign_run(self, index: int) -> None:
        run = self.aggregate["runs"][index]
        for binding in self.report_bindings[index]:
            harness = binding["harness"]
            self.rewrite_json(binding["descriptor"], self.report_documents[index][harness])
        payload = _receipt_payload(
            policy_sha256=self.policy.policy_sha256,
            candidate=self.candidate,
            run=run,
            collector=run["collector"],
            report_bindings=self.report_bindings[index],
            raw_bindings=self.raw_bindings[index],
        )
        run["collector"]["signature"] = rs256_sign(canonical_json(payload))

    def write_aggregate(self, relative: str = "aggregate.json") -> Path:
        path = self.root / self.prefix / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json(self.aggregate) + b"\n")
        return path

    def write_aggregate_artifact(self, relative: str = "aggregate.json") -> dict[str, Any]:
        """Materialize and describe the private archive's aggregate edge."""

        path = self.write_aggregate(relative)
        data = path.read_bytes()
        return descriptor(
            "physical-aggregate",
            path.relative_to(self.root).as_posix(),
            data,
        )
