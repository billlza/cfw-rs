"""Deterministic proof-to-byte fixtures for physical-evidence tests only.

The static RSA-3072 private key below is intentionally committed for tests. It
must never be provisioned as, or accepted in place of, a production KMS key.
"""

from __future__ import annotations

import base64
import calendar
import copy
from datetime import datetime, timedelta, timezone
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
    SCHEMA_VERSION as AGGREGATE_SCHEMA_VERSION,
    GRANTED_LEVEL,
    _receipt_payload,
)
from scripts.harness.raw_artifacts import (
    COLLECTOR_SIGNATURE_ALGORITHM,
    EVIDENCE_PROFILE,
    KMS_ATTESTATION_FORMATS,
    KMS_PROTECTION_LEVEL,
    KMS_SIGNATURE_ALGORITHM,
    CollectorTrustPolicy,
    PROOF_SCHEMA_VERSION,
    canonical_json,
    parse_trust_policy_bytes,
    rsa_spki_sha256,
)
from scripts.publication.common import tree_digest


APP_MANIFEST = "a" * 64
SIGNED_TREE = "b" * 64
BUILD_NUMBER = "40000"
BUILT_AT = "2026-07-01T00:00:00Z"
CAPTURED_AT = "2026-07-27T12:00:00Z"
PERFORMANCE_COMPLETED_AT = "2026-07-27T15:00:00Z"
REPORT_SIGNED_AT = "2026-07-27T15:30:00Z"
RUN_CAPTURED_AT = CAPTURED_AT
RUN_COMPLETED_AT = PERFORMANCE_COMPLETED_AT
RUN_SIGNED_AT = "2026-07-27T16:00:00Z"
RUN_TIMELINE_OFFSET = timedelta(hours=4)
COLLECTOR_VERSION = "physical-collector-v1"
COLLECTOR_SOURCE = "c" * 64
COLLECTOR_EXECUTABLE = "d" * 64
TEST_KEY_VERSION = (
    "projects/cfw-fixture/locations/global/keyRings/physical-evidence/"
    "cryptoKeys/collector/cryptoKeyVersions/1"
)
TEST_ATTESTATION_SHA256 = (
    "cfa5aaa67ba711050d3da0901a55ec23df669a7e2ce25f47214f4b3afd5f3957"
)
TEST_ATTESTATION_FORMAT = "CAVIUM_V2_COMPRESSED"
assert TEST_ATTESTATION_FORMAT in KMS_ATTESTATION_FORMATS

TEST_RSA_N = (
    "2EcuGnEhqLCbHkPQ4n-jNV2C35bMgCc-FxCLnlDVpMG6rska5YOvTT33zEweRzeQ5oETbgI30XyEPMXBa5bf6NPRw5duXfMOAc3VAZnYhZ9BQY46UsJahCyp7qy6XFAdgerF9DvA6A1EyksMcacAb5eYk1kfTHVwBiye4F5H2jyt8YTfR76ywGozntA0ROnunSlYdJj_fydAxhFURmCi45rpvtUY_KwxtGDx_u3h0SDPRcW3ICZWNPtx4KqmNkEu-qiEhbsOQOz7xShwyan0zoHmpIIB5Cc7j0aWFW42wNdML0Nrb-8736I_TH-UCR5q5FmB0PcFNIFIFXVWDtSE5_J49lYjyxIpdbIusLbvdDpEXbc5ph6nfkDweC2EJ6uYpdxYKbbZV4Z1fDLIL2g3-MH7IfXeU06fUdZD3ANw3O6bLqoiSmRdkerdHakvhXaHiMmugjY7gy7jfCt8xrVWqSIA2PMsLkjAnQrQgILh40Lxv8rO8s3pIoj0M9vHQvk_"
)
TEST_RSA_E = "AQAB"
TEST_RSA_D = (
    "FUv7dARPd_v3M_JVMsIczfF1ixM484zQGWQgsds5EaGeApewLu-NQI7pXe2ugZbGjVwidkLm2jMBSbazbPPAL34Q-f1pLPxbe1cx_v4pcXPII9UGIZ-2KBPGomEFDN5t7JznFz19dmkJrN3ZzaTQCMalvvfkrbO9Im6Cyopq8UhOXJAxjsmhcnJCv2qDHlIZ-mtxPjIFEeR8nveWRxCjzMPOLP0KgKVrU5Bd5AHqqmj2E0nJb_Oc3SS-OiazrURnvIbXvLbgSnfSc3z-mpJcoNaw0zRPL_VjoKEicdqYPDFJBlR4UfblnQW4lec8qdBe12Fxzp72VyhN1DdLisFemDj6BSjzoxjt97N-Ecb-5lApO-TFMoJYlVm04svF_vmPQx1i2qr001iOBPYw38y5yTobckk7OnYy5cvjrdI5RwcjzI4P0t6sryH4iKeU8sUJMZK3x09ErdMePOkQy7UXHjlVclWYbpKhSQF58ZenFEFDYn5UIggpBE7NyOPVYHgx"
)


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


TEST_MODULUS = int.from_bytes(_b64url_decode(TEST_RSA_N), "big")
TEST_EXPONENT = int.from_bytes(_b64url_decode(TEST_RSA_E), "big")
TEST_PRIVATE_EXPONENT = int.from_bytes(_b64url_decode(TEST_RSA_D), "big")
TEST_PUBLIC_KEY_SHA256 = rsa_spki_sha256(TEST_MODULUS, TEST_EXPONENT)
DEFAULT_PSS_SALT = hashlib.sha256(b"cfw-ps256-fixture-salt-v1").digest()


def _fixture_mgf(seed: bytes, length: int, hash_name: str) -> bytes:
    digest_size = hashlib.new(hash_name).digest_size
    return b"".join(
        hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest()
        for counter in range((length + digest_size - 1) // digest_size)
    )[:length]


def pss_encoded_message(
    message: bytes,
    *,
    salt: bytes = DEFAULT_PSS_SALT,
    message_hash_name: str = "sha256",
    mgf_hash_name: str = "sha256",
    trailer: int = 0xBC,
    padding_byte: int = 0,
    delimiter: int = 1,
    force_unused_high_bit: bool = False,
) -> bytes:
    """Build deterministic EMSA-PSS bytes, including malformed test variants."""

    width = 384
    message_hash = hashlib.new(message_hash_name, message).digest()
    hash_length = hashlib.new(message_hash_name).digest_size
    padding_length = width - hash_length - len(salt) - 2
    if padding_length < 0:
        raise ValueError("fixture PSS salt is too long")
    data_block = bytes((padding_byte,)) * padding_length + bytes((delimiter,)) + salt
    encoded_hash = hashlib.new(
        message_hash_name, b"\x00" * 8 + message_hash + salt
    ).digest()
    mask = _fixture_mgf(encoded_hash, len(data_block), mgf_hash_name)
    masked_db = bytearray(
        left ^ right for left, right in zip(data_block, mask, strict=True)
    )
    masked_db[0] &= 0x7F
    if force_unused_high_bit:
        # Keep the malformed representative below this fixture modulus so RSA
        # round-trips to the exact EMSA bytes and reaches the high-bit check.
        masked_db[0] = 0x80 | (masked_db[0] & 0x3F)
    return bytes(masked_db) + encoded_hash + bytes((trailer,))


def sign_encoded_message(encoded: bytes) -> str:
    if len(encoded) != 384:
        raise ValueError("fixture encoded message must be exactly 384 bytes")
    signature = pow(
        int.from_bytes(encoded, "big"), TEST_PRIVATE_EXPONENT, TEST_MODULUS
    ).to_bytes(384, "big")
    return _b64url_encode(signature)


def ps256_sign(message: bytes, *, salt: bytes = DEFAULT_PSS_SALT) -> str:
    return sign_encoded_message(pss_encoded_message(message, salt=salt))


def test_policy() -> CollectorTrustPolicy:
    value = {
        "alg": COLLECTOR_SIGNATURE_ALGORITHM,
        "attestation_format": TEST_ATTESTATION_FORMAT,
        "attestation_sha256": TEST_ATTESTATION_SHA256,
        "collector_executable_sha256": COLLECTOR_EXECUTABLE,
        "collector_source_sha256": COLLECTOR_SOURCE,
        "collector_version": COLLECTOR_VERSION,
        "e": TEST_RSA_E,
        "evidence_profile": EVIDENCE_PROFILE,
        "key_version": TEST_KEY_VERSION,
        "kms_algorithm": KMS_SIGNATURE_ALGORITHM,
        "kty": "RSA",
        "n": TEST_RSA_N,
        "protection_level": KMS_PROTECTION_LEVEL,
        "public_key_sha256": TEST_PUBLIC_KEY_SHA256,
        "schema_version": 3,
        "state": "configured",
    }
    data = canonical_json(value) + b"\n"
    return parse_trust_policy_bytes(
        data, expected_sha256=hashlib.sha256(data).hexdigest()
    )


TEST_POLICY = test_policy()


def sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


XCFRAMEWORK_SHA = sha("libbox-xcframework")
XCFRAMEWORK_MANIFEST_SHA = sha("libbox-xcframework-manifest")


def final_artifact_hash_manifest(
    *, signed_tree_sha256: str = SIGNED_TREE
) -> dict[str, Any]:
    """Return the one final-artifact manifest bound by the physical fixture."""

    entries = sorted(
        (
            {
                "path": "artifacts/Clash-for-Mac.app.tree.json",
                "sha256": signed_tree_sha256,
            },
            {"path": "artifacts/app-manifest.json", "sha256": APP_MANIFEST},
            {"path": "artifacts/Clash-for-Mac.dmg", "sha256": sha("dmg")},
            {
                "path": "artifacts/Libbox.xcframework.tree.json",
                "sha256": XCFRAMEWORK_SHA,
            },
            {
                "path": "artifacts/Libbox.xcframework.manifest.json",
                "sha256": XCFRAMEWORK_MANIFEST_SHA,
            },
        ),
        key=lambda item: item["path"],
    )
    return {"entries": entries, "sha256": tree_digest(entries)}


ARTIFACT_HASH_MANIFEST_SHA256 = final_artifact_hash_manifest()["sha256"]


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
    extra_tokens: list[bytes] | None = None,
    start_epoch: int | None = None,
) -> bytes:
    """Build a structurally valid transport capture for v3 packet fixtures."""

    if family not in {"ipv4", "ipv6"}:
        raise ValueError("fixture packet family is invalid")
    local_address = local_address or ("192.0.2.10" if family == "ipv4" else "2001:db8:1::10")
    remote_address = remote_address or (
        "198.51.100.20" if family == "ipv4" else "2001:db8:2::20"
    )
    remote_port = remote_port or (53 if protocol == "dns" else 443)
    epoch = (
        calendar.timegm(datetime(2026, 7, 27, 12, tzinfo=timezone.utc).timetuple())
        if start_epoch is None
        else start_epoch
    )
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
    tokens.extend(extra_tokens or [])
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
    """Materialize one complete same-machine, two-OS aggregate and its bytes."""

    def __init__(
        self,
        root: Path,
        prefix: str = "evidence",
        *,
        signed_tree_sha256: str = SIGNED_TREE,
        artifact_hash_manifest_sha256: str | None = None,
        single_machine: bool = True,
    ) -> None:
        self.root = root.absolute()
        self.prefix = prefix.strip("/")
        self.policy = TEST_POLICY
        manifest_sha256 = (
            final_artifact_hash_manifest(signed_tree_sha256=signed_tree_sha256)[
                "sha256"
            ]
            if artifact_hash_manifest_sha256 is None
            else artifact_hash_manifest_sha256
        )
        self.candidate = {
            "version": "0.4.0",
            "build_number": BUILD_NUMBER,
            "app_manifest_sha256": APP_MANIFEST,
            "signed_app_tree_sha256": signed_tree_sha256,
            "artifact_hash_manifest_sha256": manifest_sha256,
            "built_at": BUILT_AT,
        }
        self.aggregate: dict[str, Any] = {
            "schema_version": AGGREGATE_SCHEMA_VERSION,
            "aggregator_version": AGGREGATOR_VERSION,
            "granted_level": GRANTED_LEVEL,
            "trust_policy_sha256": self.policy.policy_sha256,
            "candidate": self.candidate,
            "runs": [],
        }
        self.report_documents: list[dict[str, dict[str, Any]]] = []
        self.report_bindings: list[list[dict[str, Any]]] = []
        self.raw_bindings: list[list[dict[str, Any]]] = []
        self.machine_sha256 = sha("physical-machine") if single_machine else None
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
            "schema_version": PROOF_SCHEMA_VERSION,
            "run_id": run_id,
            "run_nonce": run_nonce,
            "candidate": {
                key: self.candidate[key]
                for key in (
                    "version",
                    "build_number",
                    "app_manifest_sha256",
                    "signed_app_tree_sha256",
                    "artifact_hash_manifest_sha256",
                )
            },
            "collector": {
                "version": COLLECTOR_VERSION,
                "source_sha256": COLLECTOR_SOURCE,
                "executable_sha256": COLLECTOR_EXECUTABLE,
                "algorithm": COLLECTOR_SIGNATURE_ALGORITHM,
                "key_version": TEST_KEY_VERSION,
            },
        }

    def _packet_report(
        self,
        run_name: str,
        proof: dict[str, Any],
        macos_version: str,
        time_offset: timedelta,
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
                start_epoch=calendar.timegm(
                    (
                        datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
                        + time_offset
                    ).utctimetuple()
                ),
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
                "started_at": self._shifted(CAPTURED_AT, time_offset),
                "completed_at": self._shifted(
                    "2026-07-27T12:00:05Z", time_offset
                ),
                "signed_at": self._shifted(
                    "2026-07-27T12:00:10Z", time_offset
                ),
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
                    "started_at": self._shifted(
                        "2026-07-27T12:00:01Z", time_offset
                    ),
                    "completed_at": self._shifted(
                        "2026-07-27T12:00:02Z", time_offset
                    ),
                    "recorded_at": self._shifted(
                        "2026-07-27T12:00:11Z", time_offset
                    ),
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
                    "hardware_model": "Mac16,1",
                    "clean_install": True,
                },
                "captured_at": self._shifted(CAPTURED_AT, time_offset),
                "completed_at": self._shifted(
                    "2026-07-27T12:00:05Z", time_offset
                ),
                "signed_at": self._shifted(
                    "2026-07-27T15:05:00Z", time_offset
                ),
                "cases": cases,
            },
            bindings,
        )

    @staticmethod
    def _utc(value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    @classmethod
    def _shifted(cls, value: str, offset: timedelta) -> str:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        return cls._utc(parsed + offset)

    def _renderer_ready_evidence(
        self,
        run_name: str,
        proof: dict[str, Any],
        started: datetime,
        finished: datetime,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        executable_sha256 = sha(f"{run_name}-host-executable")
        cdhash = sha(f"{run_name}-host-cdhash")[:40]
        requirement = sha(f"{run_name}-host-requirement")
        common_identity = {
            "team_id": "YKUPL7Z869",
            "signing_identifier": "com.bill.clashformac",
            "executable_sha256": executable_sha256,
            "cdhash": cdhash,
            "designated_requirement_sha256": requirement,
        }
        started_unix_us = (
            calendar.timegm(started.utctimetuple()) * 1_000_000 + started.microsecond
        )
        challenge_sha256 = sha(f"{run_name}-renderer-challenge")
        sequence = (
            ("handoff-parent", "parent-identity-verified"),
            ("handoff-parent", "child-spawned"),
            ("candidate-child", "child-identity-verified"),
            ("candidate-child", "native-ready"),
            ("candidate-child", "renderer-challenge-issued"),
            ("candidate-child", "renderer-ready-v2-published"),
            ("handoff-parent", "renderer-ready-v2-consumed"),
            ("handoff-parent", "parent-exit-committed"),
            ("candidate-child", "parent-absence-proven"),
        )
        trace = {
            "schema_version": 1,
            "proof": copy.deepcopy(proof),
            "protocol": "migration-handoff-renderer-ready-v2",
            "candidate_app_tree_sha256": proof["candidate"]["signed_app_tree_sha256"],
            "window_label": "main",
            "started_at": self._utc(started),
            "completed_at": self._utc(finished),
            "processes": [
                {
                    "role": "handoff-parent",
                    "pid": 4100 if run_name == "run-0" else 4200,
                    "start_unix_us": started_unix_us - 10_000_000,
                    **common_identity,
                },
                {
                    "role": "candidate-child",
                    "pid": 4101 if run_name == "run-0" else 4201,
                    "start_unix_us": started_unix_us + 500_000,
                    **common_identity,
                },
            ],
            "events": [
                {
                    "sequence": index,
                    "offset_ms": index * 1_000,
                    "process_role": role,
                    "event": event,
                    "generation": 1 if index in {4, 5, 6} else None,
                    "challenge_sha256": challenge_sha256 if index in {4, 5, 6} else None,
                }
                for index, (role, event) in enumerate(sequence)
            ],
        }
        artifact = self._write_json(
            f"{run_name}/lifecycle/renderer-ready-v2-trace.json",
            trace,
            "renderer-ready-trace",
        )
        return {"trace_artifact": artifact}, [
            {
                "harness": "lifecycle",
                "subject": "renderer-ready-v2:trace",
                "descriptor": artifact,
            }
        ]

    def _network_extension_evidence(
        self,
        run_name: str,
        probe_id: str,
        proof: dict[str, Any],
        started: datetime,
        finished: datetime,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        states = {
            "network-extension-approval": (
                ("OSSystemExtensionRequest", "request-submitted"),
                ("OSSystemExtensionRequest", "awaiting-user-approval"),
                ("OSSystemExtensionRequest", "extension-activated"),
                ("NEVPNManager", "configuration-enabled"),
            ),
            "network-extension-denial": (
                ("OSSystemExtensionRequest", "request-submitted"),
                ("OSSystemExtensionRequest", "awaiting-user-approval"),
                ("OSSystemExtensionRequest", "user-denied"),
            ),
            "network-extension-pending": (
                ("OSSystemExtensionRequest", "request-submitted"),
                ("OSSystemExtensionRequest", "awaiting-user-approval"),
            ),
        }[probe_id]
        duration_ms = int((finished - started).total_seconds() * 1_000)
        offsets = (
            [0, 1_000]
            if probe_id == "network-extension-pending"
            else [index * 1_000 for index in range(len(states))]
        )
        if probe_id != "network-extension-pending":
            offsets[-1] = duration_ms
        trace = {
            "schema_version": 1,
            "proof": copy.deepcopy(proof),
            "candidate_app_tree_sha256": proof["candidate"]["signed_app_tree_sha256"],
            "probe_id": probe_id,
            "request_id": f"request-{run_name}-{probe_id}",
            "started_at": self._utc(started),
            "completed_at": self._utc(finished),
            "extension_identity": {
                "team_id": "YKUPL7Z869",
                "host_bundle_id": "com.bill.clashformac",
                "provider_bundle_id": "com.bill.clashformac.packet-tunnel",
                "system_extension_wrapper_name": (
                    "com.bill.clashformac.packet-tunnel.systemextension"
                ),
                "executable_sha256": sha(f"{run_name}-packet-tunnel-executable"),
                "cdhash": sha(f"{run_name}-packet-tunnel-cdhash")[:40],
                "designated_requirement_sha256": sha(
                    f"{run_name}-packet-tunnel-requirement"
                ),
            },
            "events": [
                {
                    "sequence": index,
                    "offset_ms": offsets[index],
                    "source": source,
                    "state": state,
                }
                for index, (source, state) in enumerate(states)
            ],
        }
        artifact = self._write_json(
            f"{run_name}/lifecycle/{probe_id}-trace.json",
            trace,
            "network-extension-trace",
        )
        return {"trace_artifact": artifact}, [
            {
                "harness": "lifecycle",
                "subject": f"{probe_id}:trace",
                "descriptor": artifact,
            }
        ]

    def _sleep_wake_evidence(
        self,
        run_name: str,
        proof: dict[str, Any],
        started: datetime,
        finished: datetime,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        pre_sleep = "p" + sha(f"{run_name}-pre-sleep")[:19]
        wake_marker = "w" + sha(f"{run_name}-wake-marker")[:19]
        post_wake = "r" + sha(f"{run_name}-post-wake")[:19]
        window_end = "e" + sha(f"{run_name}-wake-finish")[:19]
        capture = pcap_bytes(
            start_marker=pre_sleep.encode("ascii"),
            token=wake_marker.encode("ascii"),
            end_marker=window_end.encode("ascii"),
            include_token=True,
            extra_tokens=[post_wake.encode("ascii")],
            protocol="tcp",
            family="ipv4",
            local_address="192.0.2.10",
            remote_address="198.51.100.240",
            local_port=41000,
            remote_port=443,
            start_epoch=calendar.timegm(started.utctimetuple()),
        )
        capture_artifact = self._write(
            f"{run_name}/lifecycle/sleep-wake.pcap", capture, "packet-pcap"
        )
        trace = {
            "schema_version": 1,
            "proof": copy.deepcopy(proof),
            "probe_id": "sleep-wake",
            "candidate_app_tree_sha256": proof["candidate"]["signed_app_tree_sha256"],
            "interface": {"name": "utun5", "index": 5, "link_type": 1},
            "endpoints": [
                {
                    "role": "local",
                    "address": "192.0.2.10",
                    "port": 41000,
                    "transport": "tcp",
                },
                {
                    "role": "remote",
                    "address": "198.51.100.240",
                    "port": 443,
                    "transport": "tcp",
                },
            ],
            "capture_command_sha256": sha(f"{run_name}-sleep-capture-command"),
            "pre_sleep_send_command_sha256": sha(f"{run_name}-pre-sleep-command"),
            "post_wake_send_command_sha256": sha(f"{run_name}-post-wake-command"),
            "capture_sha256": capture_artifact["sha256"],
            "pre_sleep_token": pre_sleep,
            "wake_marker_token": wake_marker,
            "post_wake_token": post_wake,
            "window_end_token": window_end,
            "sleep_started_at": self._utc(started + timedelta(milliseconds=500)),
            "wake_observed_at": self._utc(started + timedelta(seconds=1)),
            "started_at": self._utc(started),
            "completed_at": self._utc(finished),
            "observation_ms": 5_000,
            "post_wake_observation_ms": 4_000,
        }
        trace_artifact = self._write_json(
            f"{run_name}/lifecycle/sleep-wake-trace.json",
            trace,
            "sleep-wake-trace",
        )
        return {
            "trace_artifact": trace_artifact,
            "capture_artifact": capture_artifact,
        }, [
            {
                "harness": "lifecycle",
                "subject": "sleep-wake:trace",
                "descriptor": trace_artifact,
            },
            {
                "harness": "lifecycle",
                "subject": "sleep-wake:packet",
                "descriptor": capture_artifact,
            },
        ]

    def _wkwebview_evidence(
        self,
        run_name: str,
        proof: dict[str, Any],
        started: datetime,
        finished: datetime,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        width = 850
        height = 603
        seed = 17 if run_name == "run-0" else 31
        row = b"".join(
            bytes(((column + seed) % 256, (column * 3 + seed) % 256, 96, 255))
            for column in range(width)
        )
        pixels = row * height
        pixels_artifact = self._write(
            f"{run_name}/lifecycle/wkwebview-850x603.rgba",
            pixels,
            "wkwebview-rgba",
        )
        metadata = {
            "schema_version": 1,
            "proof": copy.deepcopy(proof),
            "probe_id": "wkwebview-850x603",
            "candidate_app_tree_sha256": proof["candidate"]["signed_app_tree_sha256"],
            "window_label": "main",
            "view_class": "WKWebView",
            "viewport_width_css_pixels": width,
            "viewport_height_css_pixels": height,
            "backing_scale": 1,
            "pixel_width": width,
            "pixel_height": height,
            "bytes_per_row": width * 4,
            "pixel_format": "rgba8",
            "color_space": "srgb",
            "alpha_mode": "opaque",
            "screenshot_command_sha256": sha(f"{run_name}-wkwebview-command"),
            "pixels_sha256": pixels_artifact["sha256"],
            "captured_at": self._utc(started),
            "completed_at": self._utc(finished),
        }
        metadata_artifact = self._write_json(
            f"{run_name}/lifecycle/wkwebview-850x603-metadata.json",
            metadata,
            "wkwebview-metadata",
        )
        return {
            "metadata_artifact": metadata_artifact,
            "pixels_artifact": pixels_artifact,
        }, [
            {
                "harness": "lifecycle",
                "subject": "wkwebview-850x603:metadata",
                "descriptor": metadata_artifact,
            },
            {
                "harness": "lifecycle",
                "subject": "wkwebview-850x603:pixels",
                "descriptor": pixels_artifact,
            },
        ]

    def _lifecycle_report(
        self,
        run_name: str,
        proof: dict[str, Any],
        machine: str,
        boot_environment: str,
        macos_build: str,
        time_offset: timedelta,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        environment = {
            "machine_sha256": machine,
            "machine_identity_scheme": EVIDENCE_PROFILE["machine_identity_scheme"],
            "hardware_model": "Mac16,1",
            "virtualization_present": False,
            "boot_environment_sha256": boot_environment,
            "boot_environment_scheme": EVIDENCE_PROFILE["boot_environment_scheme"],
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
        finishes: list[datetime] = []
        for index, probe_id in enumerate(sorted(PROBE_SPECS)):
            category, exit_code, observation, checks = PROBE_SPECS[probe_id]
            attributes: dict[str, Any] = {}
            if "user_count" in checks:
                attributes["user_count"] = 2
            if "concurrent_start_count" in checks:
                attributes["concurrent_start_count"] = 2
            started = (
                datetime(2026, 7, 27, 12, index, tzinfo=timezone.utc)
                + time_offset
            )
            duration_seconds = {
                "renderer-ready-v2": 8,
                "network-extension-approval": 3,
                "network-extension-denial": 2,
                "network-extension-pending": 30,
                "sleep-wake": 5,
            }.get(probe_id, 1)
            finished = started + timedelta(seconds=duration_seconds)
            finishes.append(finished)
            evidence: dict[str, Any] | None = None
            evidence_bindings: list[dict[str, Any]] = []
            if probe_id == "renderer-ready-v2":
                evidence, evidence_bindings = self._renderer_ready_evidence(
                    run_name, proof, started, finished
                )
            elif probe_id.startswith("network-extension-"):
                evidence, evidence_bindings = self._network_extension_evidence(
                    run_name, probe_id, proof, started, finished
                )
            elif probe_id == "sleep-wake":
                evidence, evidence_bindings = self._sleep_wake_evidence(
                    run_name, proof, started, finished
                )
            elif probe_id == "wkwebview-850x603":
                evidence, evidence_bindings = self._wkwebview_evidence(
                    run_name, proof, started, finished
                )
            raw = {
                "schema_version": 2,
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
                "evidence": evidence,
            }
            artifact = self._write_json(
                f"{run_name}/lifecycle/{probe_id}.json", raw, "lifecycle-event"
            )
            probes.append({"id": probe_id, "attributes": attributes, "artifact": artifact})
            bindings.append(
                {"harness": "lifecycle", "subject": probe_id, "descriptor": artifact}
            )
            bindings.extend(evidence_bindings)
        completed_at = max(finishes)
        return (
            {
                "schema_version": 3,
                "harness_version": LIFECYCLE_VERSION,
                "proof": copy.deepcopy(proof),
                "environment": environment,
                "captured_at": self._shifted(CAPTURED_AT, time_offset),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "signed_at": self._shifted(
                    "2026-07-27T15:10:00Z", time_offset
                ),
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
        time_offset: timedelta,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        parameters = {
            "machine": {
                "architecture": "arm64",
                "macos_version": macos_version,
                "macos_build": macos_build,
                "hardware_model": "Mac16,1",
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
                        "applied_at": self._shifted(CAPTURED_AT, time_offset),
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
            "captured_at": self._shifted(CAPTURED_AT, time_offset),
            "completed_at": self._shifted(
                PERFORMANCE_COMPLETED_AT, time_offset
            ),
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
                "started_at": self._shifted(CAPTURED_AT, time_offset),
                "ended_at": self._shifted(
                    PERFORMANCE_COMPLETED_AT, time_offset
                ),
                "crash_events": [],
            },
        }
        artifact = self._write_json(
            f"{run_name}/performance/samples.json", raw, "performance-samples"
        )
        report = {
            "schema_version": 2,
            "harness_version": PERFORMANCE_VERSION,
            "captured_at": self._shifted(CAPTURED_AT, time_offset),
            "completed_at": self._shifted(
                PERFORMANCE_COMPLETED_AT, time_offset
            ),
            "signed_at": self._shifted(REPORT_SIGNED_AT, time_offset),
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
            "soak": {"duration_hours": 3.0, "crash_count": 0},
            "samples_artifact": artifact,
        }
        return report, [
            {"harness": "performance", "subject": "measurements", "descriptor": artifact}
        ]

    def _adversarial_report(
        self,
        run_name: str,
        proof: dict[str, Any],
        macos_version: str,
        time_offset: timedelta,
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
                "assessed_at": self._shifted(CAPTURED_AT, time_offset),
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
            started = (
                datetime(2026, 7, 27, 12, 0, offset, tzinfo=timezone.utc)
                + time_offset
            )
            finished = (
                datetime(2026, 7, 27, 12, 0, offset + 1, tzinfo=timezone.utc)
                + time_offset
            )
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
                "captured_at": self._shifted(CAPTURED_AT, time_offset),
                "completed_at": max(transcript_finishes).isoformat().replace(
                    "+00:00", "Z"
                ),
                "signed_at": self._shifted(
                    "2026-07-27T15:15:00Z", time_offset
                ),
                "platform": {
                    "architecture": "arm64",
                    "macos_version": macos_version,
                    "hardware_model": "Mac16,1",
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
        machine = self.machine_sha256 or sha(f"{run_name}-machine")
        boot_environment = sha(f"{run_name}-boot-environment")
        time_offset = RUN_TIMELINE_OFFSET * index
        proof = self._proof(run_id, run_nonce)
        documents: dict[str, dict[str, Any]] = {}
        raw_bindings: list[dict[str, Any]] = []
        documents["packet"], packet_raw = self._packet_report(
            run_name, proof, version, time_offset
        )
        documents["lifecycle"], lifecycle_raw = self._lifecycle_report(
            run_name, proof, machine, boot_environment, build, time_offset
        )
        documents["performance"], performance_raw = self._performance_report(
            run_name, proof, machine, version, build, time_offset
        )
        documents["adversarial"], adversarial_raw = self._adversarial_report(
            run_name, proof, version, time_offset
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
                "captured_at": self._shifted(CAPTURED_AT, time_offset),
                "completed_at": document["completed_at"],
                "signed_at": document["signed_at"],
                "artifact": artifact,
            }
            report_bindings.append(
                {
                    "harness": harness,
                    "tool_version": versions[harness],
                    "captured_at": self._shifted(CAPTURED_AT, time_offset),
                    "completed_at": document["completed_at"],
                    "signed_at": document["signed_at"],
                    "descriptor": artifact,
                }
            )
        collector = {
            "version": COLLECTOR_VERSION,
            "source_sha256": COLLECTOR_SOURCE,
            "executable_sha256": COLLECTOR_EXECUTABLE,
            "key_version": TEST_KEY_VERSION,
            "algorithm": COLLECTOR_SIGNATURE_ALGORITHM,
            "signature": "pending",
        }
        run = {
            "os": os_label,
            "macos_version": version,
            "macos_build": build,
            "machine_sha256": machine,
            "machine_identity_scheme": EVIDENCE_PROFILE["machine_identity_scheme"],
            "hardware_model": "Mac16,1",
            "virtualization_present": False,
            "boot_environment_sha256": boot_environment,
            "boot_environment_scheme": EVIDENCE_PROFILE["boot_environment_scheme"],
            "clean_install": True,
            "captured_at": self._shifted(RUN_CAPTURED_AT, time_offset),
            "completed_at": self._shifted(RUN_COMPLETED_AT, time_offset),
            "signed_at": self._shifted(RUN_SIGNED_AT, time_offset),
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
        collector["signature"] = ps256_sign(canonical_json(payload))
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
        run["collector"]["signature"] = ps256_sign(canonical_json(payload))

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
