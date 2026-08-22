"""Deterministic proof-to-byte fixtures for physical-evidence tests only.

The static RSA-3072 private key below is intentionally committed for tests. It
must never be provisioned as, or accepted in place of, a production KMS key.
"""

from __future__ import annotations

import base64
import calendar
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
from pathlib import Path
import struct
from typing import Any
from unittest.mock import patch

from scripts.harness import adversarial_clients as adversarial_contract
from scripts.harness import packet_evidence as packet_contract
from scripts.harness.adversarial_clients import (
    HARNESS_VERSION as ADVERSARIAL_VERSION,
    REQUIRED_CASES as ADVERSARIAL_CASES,
)
from scripts.harness.lifecycle_matrix import (
    EVENT_DOCUMENT,
    EVENT_SCHEMA_VERSION,
    HARNESS_VERSION as LIFECYCLE_VERSION,
    IDENTITY_FIXED_COMMAND,
    IDENTITY_FIXED_COMMAND_SHA256,
    IDENTITY_OBSERVATION_DOCUMENT,
    IDENTITY_OBSERVATION_SCHEMA_VERSION,
    IDENTITY_PROBE_IDS,
    IDENTITY_VERIFIER_ROLE,
    OBSERVATION_DOCUMENT,
    OBSERVATION_SCHEMA_VERSION,
    PROBE_SPECS,
    lifecycle_probe_command,
)
from scripts.harness.packet_evidence import (
    CASE_STAGE_PLANS,
    HARNESS_VERSION as PACKET_VERSION,
    HOST_SIGNING_IDENTIFIER,
    HOST_TEAM_ID,
    INSTALLED_APP,
    INSTALLED_EXECUTABLE,
    PACKET_ATTEMPT_DOCUMENT,
    PACKET_OWNER,
    PACKET_PROVENANCE_DOCUMENT,
    PACKET_STATE_DOCUMENT,
    PRODUCT_LOG_CATEGORY,
    PRODUCT_LOG_PREDICATE,
    PRODUCT_LOG_SUBSYSTEM,
    PRODUCT_OBSERVATION_DOCUMENT,
    PRODUCT_OBSERVATION_PREFIX,
    DNS_REMOTE_CAPTURE_POLICIES,
    REMOTE_CAPTURE_KNOWN_HOSTS_SHA256,
    REMOTE_CAPTURE_OFFLOAD_CONTEXT,
    REMOTE_CAPTURE_OS_LOGIN_PROFILE_ID,
    REMOTE_CAPTURE_POSIX_USERNAME,
    REMOTE_CAPTURE_SERVICE_ACCOUNT,
    REMOTE_CAPTURE_SUDOERS_POLICY_SHA256,
    REMOTE_TCPDUMP_BINARY_SHA256,
    REQUIRED_CASES as PACKET_CASES,
    TRANSPORT_ENDPOINT_ADDRESSES,
    TRANSPORT_ENDPOINT_IDENTITY_SHA256,
    TUNNEL_CAPTURE_LOCAL_ADDRESSES,
    packet_capture_filter_argv,
)
from scripts.harness.performance_gates import (
    HARNESS_VERSION as PERFORMANCE_VERSION,
    percentiles,
)
from scripts.harness import performance_ledger as performance_contract
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
    load_json_bytes,
    parse_trust_policy_bytes,
    rsa_spki_sha256,
)
from scripts.publication.common import tree_digest
from scripts.tests.performance_evidence_fixture import build_performance_report


APP_MANIFEST = "a" * 64
SIGNED_TREE = "b" * 64
BUILD_NUMBER = "40021"
BUILT_AT = "2026-07-01T00:00:00Z"
CAPTURED_AT = "2026-07-27T12:00:00Z"
PERFORMANCE_COMPLETED_AT = "2026-07-27T15:20:00Z"
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

FIXTURE_LAN_ENDPOINT_ADDRESS = "192.168.50.9"
FIXTURE_LAN_ENDPOINT_IDENTITY_SHA256 = packet_contract.LAN_ENDPOINT_IDENTITY_SHA256


@contextmanager
def fixture_packet_policy():
    """Retain the historical fixture boundary without mutating production pins."""

    yield


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
    stage_local_addresses: tuple[str, str, str] | None = None,
    remote_address: str | None = None,
    local_port: int = 41000,
    stage_local_ports: tuple[int, int, int] | None = None,
    remote_port: int | None = None,
    link_type: int = 1,
    vlan_tags: int = 0,
    include_tcp_fallback: bool = False,
    include_dns_responses: bool = True,
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
        return struct.pack("!HHHHHH", identifier, 0x0000, 1, 0, 0, 0) + qname + struct.pack(
            "!HH", qtype, 1
        )

    def dns_response(label: bytes, identifier: int) -> bytes:
        query = dns_query(label, identifier)
        answer = ipaddress.ip_address(
            "192.0.2.1" if family == "ipv4" else "2001:db8::1"
        ).packed
        return (
            struct.pack("!HHHHHH", identifier, 0x8400, 1, 1, 0, 0)
            + query[12:]
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1 if family == "ipv4" else 28, 1, 0, len(answer))
            + answer
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

    def transport(
        payload: bytes,
        sequence: int,
        identifier: int,
        packet_local_port: int,
        *,
        response: bool = False,
    ) -> bytes:
        if protocol == "tcp":
            return struct.pack(
                "!HHIIBBHHH",
                packet_local_port,
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
            dns_response(payload, identifier)
            if protocol == "dns" and response
            else dns_query(payload, identifier)
            if protocol == "dns"
            else quic_packet(payload)
            if protocol == "quic"
            else payload
        )
        source_port = remote_port if response else packet_local_port
        destination_port = packet_local_port if response else remote_port
        return struct.pack(
            "!HHHH", source_port, destination_port, len(application) + 8, 0
        ) + application

    def network(
        payload: bytes,
        protocol_number: int,
        identifier: int,
        packet_local_address: str,
        *,
        response: bool = False,
    ) -> bytes:
        source = ipaddress.ip_address(
            remote_address if response else packet_local_address
        ).packed
        destination = ipaddress.ip_address(
            packet_local_address if response else remote_address
        ).packed
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

    if stage_local_ports is not None and (
        len(stage_local_ports) != 3
        or len(set(stage_local_ports)) != 3
        or any(not 1 <= port <= 65535 for port in stage_local_ports)
    ):
        raise ValueError("fixture stage ports must be three unique valid ports")
    selected_ports = stage_local_ports or (local_port, local_port, local_port)
    if stage_local_addresses is not None:
        if len(stage_local_addresses) != 3:
            raise ValueError("fixture stage addresses must contain three entries")
        try:
            normalized_addresses = tuple(
                str(ipaddress.ip_address(address)) for address in stage_local_addresses
            )
        except ValueError as error:
            raise ValueError("fixture stage address is invalid") from error
        expected_version = 4 if family == "ipv4" else 6
        if any(
            ipaddress.ip_address(address).version != expected_version
            for address in normalized_addresses
        ):
            raise ValueError("fixture stage address family differs")
        selected_addresses = normalized_addresses
    else:
        selected_addresses = (local_address, local_address, local_address)
    tokens = [(start_marker, selected_ports[0], selected_addresses[0])]
    if include_token:
        tokens.append((token, selected_ports[1], selected_addresses[1]))
    tokens.extend(
        (extra, selected_ports[1], selected_addresses[1])
        for extra in (extra_tokens or [])
    )
    tokens.append((end_marker, selected_ports[2], selected_addresses[2]))
    body = bytearray()
    sequence = 1000
    for packet_index, (
        application,
        packet_local_port,
        packet_local_address,
    ) in enumerate(tokens):
        protocol_number = 6 if protocol == "tcp" else 17
        transport_bytes = transport(
            application,
            sequence,
            packet_index + 1,
            packet_local_port,
        )
        frame = link_frame(
            network(
                transport_bytes,
                protocol_number,
                packet_index + 1,
                packet_local_address,
            )
        )
        timestamp = epoch + (5 if packet_index == len(tokens) - 1 else packet_index)
        body.extend(struct.pack("<IIII", timestamp, 0, len(frame), len(frame)))
        body.extend(frame)
        if protocol == "dns" and include_dns_responses:
            response_transport = transport(
                application,
                sequence,
                packet_index + 1,
                packet_local_port,
                response=True,
            )
            response_frame = link_frame(
                network(
                    response_transport,
                    protocol_number,
                    packet_index + 1,
                    packet_local_address,
                    response=True,
                )
            )
            body.extend(
                struct.pack(
                    "<IIII",
                    timestamp,
                    100_000,
                    len(response_frame),
                    len(response_frame),
                )
            )
            body.extend(response_frame)
        sequence += len(application)
    if include_tcp_fallback:
        tcp_header = struct.pack(
            "!HHIIBBHHH", local_port, remote_port, sequence, 0, 5 << 4, 0x18, 65535, 0, 0
        )
        frame = link_frame(
            network(tcp_header + b"fallback", 6, 99, local_address)
        )
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
        def command_receipt(
            role: str,
            argv: list[str],
            started_at: str,
            completed_at: str,
            *,
            stdout: str = "",
            stderr: str = "",
            binary_stdout: bytes | None = None,
        ) -> dict[str, Any]:
            started = datetime.fromisoformat(started_at[:-1] + "+00:00")
            completed = datetime.fromisoformat(completed_at[:-1] + "+00:00")
            stdout_bytes = (
                stdout.encode("utf-8") if binary_stdout is None else binary_stdout
            )
            stderr_bytes = stderr.encode("utf-8")
            return {
                "role": role,
                "argv": argv,
                "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_ms": int((completed - started).total_seconds() * 1_000),
                "exit_code": 0,
                "stdout_size": len(stdout_bytes),
                "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
                "stdout": stdout if binary_stdout is None else None,
                "stderr_size": len(stderr_bytes),
                "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
                "stderr": stderr,
            }

        def ios_command_receipt(
            role: str,
            seed: str,
            started_at: str = "2026-07-27T11:59:50.000Z",
            completed_at: str = "2026-07-27T11:59:50.010Z",
        ) -> dict[str, Any]:
            started_text = shifted(started_at)
            completed_text = shifted(completed_at)
            started = datetime.fromisoformat(started_text[:-1] + "+00:00")
            completed = datetime.fromisoformat(completed_text[:-1] + "+00:00")
            empty_sha256 = hashlib.sha256(b"").hexdigest()
            return {
                "role": role,
                "argv_sha256": sha(f"{run_name}-{seed}-argv"),
                "started_at": started_text,
                "completed_at": completed_text,
                "duration_ms": int((completed - started).total_seconds() * 1_000),
                "exit_code": 0,
                "stdout_size": 0,
                "stdout_sha256": empty_sha256,
                "stderr_size": 0,
                "stderr_sha256": empty_sha256,
            }

        def ios_copy_receipt(role: str, seed: str) -> dict[str, Any]:
            return {
                "command": ios_command_receipt(role, f"{seed}-command"),
                "envelope_sha256": sha(f"{run_name}-{seed}-envelope"),
                "receipt_sha256": sha(f"{run_name}-{seed}-receipt"),
                "receipt_size": 512,
            }

        def shifted(value: str) -> str:
            return self._shifted(value, time_offset)

        def product_state_artifact(
            *,
            case_id: str,
            state: dict[str, Any],
            sequence: int,
            recorded_at: str,
            restored: bool,
        ) -> dict[str, Any]:
            recorded = datetime.fromisoformat(
                shifted(recorded_at)[:-1] + "+00:00"
            )
            timestamp = self._utc(recorded)
            event = {
                "schema_version": 1,
                "document": PRODUCT_OBSERVATION_DOCUMENT,
                "component": "host",
                "event": "engine_snapshot",
                "sequence": sequence,
                "recorded_unix_ms": int(recorded.timestamp() * 1_000),
                "process": {
                    "pid": 4_242,
                    "start_unix_ms": int(
                        (
                            datetime(2026, 7, 27, 11, tzinfo=timezone.utc)
                            + time_offset
                        ).timestamp()
                        * 1_000
                    ),
                },
                "candidate": {
                    "version": proof["candidate"]["version"],
                    "build_number": proof["candidate"]["build_number"],
                },
                "payload": {"state": copy.deepcopy(state)},
            }
            log_entry = {
                "timestamp": timestamp,
                "processImagePath": INSTALLED_EXECUTABLE,
                "processID": 4_242,
                "subsystem": PRODUCT_LOG_SUBSYSTEM,
                "category": PRODUCT_LOG_CATEGORY,
                "eventMessage": (
                    PRODUCT_OBSERVATION_PREFIX
                    + canonical_json(event).decode("utf-8")
                ),
            }
            query_start = self._utc(recorded - timedelta(seconds=1))
            query_end = self._utc(recorded + timedelta(milliseconds=150))
            query = command_receipt(
                "product-observation-log",
                [
                    "/usr/bin/log",
                    "show",
                    "--style",
                    "ndjson",
                    "--info",
                    "--timezone",
                    "UTC",
                    "--start",
                    query_start,
                    "--end",
                    query_end,
                    "--predicate",
                    PRODUCT_LOG_PREDICATE,
                ],
                self._utc(recorded + timedelta(milliseconds=50)),
                query_end,
                stdout=canonical_json(log_entry).decode("utf-8") + "\n",
            )
            cdhash = sha(f"{run_name}-installed-host-cdhash")[:40]
            codesign = command_receipt(
                "product-observation-codesign",
                ["/usr/bin/codesign", "-d", "--verbose=4", INSTALLED_APP],
                self._utc(recorded + timedelta(milliseconds=160)),
                self._utc(recorded + timedelta(milliseconds=250)),
                stderr=(
                    f"Executable={INSTALLED_EXECUTABLE}\n"
                    f"Identifier={HOST_SIGNING_IDENTIFIER}\n"
                    f"CDHash={cdhash}\n"
                    f"TeamIdentifier={HOST_TEAM_ID}\n"
                ),
            )
            observation = {
                "schema_version": 1,
                "document": PACKET_STATE_DOCUMENT,
                "case_id": case_id,
                "log_entry": log_entry,
                "query_command": query,
                "codesign_command": codesign,
                "signing_identity": {
                    "executable": INSTALLED_EXECUTABLE,
                    "team_id": HOST_TEAM_ID,
                    "signing_identifier": HOST_SIGNING_IDENTIFIER,
                    "cdhash": cdhash,
                },
                "event": event,
            }
            suffix = "restore-state" if restored else "product-state"
            return self._write_json(
                f"{run_name}/packet/{case_id}-{suffix}.json",
                observation,
                "packet-product-state-observation",
            )

        def remote_argv(
            *,
            policy: dict[str, str],
            key_path: str,
            known_hosts_path: str,
            command: str,
        ) -> list[str]:
            return [
                "/opt/homebrew/bin/gcloud",
                "--verbosity=error",
                "--quiet",
                "compute",
                "ssh",
                f"{REMOTE_CAPTURE_POSIX_USERNAME}@{policy['instance_name']}",
                "--zone",
                policy["zone"],
                "--project",
                policy["project"],
                "--tunnel-through-iap",
                (
                    "--impersonate-service-account="
                    f"{REMOTE_CAPTURE_SERVICE_ACCOUNT}"
                ),
                f"--ssh-key-file={key_path}",
                "--plain",
                f"--command={command}",
                "--",
                "-T",
                "-F",
                "/dev/null",
                "-i",
                key_path,
                "-o",
                "CheckHostIP=no",
                "-o",
                "HashKnownHosts=no",
                "-o",
                f"HostKeyAlias=compute.{policy['instance_id']}",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={known_hosts_path}",
                "-o",
                "BatchMode=yes",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "PermitLocalCommand=no",
                "-o",
                "ForwardAgent=no",
                "-o",
                "ForwardX11=no",
                "-o",
                "ConnectTimeout=15",
                "-o",
                "ConnectionAttempts=1",
                "-o",
                "ServerAliveInterval=10",
                "-o",
                "ServerAliveCountMax=2",
                "-o",
                "ProxyUseFdpass=no",
            ]

        cases: list[dict[str, Any]] = []
        bindings: list[dict[str, Any]] = []
        transition_cases = {"stop-cleanup", "ipv6-disabled-absence"}
        stage_names = ("start", "target", "end")
        stage_ports = (51_000, 51_001, 51_002)
        stage_send_times = {
            "start": ("2026-07-27T11:59:59.900Z", "2026-07-27T12:00:00.200Z"),
            "target": ("2026-07-27T12:00:00.900Z", "2026-07-27T12:00:01.200Z"),
            "end": ("2026-07-27T12:00:04.900Z", "2026-07-27T12:00:05.200Z"),
        }
        for index, (case_id, spec) in enumerate(PACKET_CASES.items()):
            tokens = (
                "s" + sha(f"{run_name}-{case_id}-start")[:19],
                "t" + sha(f"{run_name}-{case_id}-target")[:19],
                "e" + sha(f"{run_name}-{case_id}-finish")[:19],
            )
            if spec.protocol == "dns":
                endpoint_policy = DNS_REMOTE_CAPTURE_POLICIES[spec.resolver_role]
                remote_address = endpoint_policy[spec.family]
                endpoint_identity_sha256 = endpoint_policy["identity_sha256"]
                remote_port = 53
            elif case_id == "lan-bypass":
                endpoint_policy = None
                remote_address = FIXTURE_LAN_ENDPOINT_ADDRESS
                endpoint_identity_sha256 = FIXTURE_LAN_ENDPOINT_IDENTITY_SHA256
                remote_port = 44_333
            else:
                endpoint_policy = None
                remote_address = TRANSPORT_ENDPOINT_ADDRESSES[spec.family]
                endpoint_identity_sha256 = TRANSPORT_ENDPOINT_IDENTITY_SHA256
                remote_port = 44_333

            test_sequence = index * 3 + 2
            baseline_state = {
                "config_digest": sha(f"{run_name}-{case_id}-baseline-config"),
                "desired_mode": "tunnel",
                "generation": 5,
                "ipv6_enabled": True,
                "owner": PACKET_OWNER,
                "phase": "tunnel_active",
                "ready": True,
            }
            test_state = {
                "config_digest": (
                    None
                    if spec.expected_mode == "off"
                    else sha(f"{run_name}-{case_id}-product-config")
                ),
                "desired_mode": spec.expected_mode,
                "generation": 7,
                "ipv6_enabled": spec.expected_ipv6_enabled,
                "owner": None if spec.expected_mode == "off" else PACKET_OWNER,
                "phase": spec.expected_phase,
                "ready": spec.expected_mode != "off",
            }
            restore_state = {**baseline_state, "generation": 9}
            state_recorded_at = (
                "2026-07-27T12:00:00.300Z"
                if case_id in transition_cases
                else "2026-07-27T11:59:58.500Z"
            )
            state_artifact = product_state_artifact(
                case_id=case_id,
                state=test_state,
                sequence=test_sequence,
                recorded_at=state_recorded_at,
                restored=False,
            )
            restore_state_artifact = None
            if not spec.token_observed:
                restore_state_artifact = product_state_artifact(
                    case_id=case_id,
                    state=restore_state,
                    sequence=test_sequence + 1,
                    recorded_at="2026-07-27T12:00:04.000Z",
                    restored=True,
                )

            stage_addresses: list[str] = []
            stage_interfaces: list[dict[str, Any]] = []
            stage_interface_stdout: list[str] = []
            for stage_name in stage_names:
                direct = (
                    case_id in {"lan-bypass", "excluded-routes"}
                    or case_id in transition_cases
                    and stage_name == "target"
                )
                if spec.protocol == "dns":
                    local_address = (
                        "192.0.2.10"
                        if spec.family == "ipv4"
                        else "2001:db8:1::10"
                    )
                elif direct:
                    local_address = (
                        "192.168.50.10"
                        if case_id == "lan-bypass"
                        else "192.0.2.10"
                        if spec.family == "ipv4"
                        else "2001:db8:1::10"
                    )
                else:
                    local_address = TUNNEL_CAPTURE_LOCAL_ADDRESSES[spec.family]
                stage_addresses.append(local_address)
                if direct:
                    interface_name = "en1" if case_id == "lan-bypass" else "en0"
                    link_type = 1
                    flags = [
                        "UP",
                        "BROADCAST",
                        "RUNNING",
                        "SIMPLEX",
                        "MULTICAST",
                    ]
                else:
                    interface_name = "utun5"
                    link_type = 0
                    flags = ["UP", "POINTOPOINT", "RUNNING", "MULTICAST"]
                stage_interfaces.append(
                    {
                        "name": interface_name,
                        "index": 5,
                        "link_type": link_type,
                        "flags": flags,
                    }
                )
                address_keyword = "inet" if spec.family == "ipv4" else "inet6"
                stage_interface_stdout.append(
                    (
                        f"{interface_name}: flags=8051<{','.join(flags)}> "
                        "mtu 1500 index 5\n"
                        f"\t{address_keyword} {local_address} netmask 0xffffffff\n"
                        "\tstatus: active\n"
                    )
                )

            capture = pcap_bytes(
                start_marker=tokens[0].encode("ascii"),
                token=tokens[1].encode("ascii"),
                end_marker=tokens[2].encode("ascii"),
                include_token=spec.token_observed,
                protocol=spec.protocol,
                family=spec.family,
                local_address=stage_addresses[0],
                stage_local_addresses=tuple(stage_addresses),
                remote_address=remote_address,
                local_port=stage_ports[0],
                stage_local_ports=stage_ports,
                remote_port=remote_port,
                link_type=1 if spec.protocol == "dns" else 101,
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
            with fixture_packet_policy():
                capture_filter = list(
                    packet_capture_filter_argv(
                        case_id=case_id,
                        tokens=tokens,
                        lan_endpoint_address=(
                            FIXTURE_LAN_ENDPOINT_ADDRESS
                            if case_id == "lan-bypass"
                            else None
                        ),
                    )
                )

            remote_key_generation_command = None
            remote_public_key_command = None
            remote_key_import_command = None
            remote_interface = None
            remote_interface_command = None
            remote_access = None
            capture_offload_context = None
            if spec.protocol == "dns":
                if endpoint_policy is None:  # pragma: no cover - fixed matrix
                    raise AssertionError("DNS fixture endpoint policy is unavailable")
                known_hosts_path = (
                    "/fixture/repository/scripts/physical_capture/packet_known_hosts"
                )
                key_path = (
                    "/fixture/session-scratch/runtime/packet-remote-capture/"
                    "packet-capture-rsa3072"
                )
                private_key = (
                    b"-----BEGIN PRIVATE KEY-----\n"
                    b"fixture-rsa3072-private-key\n"
                    b"-----END PRIVATE KEY-----\n"
                )
                public_key = (
                    "ssh-rsa "
                    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n"
                )
                remote_key_generation_command = command_receipt(
                    "packet-remote-key-generate",
                    [
                        "/usr/bin/openssl",
                        "genpkey",
                        "-algorithm",
                        "RSA",
                        "-pkeyopt",
                        "rsa_keygen_bits:3072",
                    ],
                    shifted("2026-07-27T11:59:55.000Z"),
                    shifted("2026-07-27T11:59:55.200Z"),
                    stderr="....+\n",
                    binary_stdout=private_key,
                )
                remote_public_key_command = command_receipt(
                    "packet-remote-public-key",
                    ["/usr/bin/ssh-keygen", "-y", "-f", key_path],
                    shifted("2026-07-27T11:59:55.200Z"),
                    shifted("2026-07-27T11:59:55.400Z"),
                    stdout=public_key,
                )
                remote_key_import_command = command_receipt(
                    "packet-remote-key-import",
                    [
                        "/opt/homebrew/bin/gcloud",
                        "--verbosity=error",
                        "--quiet",
                        "compute",
                        "os-login",
                        "ssh-keys",
                        "add",
                        "--project",
                        endpoint_policy["project"],
                        (
                            "--impersonate-service-account="
                            f"{REMOTE_CAPTURE_SERVICE_ACCOUNT}"
                        ),
                        f"--key-file={key_path}.pub",
                        "--ttl=2m",
                        "--format=value(loginProfile.name)",
                    ],
                    shifted("2026-07-27T11:59:55.400Z"),
                    shifted("2026-07-27T11:59:55.600Z"),
                    stdout=f"{REMOTE_CAPTURE_OS_LOGIN_PROFILE_ID}\n",
                )
                remote_interface = {
                    "name": endpoint_policy["interface"],
                    "index": 2,
                    "link_type": 1,
                    "flags": ["UP", "BROADCAST", "RUNNING", "MULTICAST"],
                }
                remote_interface_command = command_receipt(
                    "packet-interface-observation",
                    remote_argv(
                        policy=endpoint_policy,
                        key_path=key_path,
                        known_hosts_path=known_hosts_path,
                        command=(
                            f"/sbin/ifconfig -v {endpoint_policy['interface']}"
                        ),
                    ),
                    shifted("2026-07-27T11:59:55.600Z"),
                    shifted("2026-07-27T11:59:55.800Z"),
                    stdout=(
                        f"{endpoint_policy['interface']}: "
                        "flags=1043<UP,BROADCAST,RUNNING,MULTICAST> "
                        "mtu 1460 index 2\n"
                        "        inet 10.42.40.3 netmask 255.255.255.255\n"
                    ),
                )
                capture_text = (
                    f"sudo -n /usr/bin/tcpdump -i "
                    f"{endpoint_policy['interface']} -n -U -s 0 "
                    "-c 6 -w - udp and port 53"
                )
                capture_command = command_receipt(
                    "packet-remote-capture",
                    remote_argv(
                        policy=endpoint_policy,
                        key_path=key_path,
                        known_hosts_path=known_hosts_path,
                        command=capture_text,
                    ),
                    shifted("2026-07-27T11:59:55.900Z"),
                    shifted("2026-07-27T12:00:05.300Z"),
                    stderr=(
                        f"tcpdump: listening on {endpoint_policy['interface']}, "
                        "link-type EN10MB (Ethernet), "
                        "snapshot length 262144 bytes\n"
                        "6 packets captured\n"
                        "6 packets received by filter\n"
                        "0 packets dropped by kernel\n"
                    ),
                    binary_stdout=capture,
                )
                remote_access = {
                    "project": endpoint_policy["project"],
                    "zone": endpoint_policy["zone"],
                    "instance_name": endpoint_policy["instance_name"],
                    "instance_id": endpoint_policy["instance_id"],
                    "internal_ip_address": endpoint_policy["internal_ip"],
                    "host_alias": f"compute.{endpoint_policy['instance_id']}",
                    "host_key_bytes_sha256": endpoint_policy[
                        "host_key_bytes_sha256"
                    ],
                    "service_account": REMOTE_CAPTURE_SERVICE_ACCOUNT,
                    "service_account_unique_id": REMOTE_CAPTURE_OS_LOGIN_PROFILE_ID,
                    "posix_username": REMOTE_CAPTURE_POSIX_USERNAME,
                    "os_login_profile_id": REMOTE_CAPTURE_OS_LOGIN_PROFILE_ID,
                    "known_hosts_snapshot_path": known_hosts_path,
                    "known_hosts_snapshot_sha256": (
                        REMOTE_CAPTURE_KNOWN_HOSTS_SHA256
                    ),
                    "ssh_key_file_path": key_path,
                    "ssh_key_file_path_sha256": hashlib.sha256(
                        key_path.encode("utf-8")
                    ).hexdigest(),
                    "gcloud_path": "/opt/homebrew/bin/gcloud",
                    "sudoers_policy_sha256": (
                        REMOTE_CAPTURE_SUDOERS_POLICY_SHA256
                    ),
                    "tcpdump_binary_sha256": REMOTE_TCPDUMP_BINARY_SHA256,
                    "private_key_size": len(private_key),
                    "private_key_sha256": hashlib.sha256(private_key).hexdigest(),
                    "public_key_sha256": hashlib.sha256(
                        public_key.encode("ascii")
                    ).hexdigest(),
                }
                capture_offload_context = REMOTE_CAPTURE_OFFLOAD_CONTEXT
                capture_device = {
                    "name": endpoint_policy["interface"],
                    "link_type": 1,
                    "scope": "exact-remote-interface",
                }
            else:
                count = 3 if spec.token_observed else 2
                capture_command = command_receipt(
                    "packet-capture",
                    [
                        "/usr/sbin/tcpdump",
                        "-i",
                        "pktap,all",
                        "-y",
                        "RAW",
                        "-n",
                        "-U",
                        "-s",
                        "0",
                        "-c",
                        str(count),
                        "-w",
                        "-",
                        *capture_filter,
                    ],
                    shifted("2026-07-27T11:59:55.900Z"),
                    shifted("2026-07-27T12:00:05.300Z"),
                    stderr=(
                        "tcpdump: listening on pktap,all, link-type RAW "
                        "(Raw IP), snapshot length 262144 bytes\n"
                        f"{count} packets captured\n"
                        f"{count} packets received by filter\n"
                        "0 packets dropped by kernel\n"
                    ),
                    binary_stdout=capture,
                )
                capture_device = {
                    "name": "pktap,all",
                    "link_type": 101,
                    "scope": "all-interfaces-source-filtered-raw",
                }

            attempt_stages: list[dict[str, Any]] = []
            for stage_index, stage_name in enumerate(stage_names):
                interface = stage_interfaces[stage_index]
                if (
                    case_id in transition_cases
                    and stage_name == "target"
                ):
                    route_times = (
                        "2026-07-27T12:00:00.600Z",
                        "2026-07-27T12:00:00.700Z",
                    )
                    interface_times = (
                        "2026-07-27T12:00:00.700Z",
                        "2026-07-27T12:00:00.800Z",
                    )
                    send_times = (
                        "2026-07-27T12:00:00.900Z",
                        "2026-07-27T12:00:03.900Z",
                    )
                else:
                    route_times = {
                        "start": (
                            "2026-07-27T11:59:59.000Z",
                            "2026-07-27T11:59:59.100Z",
                        ),
                        "target": (
                            "2026-07-27T12:00:00.300Z",
                            "2026-07-27T12:00:00.400Z",
                        ),
                        "end": (
                            "2026-07-27T12:00:04.300Z",
                            "2026-07-27T12:00:04.400Z",
                        ),
                    }[stage_name]
                    interface_times = {
                        "start": (
                            "2026-07-27T11:59:59.100Z",
                            "2026-07-27T11:59:59.200Z",
                        ),
                        "target": (
                            "2026-07-27T12:00:00.400Z",
                            "2026-07-27T12:00:00.500Z",
                        ),
                        "end": (
                            "2026-07-27T12:00:04.400Z",
                            "2026-07-27T12:00:04.500Z",
                        ),
                    }[stage_name]
                    send_times = stage_send_times[stage_name]
                route_command = command_receipt(
                    "packet-route-observation",
                    ["/sbin/route", "-n", "get", remote_address],
                    shifted(route_times[0]),
                    shifted(route_times[1]),
                    stdout=(
                        f"   route to: {remote_address}\n"
                        f" interface: {interface['name']}\n"
                    ),
                )
                interface_command = command_receipt(
                    "packet-send-interface-observation",
                    ["/sbin/ifconfig", "-v", interface["name"]],
                    shifted(interface_times[0]),
                    shifted(interface_times[1]),
                    stdout=stage_interface_stdout[stage_index],
                )
                token_text = tokens[stage_index]
                endpoint_set = [
                    {
                        "role": "local",
                        "address": stage_addresses[stage_index],
                        "port": stage_ports[stage_index],
                        "transport": (
                            "tcp" if spec.protocol == "tcp" else "udp"
                        ),
                    },
                    {
                        "role": "remote",
                        "address": remote_address,
                        "port": remote_port,
                        "transport": (
                            "tcp" if spec.protocol == "tcp" else "udp"
                        ),
                    },
                ]
                sender_argv = [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    "-B",
                    (
                        "/fixture/repository/scripts/physical_capture/"
                        "packet_sender.py"
                    ),
                    "--case",
                    case_id,
                    "--stage",
                    stage_name,
                    "--protocol",
                    spec.protocol,
                    "--family",
                    spec.family,
                    "--resolver-role",
                    spec.resolver_role,
                ]
                if spec.protocol != "dns":
                    sender_argv.extend(
                        [
                            "--local-address",
                            stage_addresses[stage_index],
                            "--local-port",
                            "0",
                            "--remote-address",
                            remote_address,
                            "--remote-port",
                            str(remote_port),
                        ]
                    )
                absence_ms = (
                    "3000"
                    if case_id in transition_cases and stage_name == "target"
                    else "0"
                )
                sender_argv.extend(
                    [
                        "--token",
                        token_text,
                        "--quic-version",
                        str(1 if spec.protocol == "quic" else 0),
                        "--absence-window-ms",
                        absence_ms,
                    ]
                )
                dns_result = None
                if spec.protocol == "dns":
                    dns_result = {
                        "trigger": "getaddrinfo",
                        "resolver_role": spec.resolver_role,
                        "requested_type": (
                            "A" if spec.family == "ipv4" else "AAAA"
                        ),
                        "query": {
                            "name": f"{token_text}.evidence.test",
                            "token_sha256": hashlib.sha256(
                                token_text.encode("ascii")
                            ).hexdigest(),
                            "addresses": [
                                (
                                    "192.0.2.1"
                                    if spec.family == "ipv4"
                                    else "2001:db8::1"
                                )
                            ],
                        },
                    }
                send_result = {
                    "schema_version": 2,
                    "document": "cfw-packet-send-stage-result-v2",
                    "case_id": case_id,
                    "stage": stage_name,
                    "local_address": (
                        None
                        if spec.protocol == "dns"
                        else stage_addresses[stage_index]
                    ),
                    "local_port": (
                        None if spec.protocol == "dns" else stage_ports[stage_index]
                    ),
                    "remote_address": (
                        None if spec.protocol == "dns" else remote_address
                    ),
                    "remote_port": (
                        None if spec.protocol == "dns" else remote_port
                    ),
                    "transport": (
                        "resolver"
                        if spec.protocol == "dns"
                        else "tcp"
                        if spec.protocol == "tcp"
                        else "udp"
                    ),
                    "token_sha256": hashlib.sha256(
                        token_text.encode("ascii")
                    ).hexdigest(),
                    "bytes_submitted": len(token_text.encode("ascii")),
                    "dns_result": dns_result,
                }
                send_command = command_receipt(
                    f"packet-send-{spec.protocol}-{stage_name}",
                    sender_argv,
                    shifted(send_times[0]),
                    shifted(send_times[1]),
                    stdout=canonical_json(send_result).decode("utf-8") + "\n",
                )
                attempt_stages.append(
                    {
                        "stage": stage_name,
                        "host_stage": CASE_STAGE_PLANS[case_id][stage_index],
                        "token_sha256": hashlib.sha256(
                            token_text.encode("ascii")
                        ).hexdigest(),
                        "endpoint_set": endpoint_set,
                        "route_command": route_command,
                        "interface_command": interface_command,
                        "interface": interface,
                        "command": send_command,
                    }
                )

            if case_id == "lan-bypass":
                ios_session_id = sha(f"{run_name}-{case_id}-ios-session")
                ios_process_id = 5_544
                server_bindings = [
                    {
                        "stage": stage["stage"],
                        "token_sha256": stage["token_sha256"],
                        "local_address": stage["endpoint_set"][0]["address"],
                        "local_port": stage["endpoint_set"][0]["port"],
                        "remote_address": stage["endpoint_set"][1]["address"],
                        "remote_port": stage["endpoint_set"][1]["port"],
                        "bytes_received": 20,
                        "eof_observed": True,
                    }
                    for stage in attempt_stages
                ]
                artifact_validation = {
                    "profile_decode": ios_command_receipt(
                        "ios-peer-profile-decode", "profile-decode"
                    ),
                    "keychain_certificate": ios_command_receipt(
                        "ios-peer-keychain-certificate", "keychain-certificate"
                    ),
                    "signature_verify": ios_command_receipt(
                        "ios-peer-codesign-verify", "codesign-verify"
                    ),
                    "signature_details": ios_command_receipt(
                        "ios-peer-codesign-details", "codesign-details"
                    ),
                    "signature_entitlements": ios_command_receipt(
                        "ios-peer-codesign-entitlements", "codesign-entitlements"
                    ),
                    "architectures": ios_command_receipt(
                        "ios-peer-executable-architectures", "architectures"
                    ),
                    "build_version": ios_command_receipt(
                        "ios-peer-executable-build-version", "build-version"
                    ),
                    "cdhash": "a" * 40,
                    "profile_uuid": packet_contract.IOS_LAN_PROFILE_UUID,
                }
                primer_cleanup = {
                    "process_inventory": ios_command_receipt(
                        "ios-peer-process-inventory", "primer-cleanup-processes"
                    ),
                    "process_inventory_sha256": sha(
                        f"{run_name}-primer-cleanup-processes"
                    ),
                    "primer_copy": ios_copy_receipt(
                        "ios-peer-primer-result-copy", "primer-cleanup-copy"
                    ),
                    "terminate_command": ios_command_receipt(
                        "ios-peer-primer-terminate", "primer-terminate"
                    ),
                    "terminate_receipt_sha256": sha(
                        f"{run_name}-primer-terminate-receipt"
                    ),
                    "process_id": 5_543,
                    "post_terminate_process_inventory": ios_command_receipt(
                        "ios-peer-process-inventory", "primer-stopped-processes"
                    ),
                    "post_terminate_process_inventory_sha256": sha(
                        f"{run_name}-primer-stopped-processes"
                    ),
                }
                admission = {
                    "schema_version": 1,
                    "document": "cfm-ios-packet-lan-peer-admission-v1",
                    "evidence_role": "server_observation_only",
                    "claim_eligible": False,
                    "source_identity_sha256": (
                        packet_contract.LAN_ENDPOINT_IDENTITY_SHA256
                    ),
                    "source_identity_file_sha256": (
                        packet_contract.LAN_ENDPOINT_IDENTITY_FILE_SHA256
                    ),
                    "device": {
                        "core_device_identifier_sha256": (
                            packet_contract.IOS_LAN_CORE_DEVICE_SHA256
                        ),
                        "provisioning_udid_sha256": (
                            packet_contract.IOS_LAN_PROVISIONING_UDID_SHA256
                        ),
                        "product_type": "iPhone17,1",
                        "os_version": "26.5",
                        "os_build": "23F77",
                        "inventory_connection_state": "disconnected",
                        "inventory_preparedness_state": None,
                        "device_list_receipt_sha256": sha(
                            f"{run_name}-ios-device-list"
                        ),
                        "device_list_command": ios_command_receipt(
                            "ios-peer-device-list", "device-list"
                        ),
                        "device_details_receipt_sha256": sha(
                            f"{run_name}-ios-device-details"
                        ),
                        "device_details_command": ios_command_receipt(
                            "ios-peer-device-details", "device-details"
                        ),
                        "lock_receipt_sha256": sha(f"{run_name}-ios-lock"),
                        "lock_command": ios_command_receipt(
                            "ios-peer-lock-state", "lock-state"
                        ),
                    },
                    "artifact": {
                        "app_tree_sha256": packet_contract.IOS_LAN_APP_TREE_SHA256,
                        "executable_sha256": (
                            packet_contract.IOS_LAN_EXECUTABLE_SHA256
                        ),
                        "source_tree_sha256": (
                            packet_contract.IOS_LAN_SOURCE_TREE_SHA256
                        ),
                        "profile_sha256": packet_contract.IOS_LAN_PROFILE_SHA256,
                        "entitlements_sha256": (
                            packet_contract.IOS_LAN_ENTITLEMENTS_SHA256
                        ),
                        "signing_certificate_sha256": (
                            packet_contract.IOS_LAN_SIGNING_CERTIFICATE_SHA256
                        ),
                        "validation": artifact_validation,
                    },
                    "preflight": {
                        "app_inventory_sha256": sha(
                            f"{run_name}-ios-preflight-apps"
                        ),
                        "process_inventory_sha256": sha(
                            f"{run_name}-ios-preflight-processes"
                        ),
                        "app_inventory_command": ios_command_receipt(
                            "ios-peer-app-inventory", "preflight-apps"
                        ),
                        "process_inventory_command": ios_command_receipt(
                            "ios-peer-process-inventory", "preflight-processes"
                        ),
                        "app_absent": True,
                        "process_absent": True,
                    },
                    "installation": {
                        "install_intent_sha256": sha(
                            f"{run_name}-ios-install-intent"
                        ),
                        "install_receipt_sha256": sha(
                            f"{run_name}-ios-install-receipt"
                        ),
                        "post_install_app_inventory_sha256": sha(
                            f"{run_name}-ios-installed-apps"
                        ),
                        "install_command": ios_command_receipt(
                            "ios-peer-install", "install"
                        ),
                        "post_install_app_inventory_command": ios_command_receipt(
                            "ios-peer-app-inventory", "installed-apps"
                        ),
                    },
                    "primer": {
                        "pre_launch_lock_receipt_sha256": sha(
                            f"{run_name}-ios-primer-pre-launch-lock"
                        ),
                        "pre_launch_lock_command": ios_command_receipt(
                            "ios-peer-lock-state", "primer-pre-launch-lock"
                        ),
                        "launch_receipt_sha256": sha(
                            f"{run_name}-ios-primer-launch"
                        ),
                        "launch_command": ios_command_receipt(
                            "ios-peer-primer-launch", "primer-launch"
                        ),
                        "process_inventory_sha256": sha(
                            f"{run_name}-ios-primer-processes"
                        ),
                        "process_inventory_command": ios_command_receipt(
                            "ios-peer-process-inventory", "primer-processes"
                        ),
                        "receipt_copy": ios_copy_receipt(
                            "ios-peer-primer-result-copy", "primer-result-copy"
                        ),
                        "cleanup": primer_cleanup,
                    },
                    "session": {
                        "session_id": ios_session_id,
                        "session_sha256": sha(f"{run_name}-ios-session-document"),
                        "copy_receipt_sha256": sha(
                            f"{run_name}-ios-session-copy-receipt"
                        ),
                        "copy_command": ios_command_receipt(
                            "ios-peer-packet-lan-session-copy", "session-copy"
                        ),
                    },
                    "process": {
                        "pre_launch_lock_receipt_sha256": sha(
                            f"{run_name}-ios-packet-pre-launch-lock"
                        ),
                        "pre_launch_lock_command": ios_command_receipt(
                            "ios-peer-lock-state", "packet-pre-launch-lock"
                        ),
                        "process_id": ios_process_id,
                        "launch_receipt_sha256": sha(
                            f"{run_name}-ios-packet-launch"
                        ),
                        "launch_command": ios_command_receipt(
                            "ios-peer-packet-lan-launch", "packet-launch"
                        ),
                        "process_inventory_sha256": sha(
                            f"{run_name}-ios-packet-processes"
                        ),
                        "process_inventory_command": ios_command_receipt(
                            "ios-peer-process-inventory", "packet-processes"
                        ),
                        "ready_copy": ios_copy_receipt(
                            "ios-peer-packet-lan-ready-copy", "packet-ready-copy"
                        ),
                    },
                    "network": {
                        "interface_name": "en0",
                        "ipv4": FIXTURE_LAN_ENDPOINT_ADDRESS,
                    },
                    "listener": {"port": 44_333, "transport": "tcp4"},
                    "admitted_at": shifted("2026-07-27T11:59:58.000Z"),
                }
                before_capture = {
                    "schema_version": 1,
                    "document": "cfm-ios-packet-lan-peer-before-capture-v1",
                    "claim_eligible": False,
                    "session_id": ios_session_id,
                    "process_id": ios_process_id,
                    "peer_ipv4": FIXTURE_LAN_ENDPOINT_ADDRESS,
                    "listener_port": 44_333,
                    "process_inventory": ios_command_receipt(
                        "ios-peer-process-inventory", "before-capture-processes"
                    ),
                    "process_inventory_sha256": sha(
                        f"{run_name}-ios-before-capture-processes"
                    ),
                    "ready_copy": ios_copy_receipt(
                        "ios-peer-packet-lan-ready-copy", "before-ready-copy"
                    ),
                    "observed_at": shifted("2026-07-27T11:59:58.500Z"),
                }
                after_capture = {
                    "schema_version": 1,
                    "document": "cfm-ios-packet-lan-peer-after-capture-v1",
                    "claim_eligible": False,
                    "session_id": ios_session_id,
                    "process_id": ios_process_id,
                    "peer_ipv4": FIXTURE_LAN_ENDPOINT_ADDRESS,
                    "listener_port": 44_333,
                    "result_copy": ios_copy_receipt(
                        "ios-peer-packet-lan-result-copy", "packet-result-copy"
                    ),
                    "result_sha256": sha(f"{run_name}-ios-packet-result"),
                    "result_status": "closed",
                    "sender_server_bindings": server_bindings,
                    "process_inventory": ios_command_receipt(
                        "ios-peer-process-inventory", "after-capture-processes"
                    ),
                    "process_inventory_sha256": sha(
                        f"{run_name}-ios-after-capture-processes"
                    ),
                    "ready_copy": ios_copy_receipt(
                        "ios-peer-packet-lan-ready-copy", "after-ready-copy"
                    ),
                    "observed_at": shifted("2026-07-27T12:00:05.400Z"),
                }
                termination = {
                    "process_inventory": ios_command_receipt(
                        "ios-peer-process-inventory", "cleanup-processes"
                    ),
                    "process_inventory_sha256": sha(
                        f"{run_name}-ios-cleanup-processes"
                    ),
                    "ready_copy": ios_copy_receipt(
                        "ios-peer-packet-lan-ready-copy", "cleanup-ready-copy"
                    ),
                    "terminate_command": ios_command_receipt(
                        "ios-peer-terminate", "packet-terminate"
                    ),
                    "terminate_receipt_sha256": sha(
                        f"{run_name}-ios-packet-terminate"
                    ),
                    "process_id": ios_process_id,
                    "post_terminate_process_inventory": ios_command_receipt(
                        "ios-peer-process-inventory", "packet-stopped-processes"
                    ),
                    "post_terminate_process_inventory_sha256": sha(
                        f"{run_name}-ios-packet-stopped-processes"
                    ),
                }
                uninstall = {
                    "uninstall_command": ios_command_receipt(
                        "ios-peer-uninstall", "uninstall"
                    ),
                    "uninstall_receipt_sha256": sha(
                        f"{run_name}-ios-uninstall"
                    ),
                    "final_app_inventory": ios_command_receipt(
                        "ios-peer-app-inventory", "final-apps"
                    ),
                    "final_app_inventory_sha256": sha(
                        f"{run_name}-ios-final-apps"
                    ),
                    "final_process_inventory": ios_command_receipt(
                        "ios-peer-process-inventory", "final-processes"
                    ),
                    "final_process_inventory_sha256": sha(
                        f"{run_name}-ios-final-processes"
                    ),
                    "app_absent": True,
                    "process_absent": True,
                }
                cleanup = {
                    "schema_version": 1,
                    "document": "cfm-ios-packet-lan-peer-cleanup-v1",
                    "claim_eligible": False,
                    "outcome": "capture-complete",
                    "capture_state": "capture-validated",
                    "session_id": ios_session_id,
                    "process_id": ios_process_id,
                    "termination": termination,
                    "uninstall": uninstall,
                }
                remote_access = {
                    "schema_version": 1,
                    "document": "cfm-ios-packet-lan-peer-provenance-v1",
                    "evidence_role": "server_observation_only",
                    "claim_eligible": False,
                    "source_identity_sha256": (
                        packet_contract.LAN_ENDPOINT_IDENTITY_SHA256
                    ),
                    "source_identity_file_sha256": (
                        packet_contract.LAN_ENDPOINT_IDENTITY_FILE_SHA256
                    ),
                    "runtime_endpoint_source": (
                        "cfm-ios-packet-lan-peer-ready-v1"
                    ),
                    "network": {
                        "interface_name": "en0",
                        "ipv4": FIXTURE_LAN_ENDPOINT_ADDRESS,
                        "listener_port": 44_333,
                        "transport": "tcp4",
                    },
                    "admission": admission,
                    "before_capture": before_capture,
                    "after_capture": after_capture,
                    "cleanup": cleanup,
                }
                capture_offload_context = (
                    "ios-coredevice-localnetwork-packet-peer-v1"
                )

            provenance = {
                "schema_version": 4,
                "document": PACKET_PROVENANCE_DOCUMENT,
                "case_id": case_id,
                "state_observation_sha256": state_artifact["sha256"],
                "capture_artifact_sha256": artifact["sha256"],
                "endpoint_identity_sha256": endpoint_identity_sha256,
                "capture_device": capture_device,
                "capture_point": spec.vantage,
                "resolver_role": spec.resolver_role,
                "capture_filter_argv": capture_filter,
                "capture_filter_sha256": hashlib.sha256(
                    canonical_json(capture_filter)
                ).hexdigest(),
                "remote_key_generation_command": (
                    remote_key_generation_command
                ),
                "remote_public_key_command": remote_public_key_command,
                "remote_key_import_command": remote_key_import_command,
                "remote_interface": remote_interface,
                "remote_interface_command": remote_interface_command,
                "capture_command": capture_command,
                "capture_alive_at": shifted("2026-07-27T11:59:58.000Z"),
                "started_at": shifted(
                    "2026-07-27T12:00:00.100Z"
                    if spec.protocol == "dns"
                    else "2026-07-27T12:00:00.000Z"
                ),
                "completed_at": shifted(
                    "2026-07-27T12:00:05.100Z"
                    if spec.protocol == "dns"
                    else "2026-07-27T12:00:05.000Z"
                ),
                "quic_version": 1 if spec.protocol == "quic" else None,
                "remote_access": remote_access,
                "capture_offload_context": capture_offload_context,
                "host_transaction": {
                    "session_id": sha(f"{run_name}-{case_id}-host-session"),
                    "baseline": baseline_state,
                    "baseline_observation_sequence": test_sequence - 1,
                    "test": test_state,
                    "test_observation_sequence": test_sequence,
                    "restore": restore_state,
                    "restore_observation_sequence": test_sequence + 1,
                    "candidate_observation_sequence": test_sequence,
                },
            }
            provenance_artifact = self._write_json(
                f"{run_name}/packet/{case_id}-provenance.json",
                provenance,
                "packet-capture-provenance",
            )
            attempt = {
                "schema_version": 4,
                "document": PACKET_ATTEMPT_DOCUMENT,
                "case_id": case_id,
                "state_observation_sha256": state_artifact["sha256"],
                "capture_provenance_sha256": provenance_artifact["sha256"],
                "stages": attempt_stages,
                "recorded_at": shifted("2026-07-27T12:00:06.000Z"),
                "absence_window_completed_at": (
                    None
                    if spec.token_observed
                    else attempt_stages[1]["command"]["completed_at"]
                ),
            }
            attempt_artifact = self._write_json(
                f"{run_name}/packet/{case_id}-send-attempt.json",
                attempt,
                "packet-send-attempt",
            )
            send_digest = hashlib.sha256(
                canonical_json(
                    [
                        stage["command"]["argv_sha256"]
                        for stage in attempt_stages
                    ]
                )
            ).hexdigest()
            cases.append(
                {
                    "id": case_id,
                    "protocol": spec.protocol,
                    "family": spec.family,
                    "resolver_role": spec.resolver_role,
                    "vantage": spec.vantage,
                    "token": tokens[1],
                    "window_start_token": tokens[0],
                    "window_end_token": tokens[2],
                    "token_observed": spec.token_observed,
                    "observation_ms": 5_000,
                    "quic_version": 1 if spec.protocol == "quic" else None,
                    "capture_filter_sha256": provenance[
                        "capture_filter_sha256"
                    ],
                    "capture_command_sha256": capture_command["argv_sha256"],
                    "send_command_sha256": send_digest,
                    "artifact": artifact,
                    "state_artifact": state_artifact,
                    "restore_state_artifact": restore_state_artifact,
                    "provenance_artifact": provenance_artifact,
                    "attempt_artifact": attempt_artifact,
                }
            )
            for subject, descriptor_value in (
                (case_id, artifact),
                (f"{case_id}:product-state", state_artifact),
                (f"{case_id}:capture-provenance", provenance_artifact),
                (f"{case_id}:send-attempt", attempt_artifact),
            ):
                bindings.append(
                    {
                        "harness": "packet",
                        "subject": subject,
                        "descriptor": descriptor_value,
                    }
                )
            if restore_state_artifact is not None:
                bindings.append(
                    {
                        "harness": "packet",
                        "subject": f"{case_id}:restore-state",
                        "descriptor": restore_state_artifact,
                    }
                )
        return (
            {
                "schema_version": 4,
                "harness_version": PACKET_VERSION,
                "proof": copy.deepcopy(proof),
                "platform": {
                    "architecture": "arm64",
                    "macos_version": macos_version,
                    "hardware_model": "Mac16,1",
                    "clean_install": True,
                },
                "captured_at": shifted("2026-07-27T12:00:00.000Z"),
                "completed_at": shifted("2026-07-27T12:00:06.000Z"),
                "signed_at": shifted("2026-07-27T15:05:00.000Z"),
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
        identity_started = datetime(
            2026, 7, 27, 12, 0, tzinfo=timezone.utc
        ) + time_offset
        identity_finished = identity_started + timedelta(seconds=1)
        identity_app = (
            "/fixture/repository/"
            "target/candidates/0.4.0/signed/Clash for Mac.app"
        )
        identity_stdout = (
            f"release app verified: {identity_app}\n"
            "identity: YKUPL7Z869 / com.bill.clashformac / "
            "com.bill.clashformac.packet-tunnel / "
            "com.bill.clashformac.proxy-agent\n"
            "platform: arm64 / macOS 15.0+\n"
            "build number: 40021\n"
        )
        identity_stderr = (
            f"{identity_app}: valid on disk\n"
            f"{identity_app}: satisfies its Designated Requirement\n"
        )
        identity_command = {
            "role": IDENTITY_VERIFIER_ROLE,
            "command": list(IDENTITY_FIXED_COMMAND),
            "command_sha256": IDENTITY_FIXED_COMMAND_SHA256,
            "exit_code": 0,
            "duration_ms": 1000,
            "stdout_sha256": hashlib.sha256(
                identity_stdout.encode("utf-8")
            ).hexdigest(),
            "stderr_sha256": hashlib.sha256(
                identity_stderr.encode("utf-8")
            ).hexdigest(),
            "stdout": identity_stdout,
            "stderr": identity_stderr,
        }
        identity_started_at = identity_started.isoformat().replace("+00:00", "Z")
        identity_finished_at = identity_finished.isoformat().replace("+00:00", "Z")
        identity_batch_material = {
            "schema_version": IDENTITY_OBSERVATION_SCHEMA_VERSION,
            "document": IDENTITY_OBSERVATION_DOCUMENT,
            "candidate": {
                **copy.deepcopy(proof["candidate"]),
                "built_at": self.candidate["built_at"],
            },
            "run_id": proof["run_id"],
            "environment": copy.deepcopy(environment),
            "command": copy.deepcopy(identity_command),
            "started_at": identity_started_at,
            "finished_at": identity_finished_at,
        }
        identity_batch_sha256 = hashlib.sha256(
            canonical_json(identity_batch_material)
        ).hexdigest()
        for index, probe_id in enumerate(sorted(PROBE_SPECS)):
            category, exit_code, terminal_observation, checks = PROBE_SPECS[probe_id]
            attributes: dict[str, Any] = {}
            if "user_count" in checks:
                attributes["user_count"] = 2
            if "concurrent_start_count" in checks:
                attributes["concurrent_start_count"] = 2
            started = (
                identity_started
                if probe_id in IDENTITY_PROBE_IDS
                else datetime(2026, 7, 27, 12, index, tzinfo=timezone.utc)
                + time_offset
            )
            duration_seconds = {
                "renderer-ready-v2": 8,
                "network-extension-approval": 3,
                "network-extension-denial": 2,
                "network-extension-pending": 30,
                "sleep-wake": 5,
            }.get(probe_id, 1)
            finished = (
                identity_finished
                if probe_id in IDENTITY_PROBE_IDS
                else started + timedelta(seconds=duration_seconds)
            )
            finishes.append(finished)
            evidence: dict[str, Any] | None = None
            evidence_bindings: list[dict[str, Any]] = []
            if probe_id in IDENTITY_PROBE_IDS:
                observation = {
                    **copy.deepcopy(identity_batch_material),
                    "batch_sha256": identity_batch_sha256,
                    "probe_id": probe_id,
                }
            elif probe_id == "renderer-ready-v2":
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
            if probe_id not in IDENTITY_PROBE_IDS:
                observation = {
                    "schema_version": OBSERVATION_SCHEMA_VERSION,
                    "document": OBSERVATION_DOCUMENT,
                    "candidate": {
                        **copy.deepcopy(proof["candidate"]),
                        "built_at": self.candidate["built_at"],
                    },
                    "run_id": proof["run_id"],
                    "environment": copy.deepcopy(environment),
                    "probe_id": probe_id,
                    "category": category,
                    "command": lifecycle_probe_command(probe_id),
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
                            "observation": terminal_observation,
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
            observation_artifact = self._write_json(
                f"{run_name}/lifecycle/observations/{probe_id}.json",
                observation,
                "lifecycle-observation",
            )
            event = {
                "schema_version": EVENT_SCHEMA_VERSION,
                "document": EVENT_DOCUMENT,
                "proof": copy.deepcopy(proof),
                "probe_id": probe_id,
                "observation_artifact": observation_artifact,
            }
            event_artifact = self._write_json(
                f"{run_name}/lifecycle/events/{probe_id}.json",
                event,
                "lifecycle-event",
            )
            probes.append(
                {"id": probe_id, "attributes": attributes, "artifact": event_artifact}
            )
            bindings.append(
                {
                    "harness": "lifecycle",
                    "subject": f"{probe_id}:observation",
                    "descriptor": observation_artifact,
                }
            )
            bindings.append(
                {
                    "harness": "lifecycle",
                    "subject": probe_id,
                    "descriptor": event_artifact,
                }
            )
            bindings.extend(evidence_bindings)
        completed_at = max(finishes)
        return (
            {
                "schema_version": 4,
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
        boot_environment: str,
        os_label: str,
        macos_version: str,
        macos_build: str,
        time_offset: timedelta,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        return build_performance_report(
            write_json=self._write_json,
            run_name=run_name,
            proof=proof,
            candidate=self.candidate,
            machine=machine,
            boot_environment=boot_environment,
            os_label=os_label,
            macos_version=macos_version,
            macos_build=macos_build,
            started_at=self._shifted(CAPTURED_AT, time_offset),
            signed_at=self._shifted(REPORT_SIGNED_AT, time_offset),
        )

    def _adversarial_report(
        self,
        run_name: str,
        proof: dict[str, Any],
        macos_version: str,
        time_offset: timedelta,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        bindings: list[dict[str, Any]] = []
        transcript_finishes: list[datetime] = []
        coverage_entries: list[dict[str, Any]] = []
        transcript_artifacts: dict[str, dict[str, Any]] = {}
        common_canary = sha(f"{run_name}-secret-canary")
        baseline_client_requirement = sha(f"{run_name}-baseline-client-requirement")
        baseline_client_entitlements = sha(f"{run_name}-baseline-client-entitlements")
        base_time = datetime(2026, 7, 27, 12, 1, tzinfo=timezone.utc) + time_offset

        for index, case_id in enumerate(adversarial_contract.all_subject_ids()):
            spec = adversarial_contract.case_spec(case_id)
            started = base_time + timedelta(seconds=index * 3)
            finished = started + timedelta(seconds=1)
            assessed = started - timedelta(seconds=1)
            transcript_finishes.append(finished)
            started_at = started.isoformat().replace("+00:00", "Z")
            finished_at = finished.isoformat().replace("+00:00", "Z")
            assessed_at = assessed.isoformat().replace("+00:00", "Z")
            client_pid = 20_000 + index
            server_pid = 700
            client_euid = 0 if case_id == "wrong-uid" else 501
            client_audit = 200_002 if case_id == "wrong-audit-session" else 100_001
            client_team = "" if case_id == "wrong-team-id" else adversarial_contract.PRODUCT_TEAM_ID
            client_signing = (
                f"com.bill.clashformac.variant.{index}"
                if case_id in {"wrong-bundle-identifier", "same-team-unknown-bundle"}
                else adversarial_contract.PRODUCT_HOST_SIGNING_ID
            )
            client_requirement = (
                sha(f"{run_name}-{case_id}-client-requirement")
                if case_id
                in {
                    "wrong-team-id",
                    "wrong-bundle-identifier",
                    "wrong-designated-requirement",
                    "same-team-unknown-bundle",
                }
                else baseline_client_requirement
            )
            client_entitlements = (
                sha(f"{run_name}-{case_id}-client-entitlements")
                if case_id == "wrong-entitlement"
                else baseline_client_entitlements
            )
            conditions = adversarial_contract.expected_identity_conditions(case_id)
            client_signature = {
                "schema_version": 1,
                "document": adversarial_contract.SIGNATURE_DOCUMENT,
                "case_id": case_id,
                "kind": "client",
                "process": {"pid": client_pid, "start_unix_ms": 1_800_000_000_000 + index},
                "process_image_path": f"/fixture/adversarial/{case_id}/CFWAdversarialProbe",
                "binary_sha256": sha(f"{run_name}-{case_id}-client-binary"),
                "cdhash": sha(f"{run_name}-{case_id}-client-cdhash")[:40],
                "team_id": client_team,
                "signing_id": client_signing,
                "designated_requirement_sha256": client_requirement,
                "entitlements_sha256": client_entitlements,
                "conditions": conditions,
                "codesign_command_sha256": sha(f"{run_name}-{case_id}-client-command"),
                "codesign_output_sha256": sha(f"{run_name}-{case_id}-client-output"),
                "exit_code": 0,
                "assessed_at": assessed_at,
            }
            server_signature = {
                "schema_version": 1,
                "document": adversarial_contract.SIGNATURE_DOCUMENT,
                "case_id": case_id,
                "kind": "server",
                "process": {"pid": server_pid, "start_unix_ms": 1_799_999_000_000},
                "process_image_path": adversarial_contract.AUTHORITY_PROCESS_IMAGE_PATH,
                "binary_sha256": sha(f"{run_name}-authority-binary"),
                "cdhash": sha(f"{run_name}-authority-cdhash")[:40],
                "team_id": adversarial_contract.PRODUCT_TEAM_ID,
                "signing_id": adversarial_contract.AUTHORITY_SIGNING_ID,
                "designated_requirement_sha256": sha(f"{run_name}-authority-requirement"),
                "entitlements_sha256": sha(f"{run_name}-authority-entitlements"),
                "conditions": adversarial_contract.expected_identity_conditions("baseline"),
                "codesign_command_sha256": sha(f"{run_name}-authority-command"),
                "codesign_output_sha256": sha(f"{run_name}-authority-output"),
                "exit_code": 0,
                "assessed_at": assessed_at,
            }
            client_signature_artifact = self._write_json(
                f"{run_name}/adversarial/signatures/client-{case_id}.json",
                client_signature,
                "adversarial-signature-observation",
            )
            server_signature_artifact = self._write_json(
                f"{run_name}/adversarial/signatures/server-{case_id}.json",
                server_signature,
                "adversarial-signature-observation",
            )

            request_sha256 = sha(f"{run_name}-{case_id}-raw-request")
            pre_state = sha(f"{run_name}-{case_id}-pre-state")
            post_state = (
                sha(f"{run_name}-{case_id}-post-state")
                if spec.state_relation == "changed"
                else pre_state
            )
            boundary_record: dict[str, Any] = {}
            server_record: dict[str, Any] = {}
            if spec.decision_source.startswith("authority_"):
                if spec.decision_source == "authority_journal":
                    payload: dict[str, Any] = {
                        "journal_input_sha256": request_sha256,
                        "actual_code": spec.actual_code,
                        "pre_state_sha256": pre_state,
                        "post_state_sha256": post_state,
                        "cleanup_state": spec.cleanup_state,
                    }
                else:
                    connection_accepted = spec.accepted or spec.decision_source in {
                        "authority_operation",
                        "authority_liveness",
                    }
                    connection_identity = None
                    if connection_accepted:
                        identity_material = b"host" + struct.pack(
                            ">III", client_pid, client_euid, client_audit
                        )
                        connection_identity = hashlib.sha256(identity_material).hexdigest()
                    payload = {
                        "role": "host",
                        "peer_pid": client_pid,
                        "euid": client_euid,
                        "audit_session_id": client_audit,
                        "connection_identity_sha256": connection_identity,
                        "accepted": spec.accepted,
                        "actual_code": spec.actual_code,
                        "pre_state_sha256": pre_state,
                        "post_state_sha256": post_state,
                        "cleanup_state": spec.cleanup_state,
                    }
                    if spec.decision_source != "authority_peer":
                        payload["request_sha256"] = request_sha256
                event = {
                    "schema_version": 1,
                    "document": adversarial_contract.PRODUCT_OBSERVATION_DOCUMENT,
                    "component": adversarial_contract.PRODUCT_OBSERVATION_COMPONENT,
                    "event": spec.event,
                    "sequence": index + 1,
                    "recorded_unix_ms": round((started + timedelta(milliseconds=500)).timestamp() * 1000),
                    "process": server_signature["process"],
                    "candidate": {
                        "version": proof["candidate"]["version"],
                        "build_number": proof["candidate"]["build_number"],
                    },
                    "payload": payload,
                }
                server_record = {
                    "log": {
                        "event_type": "logEvent",
                        "message_type": "Info",
                        "subsystem": adversarial_contract.PRODUCT_OBSERVATION_SUBSYSTEM,
                        "category": adversarial_contract.PRODUCT_OBSERVATION_CATEGORY,
                        "process_image_path": adversarial_contract.AUTHORITY_PROCESS_IMAGE_PATH,
                        "process_id": server_pid,
                        "boot_uuid": "A1B2C3D4-1111-2222-3333-444455556666",
                        "timestamp": finished_at,
                        "event_message_sha256": hashlib.sha256(
                            adversarial_contract.PRODUCT_OBSERVATION_PREFIX.encode("utf-8")
                            + canonical_json(event)
                        ).hexdigest(),
                    },
                    "event": event,
                }
            else:
                if spec.decision_source == "xpc_requirement":
                    evidence: dict[str, Any] = {
                        "listener_requirement_sha256": adversarial_contract.HOST_REQUIREMENT_SHA256,
                        "codesign_assessment_sha256": sha(
                            f"{run_name}-{case_id}-requirement-assessment"
                        ),
                        "codesign_exit_code": 3,
                        "connection_outcome": "invalidated_before_export",
                        "transport_error_code": "global_authority_interrupted",
                        "accepted_event_count": 0,
                        "search_predicate_sha256": adversarial_contract.LOG_PREDICATE_SHA256,
                    }
                    document = adversarial_contract.XPC_REQUIREMENT_DOCUMENT
                elif spec.decision_source == "identity_freshness":
                    evidence = {
                        "captured_pid": client_pid,
                        "captured_start_unix_ms": 1_700_000_000_000,
                        "current_pid": client_pid,
                        "current_start_unix_ms": 1_800_000_000_000,
                        "captured_audit_session_id": 100_001,
                        "current_audit_session_id": (
                            100_001 if case_id == "stale-pid-evidence" else 200_002
                        ),
                    }
                    document = adversarial_contract.IDENTITY_FRESHNESS_DOCUMENT
                else:
                    evidence = {
                        "coverage_subject": f"secret-coverage:{case_id}",
                        "enumeration_complete": True,
                    }
                    document = adversarial_contract.SECRET_DECISION_DOCUMENT
                boundary_record = {
                    "schema_version": 1,
                    "document": document,
                    "case_id": case_id,
                    "source": spec.decision_source,
                    "request_sha256": request_sha256,
                    "actual_code": spec.actual_code,
                    "accepted": spec.accepted,
                    "pre_state_sha256": pre_state,
                    "post_state_sha256": post_state,
                    "cleanup_state": spec.cleanup_state,
                    "evidence": evidence,
                }

            coverage: dict[str, Any] | None = None
            coverage_artifact: dict[str, Any] | None = None
            if spec.secret_surface is not None:
                location = sha(f"{run_name}-{case_id}-coverage-location")
                coverage = {
                    "schema_version": 1,
                    "document": adversarial_contract.COVERAGE_DOCUMENT,
                    "case_id": case_id,
                    "surface": spec.secret_surface,
                    "canary_sha256": common_canary,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "enumeration_complete": True,
                    "unreadable_count": 0,
                    "excluded_count": 0,
                    "entry_count": 1,
                    "total_scanned_bytes": 128,
                    "total_match_count": 0,
                    "entries": [
                        {
                            "location_sha256": location,
                            "content_sha256": sha(f"{run_name}-{case_id}-coverage-content"),
                            "scanned_bytes": 128,
                            "match_count": 0,
                        }
                    ],
                }
                coverage_artifact = self._write_json(
                    f"{run_name}/adversarial/coverage/{case_id}.json",
                    coverage,
                    "adversarial-secret-coverage",
                )
                coverage_entries.append(
                    {"case_id": case_id, "descriptor": coverage_artifact}
                )

            reset_digest = sha(f"{run_name}-{case_id}-reset-state")
            observation = {
                "schema_version": 1,
                "document": adversarial_contract.OBSERVATION_DOCUMENT,
                "case_id": case_id,
                "category": spec.category,
                "role": spec.role,
                "precondition": spec.precondition,
                "request_sha256": request_sha256,
                "command": {
                    "role": "adversarial-probe",
                    "argv_sha256": sha(f"{run_name}-{case_id}-argv"),
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "duration_ms": 1000,
                    "exit_code": 0,
                },
                "client_runtime": {
                    "process": client_signature["process"],
                    "euid": client_euid,
                    "audit_session_id": client_audit,
                },
                "client_signature_subject": f"client-signature:{case_id}",
                "server_signature_subject": f"server-signature:{case_id}",
                "secret_coverage_subject": (
                    f"secret-coverage:{case_id}" if spec.secret_surface is not None else ""
                ),
                "server_record": server_record,
                "boundary_record": boundary_record,
                "isolation": {
                    "mode": spec.isolation_mode,
                    "reset_required": spec.reset_required,
                    "reset_performed": spec.reset_required,
                    "reset_verified": spec.reset_required,
                    "contamination_detected": False,
                    "pre_reset_state_sha256": reset_digest if spec.reset_required else "",
                    "post_reset_state_sha256": reset_digest if spec.reset_required else "",
                },
            }
            observation_artifact = self._write_json(
                f"{run_name}/adversarial/observations/{case_id}.json",
                observation,
                "adversarial-case-observation",
            )
            transcript_value = adversarial_contract.build_adversarial_transcript(
                case_id=case_id,
                proof=proof,
                observation_artifact=observation_artifact,
                observation=observation,
                client_signature_artifact=client_signature_artifact,
                client_signature=client_signature,
                server_signature_artifact=server_signature_artifact,
                server_signature=server_signature,
                secret_coverage_artifact=coverage_artifact,
                secret_coverage=coverage,
            )
            transcript_artifact = self._write_json(
                f"{run_name}/adversarial/transcripts/{case_id}.json",
                transcript_value,
                "adversarial-transcript",
            )
            transcript_artifacts[case_id] = transcript_artifact
            for subject, descriptor in (
                (case_id, transcript_artifact),
                (f"observation:{case_id}", observation_artifact),
                (f"client-signature:{case_id}", client_signature_artifact),
                (f"server-signature:{case_id}", server_signature_artifact),
            ):
                bindings.append(
                    {"harness": "adversarial", "subject": subject, "descriptor": descriptor}
                )
            if coverage_artifact is not None:
                bindings.append(
                    {
                        "harness": "adversarial",
                        "subject": f"secret-coverage:{case_id}",
                        "descriptor": coverage_artifact,
                    }
                )

        baseline_spec = adversarial_contract.BASELINE_SPEC
        cases: list[dict[str, Any]] = []
        for case_id in sorted(ADVERSARIAL_CASES):
            spec = adversarial_contract.case_spec(case_id)
            cases.append(
                {
                    "id": case_id,
                    "category": spec.category,
                    "role": spec.role,
                    "precondition": spec.precondition,
                    "event": spec.event,
                    "artifact": transcript_artifacts[case_id],
                }
            )
        return (
            {
                "schema_version": 3,
                "harness_version": ADVERSARIAL_VERSION,
                "proof": copy.deepcopy(proof),
                "captured_at": base_time.isoformat().replace("+00:00", "Z"),
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
                "secret_coverage_manifest_sha256": hashlib.sha256(
                    canonical_json(sorted(coverage_entries, key=lambda item: item["case_id"]))
                ).hexdigest(),
                "baseline": {
                    "id": "baseline",
                    "category": baseline_spec.category,
                    "role": baseline_spec.role,
                    "precondition": baseline_spec.precondition,
                    "event": baseline_spec.event,
                    "artifact": transcript_artifacts["baseline"],
                },
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
            run_name,
            proof,
            machine,
            boot_environment,
            os_label,
            version,
            build,
            time_offset,
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
                "captured_at": document["captured_at"],
                "completed_at": document["completed_at"],
                "signed_at": document["signed_at"],
                "artifact": artifact,
            }
            report_bindings.append(
                {
                    "harness": harness,
                    "tool_version": versions[harness],
                    "captured_at": document["captured_at"],
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

    def rebind_candidate_built_at(self, built_at: str) -> None:
        """Keep valid identity observation bytes when testing an outer time mismatch."""

        if not isinstance(built_at, str) or not built_at.endswith("Z"):
            raise ValueError("fixture built_at must be a UTC timestamp")
        try:
            parsed = datetime.fromisoformat(built_at[:-1] + "+00:00")
        except ValueError as error:
            raise ValueError("fixture built_at must be ISO-8601") from error
        if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError("fixture built_at must use UTC")

        self.candidate["built_at"] = built_at
        for run_index, documents in enumerate(self.report_documents):
            lifecycle = documents["lifecycle"]
            lifecycle_bindings = {
                binding["subject"]: binding["descriptor"]
                for binding in self.raw_bindings[run_index]
                if binding["harness"] == "lifecycle"
            }
            for probe in lifecycle["probes"]:
                if probe["id"] not in IDENTITY_PROBE_IDS:
                    continue
                event_descriptor = lifecycle_bindings[probe["id"]]
                probe["artifact"] = event_descriptor
                event = load_json_bytes(
                    (self.root / event_descriptor["path"]).read_bytes(),
                    f"fixture identity event {probe['id']}",
                )
                observation_descriptor = lifecycle_bindings[
                    f"{probe['id']}:observation"
                ]
                # Lifecycle event v4 binds its source observation through the
                # sole top-level descriptor. Rebinding candidate time changes
                # the observation digest, so the event must follow that exact
                # edge rather than the removed legacy evidence wrapper.
                event["observation_artifact"] = observation_descriptor
                observation = load_json_bytes(
                    (self.root / observation_descriptor["path"]).read_bytes(),
                    f"fixture identity observation {probe['id']}",
                )
                observation["candidate"]["built_at"] = built_at
                batch_material = {
                    key: copy.deepcopy(observation[key])
                    for key in (
                        "schema_version",
                        "document",
                        "candidate",
                        "run_id",
                        "environment",
                        "command",
                        "started_at",
                        "finished_at",
                    )
                }
                observation["batch_sha256"] = hashlib.sha256(
                    canonical_json(batch_material)
                ).hexdigest()
                self.rewrite_json(observation_descriptor, observation)
                self.rewrite_json(event_descriptor, event)
            self.resign_run(run_index)

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
