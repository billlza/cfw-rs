"""Pre-nonce Packet observations from product and fixed macOS commands.

The product state source is closed: the adapter reads only the signed Host's
Apple Unified Log event, verifies the installed Host code identity, and stores
the exact raw command output.  It never accepts a caller-authored state object.

The 13-case network endpoint/vantage policy is intentionally fail-closed until
reviewed endpoints and the independent DNS capture channel are source-pinned.
Command constructors for route/interface/tcpdump/send are kept here so that
enabling that policy cannot introduce an arbitrary shell or argv surface.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Final, Mapping

from scripts.harness.packet_evidence import (
    HOST_SIGNING_IDENTIFIER,
    HOST_TEAM_ID,
    INSTALLED_APP,
    INSTALLED_EXECUTABLE,
    PACKET_STATE_DOCUMENT,
    PACKET_ATTEMPT_DOCUMENT,
    PACKET_PROVENANCE_DOCUMENT,
    CASE_STAGE_PLANS,
    EXPECTED_PACKET_RAW_SUBJECTS,
    OPTIONAL_PACKET_RAW_SUBJECTS,
    TUNNEL_CAPTURE_LOCAL_ADDRESSES,
    PRODUCT_LOG_CATEGORY,
    PRODUCT_LOG_PREDICATE,
    PRODUCT_LOG_SUBSYSTEM,
    PRODUCT_OBSERVATION_PREFIX,
    REQUIRED_CASES,
    PacketEvidenceError,
    packet_capture_filter_argv,
    validate_packet_state_observation,
)
from scripts.harness.physical_collector_request import (
    PhysicalCollectorRequestError,
    validate_context,
)
from scripts.harness.packet_capture import (
    PacketCaptureError,
    StagedCaptureEndpoint,
    dns_stage_endpoints,
    staged_marker_window,
)
from scripts.harness.raw_artifacts import (
    RawArtifactError,
    canonical_json,
    exact_object,
    load_json_bytes,
)

from .execution import (
    CommandResult,
    CommandSpec,
    ProbeExecutionError,
    ReadinessSpec,
    command_sha256,
)
from . import ios_packet_lan_peer_adapter
from .observation import ObservationArtifact, ObservationCommand, PhysicalObservationError
from .packet_host import (
    PacketCaptureDisposition,
    PacketHostAborted,
    PacketHostBaseline,
    PacketHostError,
    PacketHostReceipt,
    PacketHostRestored,
    PacketHostSnapshot,
    PacketHostTestReady,
    run_fixed_host_transaction,
)
from .session import PhysicalCaptureSession, PhysicalCaptureSessionError


OBSERVATION_DIRECTORY: Final = "raw/packet/observations"
PRODUCT_QUERY_ROLE: Final = "product-observation-log"
PRODUCT_CODESIGN_ROLE: Final = "product-observation-codesign"
PRODUCT_QUERY_LOOKBACK: Final = timedelta(minutes=5)
PRODUCT_QUERY_TIMEOUT_SECONDS: Final = 30.0
PRODUCT_QUERY_OUTPUT_LIMIT: Final = 1024 * 1024
CODESIGN_OUTPUT_LIMIT: Final = 64 * 1024
PACKET_COMMAND_TIMEOUT_SECONDS: Final = 30.0
PACKET_CAPTURE_TIMEOUT_SECONDS: Final = 45.0
PACKET_ENDPOINT_TRANSPORT_PORT: Final = 44333
PACKET_ENDPOINT_DNS_PORT: Final = 53
PACKET_ENDPOINT_BINARY_SHA256: Final = (
    "c63c202b22823197ad12cb2d5f484c95be25904260ed266083dcca6fc766db6c"
)
PACKET_ENDPOINT_SYSTEMD_UNIT_SHA256: Final = (
    "7d485a9fe9081ebf019fcc8abc1d596358a64326e2490749d9903197262e3996"
)
PACKET_ENDPOINT_INSTALL_SCRIPT_SHA256: Final = (
    "14b45b1705f762057ac38d836f2ac5c7d3721e72ec0ec45b72505b354f0d05c8"
)
PACKET_ENDPOINT_RESOLVER_CONFIG_SHA256: Final = (
    "b290cc794e7f0faac9ebbd63f83aad67d23086b48206295d5d6a2767721c1e62"
)
PACKET_ENDPOINT_CAPTURE_SUDOERS_SHA256: Final = (
    "a91c2bc91a294622d44f14e2cad653b9703fcf70afa42bf91e0248ef240c3411"
)
PACKET_CAPTURE_SERVICE_ACCOUNT: Final = (
    "packet-capture-client@cfw-release-evidence-20260730.iam.gserviceaccount.com"
)
PACKET_CAPTURE_SERVICE_ACCOUNT_UNIQUE_ID: Final = "116706315441516966425"
PACKET_CAPTURE_OS_LOGIN_ROLE: Final = "roles/compute.osLogin"
PACKET_CAPTURE_IAP_ROLE: Final = "roles/iap.tunnelResourceAccessor"
PACKET_CAPTURE_IAP_DESTINATION_PORT: Final = 22
PACKET_CAPTURE_INTERNAL_IPV4: Final = {
    "primary": "10.42.40.3",
    "secondary": "10.42.41.2",
}
PACKET_CAPTURE_POSIX_USERNAME: Final = (
    f"sa_{PACKET_CAPTURE_SERVICE_ACCOUNT_UNIQUE_ID}"
)
PACKET_GCLOUD_PATH: Final = Path("/opt/homebrew/bin/gcloud")
PACKET_CAPTURE_KEY_BASENAME: Final = "packet-capture-rsa3072"
PACKET_CAPTURE_KEY_TTL: Final = "2m"
PACKET_LOCAL_CAPTURE_DEVICE: Final = "pktap,all"
PACKET_LOCAL_CAPTURE_LINK_TYPE: Final = 101
PACKET_LOCAL_CAPTURE_READY: Final = (
    b"tcpdump: listening on pktap,all, link-type RAW (Raw IP), "
    b"snapshot length 262144 bytes\n"
)
PACKET_REMOTE_CAPTURE_READY: Final = (
    b"tcpdump: listening on ens4, link-type EN10MB (Ethernet), "
    b"snapshot length 262144 bytes\n"
)
PACKET_CAPTURE_READINESS_SECONDS: Final = 20.0
PACKET_PRIVATE_KEY_MAXIMUM: Final = 16 * 1024

_CDHASH_RE = re.compile(r"^CDHash=([0-9a-f]{40})$", re.MULTILINE)
_UTC_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class PacketCaptureAdapterError(RuntimeError):
    """A production Packet observation is unavailable, ambiguous, or unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PacketStateObservation:
    case_id: str
    artifact: ObservationArtifact
    event_recorded_at: str
    generation: int
    config_digest: str | None
    sequence: int
    state: Mapping[str, object]

    def descriptor_mapping(self) -> dict[str, dict[str, object]]:
        suffix = (
            "restore-state"
            if self.artifact.subject.endswith(":restore-state")
            else "product-state"
        )
        return {f"{self.case_id}:{suffix}": self.artifact.descriptor.as_dict()}


@dataclass(frozen=True, slots=True)
class PacketEndpointPlan:
    """One source-owned endpoint/vantage contract, never a caller input.

    ``network_role`` names the reviewed facility (dual-stack GCP transport,
    primary/secondary DNS, LAN peer, or direct-WAN target).  Local capture uses
    a route-derived interface and an exact selector.  Independent DNS ingress
    requires an exact remote interface plus a separately pinned SSH host key
    and server identity; those fields are forbidden for local captures.
    """

    remote_address: str | None
    runtime_endpoint_source: str | None
    remote_port: int
    local_bind_strategy: str
    local_address_scope: str
    local_port_min: int
    local_port_max: int
    vantage: str
    network_role: str
    endpoint_service_id: str
    endpoint_service_identity_sha256: str
    endpoint_binary_sha256: str
    endpoint_service_unit_sha256: str
    endpoint_install_script_sha256: str
    endpoint_resolver_config_sha256: str
    endpoint_capture_sudoers_sha256: str
    capture_location: str
    interface_selector: str
    expected_interface: str | None
    remote_capture_host: str | None
    remote_host_key_sha256: str | None
    remote_server_identity_sha256: str | None
    remote_capture_service_account: str | None
    remote_capture_service_account_unique_id: str | None
    remote_capture_os_login_role: str | None
    remote_capture_iap_role: str | None
    remote_capture_iap_destination_port: int | None
    remote_capture_internal_ipv4_address: str | None


def _resolved_remote_address(plan: PacketEndpointPlan) -> str:
    if not isinstance(plan.remote_address, str):
        raise PacketCaptureAdapterError(
            "packet_endpoint_unresolved",
            "packet endpoint address was not resolved before command construction",
        )
    try:
        address = ipaddress.ip_address(plan.remote_address)
    except ValueError as error:
        raise PacketCaptureAdapterError(
            "packet_endpoint_unresolved", "resolved packet endpoint is invalid"
        ) from error
    if str(address) != plan.remote_address:
        raise PacketCaptureAdapterError(
            "packet_endpoint_unresolved", "resolved packet endpoint is non-canonical"
        )
    return plan.remote_address


@dataclass(frozen=True, slots=True)
class ObservedLocalEndpoint:
    """Route/interface-derived address; port zero requests a kernel allocation."""

    address: str
    interface_name: str


@dataclass(frozen=True, slots=True)
class ObservedNetworkInterface:
    name: str
    index: int
    link_type: int
    flags: tuple[str, ...]
    addresses: Mapping[str, tuple[str, ...]]

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "index": self.index,
            "link_type": self.link_type,
            "flags": list(self.flags),
        }


@dataclass(slots=True)
class PacketCaseRuntime:
    case_id: str
    plan: PacketEndpointPlan
    tokens: tuple[str, str, str]
    capture: ObservationCommand | None = None
    capture_alive_at: str | None = None
    capture_spec: CommandSpec | None = None
    capture_receipt: dict[str, Any] | None = None
    key_generation: dict[str, Any] | None = None
    public_key: dict[str, Any] | None = None
    key_import: dict[str, Any] | None = None
    remote_interface: dict[str, object] | None = None
    remote_interface_command: dict[str, Any] | None = None
    stages: list[dict[str, Any]] | None = None
    test_state: PacketStateObservation | None = None
    restore_state: PacketStateObservation | None = None
    capture_artifact: ObservationArtifact | None = None
    provenance_artifact: ObservationArtifact | None = None
    attempt_artifact: ObservationArtifact | None = None
    baseline_host: PacketHostBaseline | None = None
    test_host: PacketHostTestReady | None = None
    restored_host: PacketHostRestored | None = None
    ios_peer_lease: ios_packet_lan_peer_adapter.IOSPacketLanPeerLease | None = None
    ios_peer_admission: dict[str, object] | None = None
    ios_peer_before_capture: dict[str, object] | None = None
    ios_peer_after_capture: dict[str, object] | None = None
    ios_peer_cleanup: dict[str, object] | None = None

    def __post_init__(self) -> None:
        self.stages = []


ENDPOINT_POLICY_PATH: Final = Path(__file__).with_name("packet_endpoints.json")
ENDPOINT_POLICY_SHA256: Final = (
    "35f1e9bfc73baae302f7b26e24adf86df57a01c61f3c71133ae7cba23e64a5cb"
)
PACKET_KNOWN_HOSTS_PATH: Final = Path(__file__).with_name("packet_known_hosts")
PACKET_KNOWN_HOSTS_SHA256: Final = (
    "3741384531dbd24c65a2225386beae492bf92c61fdf2d5b90b57051d57be36ba"
)
ENDPOINT_POLICY_DOCUMENT: Final = "cfw-packet-endpoint-policy-v1"
ENDPOINT_IDENTITY_DOCUMENT: Final = "cfw-packet-endpoint-instance-identity-v1"
PACKET_LAN_PEER_NOT_APPLICABLE_SHA256: Final = (
    "fbd5434db14195c6f6ec9602abcf0b32697515ca93863d078d61bb79ae63ae26"
)
UNRESOLVED_PACKET_CASES: Final = frozenset()
UNRESOLVED_PACKET_CONTROLS: Final = frozenset()

_LOCAL_SELECTORS: Final = frozenset(
    {
        "route-selected-tunnel",
        "route-selected-physical-wan",
        "route-selected-lan",
    }
)
_NETWORK_ROLES: Final = frozenset(
    {
        "gcp-dual-stack-transport",
        "gcp-primary-dns",
        "gcp-secondary-dns",
        "controlled-lan-peer",
        "gcp-direct-wan-target",
    }
)


def _validate_endpoint_policy(
    policy: Mapping[str, PacketEndpointPlan],
    *,
    allow_source_pinned_unresolved: bool = False,
    require_current_artifacts: bool = True,
) -> dict[str, PacketEndpointPlan]:
    expected_cases = set(REQUIRED_CASES)
    if allow_source_pinned_unresolved:
        expected_cases -= UNRESOLVED_PACKET_CASES
    if set(policy) != expected_cases:
        raise PacketCaptureAdapterError(
            "packet_endpoint_policy_unconfigured",
            "the complete 13-case endpoint and independent-vantage policy is not source-pinned",
        )
    normalized: dict[str, PacketEndpointPlan] = {}
    dns_servers: dict[str, set[tuple[str, str]]] = {}
    dual_stack_services: set[tuple[str, str]] = set()
    dual_stack_families: set[int] = set()
    for case_id, spec in REQUIRED_CASES.items():
        if case_id not in policy:
            continue
        plan = policy[case_id]
        if not isinstance(plan, PacketEndpointPlan):
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid", "packet endpoint entry is not typed"
            )
        remote: ipaddress.IPv4Address | ipaddress.IPv6Address | None
        if case_id == "lan-bypass":
            if (
                plan.remote_address is not None
                or plan.runtime_endpoint_source
                != ios_packet_lan_peer_adapter.READY_DOCUMENT
            ):
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid",
                    "LAN endpoint must be resolved from the iPhone ready receipt",
                )
            remote = None
        else:
            if plan.runtime_endpoint_source is not None:
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid",
                    "static packet endpoint unexpectedly declares a runtime source",
                )
            try:
                remote = ipaddress.ip_address(plan.remote_address)
            except (TypeError, ValueError) as error:
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid", "packet endpoint address is invalid"
                ) from error
        expected_version = 4 if spec.family == "ipv4" else 6
        expected_scope = (
            "ipv4-route-interface"
            if spec.family == "ipv4"
            else "ipv6-route-interface"
        )
        endpoint_digests = (
            plan.endpoint_binary_sha256,
            plan.endpoint_service_unit_sha256,
            plan.endpoint_install_script_sha256,
            plan.endpoint_resolver_config_sha256,
            plan.endpoint_capture_sudoers_sha256,
        )
        digest_shape_valid = all(
            re.fullmatch(r"[0-9a-f]{64}", digest) is not None
            for digest in endpoint_digests
        )
        if plan.network_role == "controlled-lan-peer":
            stable_digest_contract = (
                plan.endpoint_service_unit_sha256
                == PACKET_LAN_PEER_NOT_APPLICABLE_SHA256
                and plan.endpoint_install_script_sha256
                == PACKET_LAN_PEER_NOT_APPLICABLE_SHA256
                and plan.endpoint_resolver_config_sha256
                == PACKET_LAN_PEER_NOT_APPLICABLE_SHA256
                and plan.endpoint_capture_sudoers_sha256
                == PACKET_LAN_PEER_NOT_APPLICABLE_SHA256
            )
            current_digest_contract = (
                plan.endpoint_binary_sha256
                == SOURCE_IOS_LAN_PEER_IDENTITY.executable_sha256
            )
        else:
            stable_digest_contract = True
            current_digest_contract = (
                plan.endpoint_binary_sha256 == PACKET_ENDPOINT_BINARY_SHA256
                and plan.endpoint_service_unit_sha256
                == PACKET_ENDPOINT_SYSTEMD_UNIT_SHA256
                and plan.endpoint_install_script_sha256
                == PACKET_ENDPOINT_INSTALL_SCRIPT_SHA256
                and plan.endpoint_resolver_config_sha256
                == PACKET_ENDPOINT_RESOLVER_CONFIG_SHA256
                and plan.endpoint_capture_sudoers_sha256
                == PACKET_ENDPOINT_CAPTURE_SUDOERS_SHA256
            )
        endpoint_digest_contract = (
            digest_shape_valid
            and stable_digest_contract
            and (current_digest_contract or not require_current_artifacts)
        )
        if (
            (remote is not None and remote.version != expected_version)
            or not 1 <= plan.remote_port <= 65535
            or plan.local_bind_strategy != "route-interface-kernel-ephemeral"
            or plan.local_address_scope != expected_scope
            or not 49152 <= plan.local_port_min <= plan.local_port_max <= 65535
            or plan.vantage != spec.vantage
            or plan.network_role not in _NETWORK_ROLES
            or not plan.endpoint_service_id
            or len(plan.endpoint_service_id.encode("utf-8")) > 128
            or re.fullmatch(r"[0-9a-f]{64}", plan.endpoint_service_identity_sha256)
            is None
            or not endpoint_digest_contract
        ):
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid",
                f"packet endpoint contract is invalid for {case_id}",
            )
        if spec.protocol == "dns":
            expected_role = (
                "gcp-primary-dns"
                if spec.resolver_role == "primary"
                else "gcp-secondary-dns"
            )
            if (
                plan.remote_port != PACKET_ENDPOINT_DNS_PORT
                or plan.network_role != expected_role
                or plan.capture_location != "remote-server"
                or plan.interface_selector != "exact-remote-interface"
                or not plan.expected_interface
                or not plan.remote_capture_host
                or not plan.remote_host_key_sha256
                or not plan.remote_server_identity_sha256
                or plan.remote_capture_service_account
                != PACKET_CAPTURE_SERVICE_ACCOUNT
                or plan.remote_capture_service_account_unique_id
                != PACKET_CAPTURE_SERVICE_ACCOUNT_UNIQUE_ID
                or plan.remote_capture_os_login_role != PACKET_CAPTURE_OS_LOGIN_ROLE
                or plan.remote_capture_iap_role != PACKET_CAPTURE_IAP_ROLE
                or plan.remote_capture_iap_destination_port
                != PACKET_CAPTURE_IAP_DESTINATION_PORT
                or plan.remote_capture_internal_ipv4_address
                != PACKET_CAPTURE_INTERNAL_IPV4[spec.resolver_role]
                or re.fullmatch(r"[0-9a-f]{64}", plan.remote_host_key_sha256)
                is None
                or re.fullmatch(r"[0-9a-f]{64}", plan.remote_server_identity_sha256)
                is None
            ):
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid",
                    f"{case_id} lacks independent DNS ingress capture identity",
                )
            if plan.endpoint_service_identity_sha256 != plan.remote_server_identity_sha256:
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid",
                    f"{case_id} endpoint/capture server identities disagree",
                )
            dns_servers.setdefault(spec.resolver_role, set()).add(
                (
                    plan.remote_capture_host,
                    plan.remote_server_identity_sha256,
                )
            )
        else:
            if (
                plan.capture_location != "local-mac"
                or plan.interface_selector not in _LOCAL_SELECTORS
                or plan.remote_capture_host is not None
                or plan.remote_host_key_sha256 is not None
                or plan.remote_server_identity_sha256 is not None
                or plan.remote_capture_service_account is not None
                or plan.remote_capture_service_account_unique_id is not None
                or plan.remote_capture_os_login_role is not None
                or plan.remote_capture_iap_role is not None
                or plan.remote_capture_iap_destination_port is not None
                or plan.remote_capture_internal_ipv4_address is not None
                or not plan.expected_interface
            ):
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid",
                    f"{case_id} local capture contract is invalid",
                )
            if spec.vantage == "tunnel_egress" and (
                plan.interface_selector != "route-selected-tunnel"
                or plan.network_role != "gcp-dual-stack-transport"
                or plan.expected_interface != "utun*"
            ):
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid",
                    f"{case_id} must use the route-selected tunnel to dual-stack GCP",
                )
            if spec.vantage == "direct_wan" and (
                plan.interface_selector != "route-selected-physical-wan"
                or plan.network_role != "gcp-direct-wan-target"
                or plan.remote_port != PACKET_ENDPOINT_TRANSPORT_PORT
                or plan.expected_interface != "non-utun"
            ):
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid",
                    f"{case_id} must use the physical WAN and direct target",
                )
            if spec.vantage == "lan_segment" and (
                plan.interface_selector != "route-selected-lan"
                or plan.network_role != "controlled-lan-peer"
                or plan.remote_port != PACKET_ENDPOINT_TRANSPORT_PORT
                or plan.expected_interface != "non-utun"
            ):
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid",
                    f"{case_id} must use the controlled LAN peer",
                )
            if plan.network_role == "gcp-dual-stack-transport":
                if plan.remote_port != PACKET_ENDPOINT_TRANSPORT_PORT:
                    raise PacketCaptureAdapterError(
                        "packet_endpoint_policy_invalid",
                        f"{case_id} transport port differs from the reviewed endpoint",
                    )
                dual_stack_services.add(
                    (plan.endpoint_service_id, plan.endpoint_service_identity_sha256)
                )
                if remote is None:
                    raise PacketCaptureAdapterError(
                        "packet_endpoint_policy_invalid",
                        f"{case_id} transport endpoint is unresolved",
                    )
                dual_stack_families.add(remote.version)
        normalized[case_id] = plan
    primary_hosts = {host for host, _identity in dns_servers.get("primary", set())}
    secondary_hosts = {host for host, _identity in dns_servers.get("secondary", set())}
    primary_identities = {
        identity for _host, identity in dns_servers.get("primary", set())
    }
    secondary_identities = {
        identity for _host, identity in dns_servers.get("secondary", set())
    }
    if (
        set(dns_servers) != {"primary", "secondary"}
        or any(len(servers) != 1 for servers in dns_servers.values())
        or not primary_hosts.isdisjoint(secondary_hosts)
        or not primary_identities.isdisjoint(secondary_identities)
    ):
        raise PacketCaptureAdapterError(
            "packet_endpoint_policy_invalid",
            "primary and secondary DNS capture servers must be independently identified",
        )
    if len(dual_stack_services) != 1 or dual_stack_families != {4, 6}:
        raise PacketCaptureAdapterError(
            "packet_endpoint_policy_invalid",
            "all tunnel transport cases must bind one reviewed dual-stack GCP service",
        )
    return normalized


_ENDPOINT_POLICY_FIELDS: Final = {
    "schema_version",
    "document",
    "identities",
    "cases",
    "unresolved_cases",
    "unresolved_controls",
}
_ENDPOINT_IDENTITY_ENTRY_FIELDS: Final = {"identity_sha256", "identity"}
_ENDPOINT_IDENTITY_FIELDS: Final = {
    "schema_version",
    "document",
    "endpoint_role",
    "project",
    "zone",
    "instance_name",
    "instance_id",
    "image_name",
    "image_id",
    "interface_name",
    "external_ipv4_address",
    "external_ipv6_address",
    "external_ipv6_prefix",
    "ssh_host_key_bytes_sha256",
    "shielded_vm_signing_identity_pem_sha256",
    "endpoint_binary_sha256",
    "endpoint_service_unit_sha256",
    "endpoint_install_script_sha256",
    "endpoint_resolver_config_sha256",
    "capture_sudoers_policy_sha256",
    "remote_capture_access",
    "tcpdump_version",
    "tcpdump_package_sha256",
}
_REMOTE_CAPTURE_ACCESS_FIELDS: Final = {
    "enabled",
    "service_account",
    "service_account_unique_id",
    "os_login_role",
    "iap_role",
    "iap_destination_port",
    "internal_ipv4_address",
}
_ENDPOINT_CASE_FIELDS: Final = {
    "identity_sha256",
    "remote_address",
    "runtime_endpoint_source",
    "remote_port",
    "capture_location",
    "interface_selector",
    "expected_interface",
    "remote_capture_host",
}
_ENDPOINT_ROLES: Final = frozenset({"transport", "dns-primary", "dns-secondary"})
_ENDPOINT_PROJECT: Final = "cfw-release-evidence-20260730"
_ENDPOINT_IMAGE_NAME: Final = "debian-12-bookworm-v20260727"
_ENDPOINT_IMAGE_ID: Final = "4922483122153092318"
_ENDPOINT_INTERFACE: Final = "ens4"
_TCPDUMP_VERSION: Final = "4.99.3-1"
_TCPDUMP_PACKAGE_SHA256: Final = (
    "c97881e39b54571829ec22b98cfa9c2348c7449a92fd761ebee7826b47ef4616"
)
_MAX_ENDPOINT_POLICY_BYTES: Final = 256 * 1024

try:
    SOURCE_IOS_LAN_PEER_IDENTITY: Final = (
        ios_packet_lan_peer_adapter.load_source_identity()
    )
except ios_packet_lan_peer_adapter.IOSPacketLanPeerError as error:
    raise PacketCaptureAdapterError(
        "ios_lan_peer_identity_invalid",
        "source-pinned iPhone LAN peer identity is unavailable or malformed",
    ) from error


def _source_endpoint_policy() -> dict[str, PacketEndpointPlan]:
    """Load and authenticate the reviewed GCE identities and case projection."""

    try:
        if ENDPOINT_POLICY_PATH.is_symlink() or not ENDPOINT_POLICY_PATH.is_file():
            raise OSError("endpoint policy is not a regular source file")
        data = ENDPOINT_POLICY_PATH.read_bytes()
        if not 1 <= len(data) <= _MAX_ENDPOINT_POLICY_BYTES:
            raise OSError("endpoint policy exceeds its source byte bound")
        if hashlib.sha256(data).hexdigest() != ENDPOINT_POLICY_SHA256:
            raise OSError("endpoint policy differs from its whole-file pin")
        document = exact_object(
            load_json_bytes(data, "packet endpoint policy"),
            _ENDPOINT_POLICY_FIELDS,
            "packet endpoint policy",
        )
    except (OSError, RawArtifactError) as error:
        raise PacketCaptureAdapterError(
            "packet_endpoint_policy_invalid",
            "source-pinned packet endpoint policy is unavailable or malformed",
        ) from error
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["document"] != ENDPOINT_POLICY_DOCUMENT
        or document["unresolved_cases"] != sorted(UNRESOLVED_PACKET_CASES)
        or document["unresolved_controls"]
        != sorted(UNRESOLVED_PACKET_CONTROLS)
    ):
        raise PacketCaptureAdapterError(
            "packet_endpoint_policy_invalid",
            "source-pinned packet endpoint policy identity or unresolved set drifted",
        )

    raw_identities = document["identities"]
    if not isinstance(raw_identities, list) or len(raw_identities) != len(
        _ENDPOINT_ROLES
    ):
        raise PacketCaptureAdapterError(
            "packet_endpoint_policy_invalid",
            "packet endpoint policy must bind the exact three GCE identities",
        )
    identities: dict[str, dict[str, Any]] = {}
    identity_roles: set[str] = set()
    for index, value in enumerate(raw_identities):
        try:
            entry = exact_object(
                value,
                _ENDPOINT_IDENTITY_ENTRY_FIELDS,
                f"packet endpoint identities[{index}]",
            )
            identity = exact_object(
                entry["identity"],
                _ENDPOINT_IDENTITY_FIELDS,
                f"packet endpoint identities[{index}].identity",
            )
            remote_capture_access = exact_object(
                identity["remote_capture_access"],
                _REMOTE_CAPTURE_ACCESS_FIELDS,
                f"packet endpoint identities[{index}].remote_capture_access",
            )
            identity_bytes = canonical_json(identity)
        except RawArtifactError as error:
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid",
                "packet endpoint identity has an unexpected field or encoding",
            ) from error
        digest = entry["identity_sha256"]
        role = identity["endpoint_role"]
        identity_text_fields = _ENDPOINT_IDENTITY_FIELDS - {
            "schema_version",
            "remote_capture_access",
        }
        if any(
            not isinstance(identity[field], str) for field in identity_text_fields
        ):
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid",
                "packet endpoint canonical identity contains a non-text field",
            )
        try:
            external_v4 = ipaddress.ip_address(identity["external_ipv4_address"])
            external_v6 = ipaddress.ip_address(identity["external_ipv6_address"])
            external_prefix = ipaddress.ip_network(
                identity["external_ipv6_prefix"], strict=True
            )
        except (TypeError, ValueError) as error:
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid",
                "packet endpoint identity address/prefix is invalid",
            ) from error
        digest_fields = (
            "ssh_host_key_bytes_sha256",
            "shielded_vm_signing_identity_pem_sha256",
            "endpoint_binary_sha256",
            "endpoint_service_unit_sha256",
            "endpoint_install_script_sha256",
            "endpoint_resolver_config_sha256",
            "capture_sudoers_policy_sha256",
            "tcpdump_package_sha256",
        )
        expected_remote_capture_access = (
            {
                "enabled": False,
                "service_account": None,
                "service_account_unique_id": None,
                "os_login_role": None,
                "iap_role": None,
                "iap_destination_port": None,
                "internal_ipv4_address": None,
            }
            if role == "transport"
            else {
                "enabled": True,
                "service_account": PACKET_CAPTURE_SERVICE_ACCOUNT,
                "service_account_unique_id": (
                    PACKET_CAPTURE_SERVICE_ACCOUNT_UNIQUE_ID
                ),
                "os_login_role": PACKET_CAPTURE_OS_LOGIN_ROLE,
                "iap_role": PACKET_CAPTURE_IAP_ROLE,
                "iap_destination_port": PACKET_CAPTURE_IAP_DESTINATION_PORT,
                "internal_ipv4_address": PACKET_CAPTURE_INTERNAL_IPV4.get(
                    role.removeprefix("dns-")
                ),
            }
        )
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or hashlib.sha256(identity_bytes).hexdigest() != digest
            or role not in _ENDPOINT_ROLES
            or role in identity_roles
            or type(identity["schema_version"]) is not int
            or identity["schema_version"] != 1
            or identity["document"] != ENDPOINT_IDENTITY_DOCUMENT
            or identity["project"] != _ENDPOINT_PROJECT
            or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", identity["zone"] or "")
            is None
            or re.fullmatch(
                r"[a-z][a-z0-9-]{0,62}", identity["instance_name"] or ""
            )
            is None
            or re.fullmatch(r"[1-9][0-9]{0,19}", identity["instance_id"] or "")
            is None
            or identity["image_name"] != _ENDPOINT_IMAGE_NAME
            or identity["image_id"] != _ENDPOINT_IMAGE_ID
            or identity["interface_name"] != _ENDPOINT_INTERFACE
            or external_v4.version != 4
            or str(external_v4) != identity["external_ipv4_address"]
            or external_v6.version != 6
            or str(external_v6) != identity["external_ipv6_address"]
            or external_prefix.version != 6
            or external_prefix.prefixlen != 96
            or external_v6 != external_prefix.network_address
            or any(
                not isinstance(identity[field], str)
                or re.fullmatch(r"[0-9a-f]{64}", identity[field]) is None
                for field in digest_fields
            )
            or remote_capture_access != expected_remote_capture_access
            or identity["tcpdump_version"] != _TCPDUMP_VERSION
            or identity["tcpdump_package_sha256"] != _TCPDUMP_PACKAGE_SHA256
        ):
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid",
                "packet endpoint canonical instance identity differs from its pins",
            )
        identity_roles.add(role)
        identities[digest] = identity
    if identity_roles != _ENDPOINT_ROLES or len(identities) != len(_ENDPOINT_ROLES):
        raise PacketCaptureAdapterError(
            "packet_endpoint_policy_invalid",
            "packet endpoint identities are duplicated or incomplete",
        )
    try:
        if (
            PACKET_KNOWN_HOSTS_PATH.is_symlink()
            or not PACKET_KNOWN_HOSTS_PATH.is_file()
        ):
            raise OSError("known-hosts policy is not a regular source file")
        known_hosts_bytes = PACKET_KNOWN_HOSTS_PATH.read_bytes()
        if (
            not 1 <= len(known_hosts_bytes) <= 16 * 1024
            or hashlib.sha256(known_hosts_bytes).hexdigest()
            != PACKET_KNOWN_HOSTS_SHA256
        ):
            raise OSError("known-hosts policy differs from its whole-file pin")
        known_hosts_text = known_hosts_bytes.decode("ascii", errors="strict")
        if not known_hosts_text.endswith("\n") or "\r" in known_hosts_text:
            raise ValueError("known-hosts policy is not canonical LF text")
        known_hosts: dict[str, str] = {}
        for line in known_hosts_text.splitlines():
            fields = line.split(" ")
            if (
                len(fields) != 3
                or fields[0] in known_hosts
                or fields[1] != "ssh-ed25519"
            ):
                raise ValueError("known-hosts policy line is invalid")
            base64.b64decode(fields[2], validate=True)
            known_hosts[fields[0]] = fields[2]
        dns_identities = [
            identity
            for identity in identities.values()
            if identity["endpoint_role"].startswith("dns-")
        ]
        if set(known_hosts) != {
            f"compute.{identity['instance_id']}" for identity in dns_identities
        }:
            raise ValueError("known-hosts aliases differ from DNS instance IDs")
        for identity in dns_identities:
            alias = f"compute.{identity['instance_id']}"
            public_key_file = (
                f"ssh-ed25519 {known_hosts[alias]} "
                f"root@{identity['instance_name']}\n"
            ).encode("ascii")
            if (
                hashlib.sha256(public_key_file).hexdigest()
                != identity["ssh_host_key_bytes_sha256"]
            ):
                raise ValueError("known-hosts key differs from instance identity")
    except (OSError, UnicodeError, ValueError) as error:
        raise PacketCaptureAdapterError(
            "packet_endpoint_policy_invalid",
            "source-pinned Packet known-hosts policy is unavailable or inconsistent",
        ) from error

    raw_cases = document["cases"]
    expected_cases = set(REQUIRED_CASES) - UNRESOLVED_PACKET_CASES
    if not isinstance(raw_cases, dict) or set(raw_cases) != expected_cases:
        raise PacketCaptureAdapterError(
            "packet_endpoint_policy_invalid",
            "packet endpoint case projection differs from the reviewed partial matrix",
        )
    plans: dict[str, PacketEndpointPlan] = {}
    for case_id, spec in REQUIRED_CASES.items():
        if case_id in UNRESOLVED_PACKET_CASES:
            continue
        try:
            value = exact_object(
                raw_cases[case_id],
                _ENDPOINT_CASE_FIELDS,
                f"packet endpoint cases.{case_id}",
            )
        except RawArtifactError as error:
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid",
                f"packet endpoint case projection is malformed for {case_id}",
            ) from error
        identity_sha256 = value["identity_sha256"]
        if (
            not isinstance(identity_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", identity_sha256) is None
            or value["remote_address"] is not None
            and not isinstance(value["remote_address"], str)
            or value["runtime_endpoint_source"] is not None
            and not isinstance(value["runtime_endpoint_source"], str)
            or type(value["remote_port"]) is not int
            or not isinstance(value["capture_location"], str)
            or not isinstance(value["interface_selector"], str)
            or not isinstance(value["expected_interface"], str)
            or (
                value["remote_capture_host"] is not None
                and not isinstance(value["remote_capture_host"], str)
            )
        ):
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid",
                f"packet endpoint case types are invalid for {case_id}",
            )
        if case_id == "lan-bypass":
            if (
                identity_sha256 != SOURCE_IOS_LAN_PEER_IDENTITY.identity_sha256
                or value["remote_address"] is not None
                or value["runtime_endpoint_source"]
                != ios_packet_lan_peer_adapter.READY_DOCUMENT
                or value["remote_port"] != ios_packet_lan_peer_adapter.LISTENER_PORT
                or value["capture_location"] != "local-mac"
                or value["interface_selector"] != "route-selected-lan"
                or value["expected_interface"] != "non-utun"
                or value["remote_capture_host"] is not None
            ):
                raise PacketCaptureAdapterError(
                    "packet_endpoint_policy_invalid",
                    "lan-bypass endpoint projection differs from the admitted iPhone peer",
                )
            plans[case_id] = PacketEndpointPlan(
                remote_address=None,
                runtime_endpoint_source=value["runtime_endpoint_source"],
                remote_port=value["remote_port"],
                local_bind_strategy="route-interface-kernel-ephemeral",
                local_address_scope="ipv4-route-interface",
                local_port_min=49152,
                local_port_max=65535,
                vantage=spec.vantage,
                network_role="controlled-lan-peer",
                endpoint_service_id=(
                    f"ios://packet-lan-peer/{SOURCE_IOS_LAN_PEER_IDENTITY.identity_sha256}"
                ),
                endpoint_service_identity_sha256=(
                    SOURCE_IOS_LAN_PEER_IDENTITY.identity_sha256
                ),
                endpoint_binary_sha256=(
                    SOURCE_IOS_LAN_PEER_IDENTITY.executable_sha256
                ),
                endpoint_service_unit_sha256=PACKET_LAN_PEER_NOT_APPLICABLE_SHA256,
                endpoint_install_script_sha256=PACKET_LAN_PEER_NOT_APPLICABLE_SHA256,
                endpoint_resolver_config_sha256=PACKET_LAN_PEER_NOT_APPLICABLE_SHA256,
                endpoint_capture_sudoers_sha256=PACKET_LAN_PEER_NOT_APPLICABLE_SHA256,
                capture_location=value["capture_location"],
                interface_selector=value["interface_selector"],
                expected_interface=value["expected_interface"],
                remote_capture_host=None,
                remote_host_key_sha256=None,
                remote_server_identity_sha256=None,
                remote_capture_service_account=None,
                remote_capture_service_account_unique_id=None,
                remote_capture_os_login_role=None,
                remote_capture_iap_role=None,
                remote_capture_iap_destination_port=None,
                remote_capture_internal_ipv4_address=None,
            )
            continue
        identity = identities.get(identity_sha256)
        if identity is None:
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid",
                f"packet endpoint case has an unknown instance identity for {case_id}",
            )
        expected_address = identity[
            "external_ipv4_address"
            if spec.family == "ipv4"
            else "external_ipv6_address"
        ]
        if spec.protocol == "dns":
            expected_identity_role = f"dns-{spec.resolver_role}"
            expected_role = f"gcp-{spec.resolver_role}-dns"
            expected_capture_location = "remote-server"
            expected_selector = "exact-remote-interface"
            expected_interface = identity["interface_name"]
            expected_capture_host = identity["external_ipv4_address"]
            expected_port = PACKET_ENDPOINT_DNS_PORT
        else:
            expected_identity_role = "transport"
            expected_role = (
                "gcp-direct-wan-target"
                if spec.vantage == "direct_wan"
                else "gcp-dual-stack-transport"
            )
            expected_capture_location = "local-mac"
            expected_selector = (
                "route-selected-physical-wan"
                if spec.vantage == "direct_wan"
                else "route-selected-tunnel"
            )
            expected_interface = "non-utun" if spec.vantage == "direct_wan" else "utun*"
            expected_capture_host = None
            expected_port = PACKET_ENDPOINT_TRANSPORT_PORT
        if (
            identity["endpoint_role"] != expected_identity_role
            or value["remote_address"] != expected_address
            or value["runtime_endpoint_source"] is not None
            or value["remote_port"] != expected_port
            or value["capture_location"] != expected_capture_location
            or value["interface_selector"] != expected_selector
            or value["expected_interface"] != expected_interface
            or value["remote_capture_host"] != expected_capture_host
        ):
            raise PacketCaptureAdapterError(
                "packet_endpoint_policy_invalid",
                f"packet endpoint case projection differs from its identity for {case_id}",
            )
        service_id = (
            f"gce://{identity['project']}/{identity['zone']}/"
            f"{identity['instance_name']}/{identity['instance_id']}"
        )
        remote_capture_access = identity["remote_capture_access"]
        plans[case_id] = PacketEndpointPlan(
            remote_address=value["remote_address"],
            runtime_endpoint_source=None,
            remote_port=value["remote_port"],
            local_bind_strategy="route-interface-kernel-ephemeral",
            local_address_scope=(
                "ipv4-route-interface"
                if spec.family == "ipv4"
                else "ipv6-route-interface"
            ),
            local_port_min=49152,
            local_port_max=65535,
            vantage=spec.vantage,
            network_role=expected_role,
            endpoint_service_id=service_id,
            endpoint_service_identity_sha256=identity_sha256,
            endpoint_binary_sha256=identity["endpoint_binary_sha256"],
            endpoint_service_unit_sha256=identity[
                "endpoint_service_unit_sha256"
            ],
            endpoint_install_script_sha256=identity[
                "endpoint_install_script_sha256"
            ],
            endpoint_resolver_config_sha256=identity[
                "endpoint_resolver_config_sha256"
            ],
            endpoint_capture_sudoers_sha256=identity[
                "capture_sudoers_policy_sha256"
            ],
            capture_location=value["capture_location"],
            interface_selector=value["interface_selector"],
            expected_interface=value["expected_interface"],
            remote_capture_host=value["remote_capture_host"],
            remote_host_key_sha256=(
                identity["ssh_host_key_bytes_sha256"]
                if spec.protocol == "dns"
                else None
            ),
            remote_server_identity_sha256=(
                identity_sha256 if spec.protocol == "dns" else None
            ),
            remote_capture_service_account=(
                remote_capture_access["service_account"]
                if spec.protocol == "dns"
                else None
            ),
            remote_capture_service_account_unique_id=(
                remote_capture_access["service_account_unique_id"]
                if spec.protocol == "dns"
                else None
            ),
            remote_capture_os_login_role=(
                remote_capture_access["os_login_role"]
                if spec.protocol == "dns"
                else None
            ),
            remote_capture_iap_role=(
                remote_capture_access["iap_role"]
                if spec.protocol == "dns"
                else None
            ),
            remote_capture_iap_destination_port=(
                remote_capture_access["iap_destination_port"]
                if spec.protocol == "dns"
                else None
            ),
            remote_capture_internal_ipv4_address=(
                remote_capture_access["internal_ipv4_address"]
                if spec.protocol == "dns"
                else None
            ),
        )
    return _validate_endpoint_policy(
        plans,
        allow_source_pinned_unresolved=True,
        require_current_artifacts=False,
    )


SOURCE_PINNED_ENDPOINTS: Final[Mapping[str, PacketEndpointPlan]] = (
    _source_endpoint_policy()
)


def _revalidate_source_pins() -> None:
    try:
        endpoint_policy = _source_endpoint_policy()
        ios_identity = ios_packet_lan_peer_adapter.load_source_identity()
    except PacketCaptureAdapterError:
        raise
    except ios_packet_lan_peer_adapter.IOSPacketLanPeerError as error:
        raise PacketCaptureAdapterError(
            "ios_lan_peer_identity_stale",
            "source-pinned iPhone LAN peer identity could not be reopened",
        ) from error
    except Exception as error:
        raise PacketCaptureAdapterError(
            "packet_source_policy_invalid",
            "source-pinned Packet endpoint or iPhone identity could not be reopened",
        ) from error
    try:
        _validate_endpoint_policy(endpoint_policy)
    except PacketCaptureAdapterError as error:
        raise PacketCaptureAdapterError(
            "packet_endpoint_artifact_identity_stale",
            "source-pinned Packet endpoints do not bind the current endpoint artifacts",
        ) from error
    if (
        endpoint_policy != SOURCE_PINNED_ENDPOINTS
        or ios_identity.file_sha256 != SOURCE_IOS_LAN_PEER_IDENTITY.file_sha256
        or ios_identity.identity_sha256
        != SOURCE_IOS_LAN_PEER_IDENTITY.identity_sha256
        or ios_identity.as_identity() != SOURCE_IOS_LAN_PEER_IDENTITY.as_identity()
    ):
        raise PacketCaptureAdapterError(
            "packet_source_policy_changed",
            "source-pinned Packet endpoint or iPhone identity changed after import",
        )


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PacketCaptureAdapterError(
            "invalid_observation_time", "packet observation time must be timezone-aware"
        )
    return value.astimezone(timezone.utc).strftime(_UTC_FORMAT)


def _decode(value: bytes, label: str, maximum: int) -> str:
    if not isinstance(value, bytes) or len(value) > maximum:
        raise PacketCaptureAdapterError(
            "command_output_unbounded", f"{label} exceeds its fixed byte bound"
        )
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PacketCaptureAdapterError(
            "command_output_invalid", f"{label} is not UTF-8"
        ) from error
    if "\x00" in text:
        raise PacketCaptureAdapterError(
            "command_output_invalid", f"{label} contains a NUL byte"
        )
    return text


def _command_receipt(
    result: CommandResult,
    spec: CommandSpec,
    *,
    output_limit: int,
    binary_stdout: bool = False,
) -> dict[str, Any]:
    if (
        result.role != spec.role
        or result.argv_sha256 != command_sha256(spec.argv)
        or type(result.exit_code) is not int
        or result.exit_code != 0
    ):
        raise PacketCaptureAdapterError(
            "command_result_drift", "fixed packet command result differs from its spec"
        )
    if binary_stdout and len(result.stdout) > output_limit:
        raise PacketCaptureAdapterError(
            "command_output_unbounded", f"{spec.role}.stdout exceeds its fixed byte bound"
        )
    stdout = (
        None
        if binary_stdout
        else _decode(result.stdout, f"{spec.role}.stdout", output_limit)
    )
    stderr = _decode(result.stderr, f"{spec.role}.stderr", output_limit)
    return {
        "role": spec.role,
        "argv": list(spec.argv),
        "argv_sha256": result.argv_sha256,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "duration_ms": result.duration_ms,
        "exit_code": result.exit_code,
        "stdout_size": len(result.stdout),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdout": stdout,
        "stderr_size": len(result.stderr),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderr": stderr,
    }


def _product_query_spec(repository: Path, start: datetime, end: datetime) -> CommandSpec:
    return CommandSpec(
        role=PRODUCT_QUERY_ROLE,
        argv=(
            "/usr/bin/log",
            "show",
            "--style",
            "ndjson",
            "--info",
            "--timezone",
            "UTC",
            "--start",
            _utc(start),
            "--end",
            _utc(end),
            "--predicate",
            PRODUCT_LOG_PREDICATE,
        ),
        cwd=repository,
        timeout_seconds=PRODUCT_QUERY_TIMEOUT_SECONDS,
        stdout_limit=PRODUCT_QUERY_OUTPUT_LIMIT,
        stderr_limit=CODESIGN_OUTPUT_LIMIT,
    )


def _codesign_spec(repository: Path) -> CommandSpec:
    return CommandSpec(
        role=PRODUCT_CODESIGN_ROLE,
        argv=("/usr/bin/codesign", "-d", "--verbose=4", INSTALLED_APP),
        cwd=repository,
        timeout_seconds=PRODUCT_QUERY_TIMEOUT_SECONDS,
        stdout_limit=CODESIGN_OUTPUT_LIMIT,
        stderr_limit=CODESIGN_OUTPUT_LIMIT,
    )


def _parse_log_entries(stdout: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            value = load_json_bytes(line.encode("utf-8"), "Unified Log entry")
        except (RawArtifactError, UnicodeEncodeError) as error:
            raise PacketCaptureAdapterError(
                "product_log_invalid", "Unified Log output is not strict NDJSON"
            ) from error
        if not isinstance(value, dict):
            raise PacketCaptureAdapterError(
                "product_log_invalid", "Unified Log entry is not an object"
            )
        entries.append(value)
    return entries


def _candidate_event(entry: dict[str, Any]) -> tuple[int, dict[str, Any]] | None:
    required = {
        "timestamp",
        "processImagePath",
        "processID",
        "subsystem",
        "category",
        "eventMessage",
    }
    if not required <= set(entry):
        return None
    if (
        entry["processImagePath"] != INSTALLED_EXECUTABLE
        or entry["subsystem"] != PRODUCT_LOG_SUBSYSTEM
        or entry["category"] != PRODUCT_LOG_CATEGORY
        or not isinstance(entry["eventMessage"], str)
        or not entry["eventMessage"].startswith(PRODUCT_OBSERVATION_PREFIX)
    ):
        return None
    encoded = entry["eventMessage"][len(PRODUCT_OBSERVATION_PREFIX) :]
    try:
        event = load_json_bytes(encoded.encode("utf-8"), "Host release observation")
        if canonical_json(event).decode("utf-8") != encoded:
            raise ValueError("event is not canonical")
        recorded = event["recorded_unix_ms"]
    except (
        KeyError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
        RawArtifactError,
    ) as error:
        raise PacketCaptureAdapterError(
            "product_event_invalid", "Host release observation is not canonical"
        ) from error
    if type(recorded) is not int or recorded < 1:
        raise PacketCaptureAdapterError(
            "product_event_invalid", "Host release observation time is invalid"
        )
    return recorded, event


def _latest_product_event(
    entries: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidates: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    for entry in entries:
        parsed = _candidate_event(entry)
        if parsed is not None:
            candidates.append((parsed[0], entry, parsed[1]))
    if not candidates:
        raise PacketCaptureAdapterError(
            "product_observation_missing", "no installed Host release observation was retained"
        )
    latest_time = max(candidate[0] for candidate in candidates)
    latest = [candidate for candidate in candidates if candidate[0] == latest_time]
    if len(latest) != 1:
        raise PacketCaptureAdapterError(
            "product_observation_ambiguous", "latest Host release observation is ambiguous"
        )
    _recorded, entry, event = latest[0]
    normalized = {
        field: entry[field]
        for field in (
            "timestamp",
            "processImagePath",
            "processID",
            "subsystem",
            "category",
            "eventMessage",
        )
    }
    return normalized, event


def _codesign_identity(receipt: dict[str, Any]) -> dict[str, str]:
    output = receipt["stdout"] + receipt["stderr"]
    matches = _CDHASH_RE.findall(output)
    if len(matches) != 1:
        raise PacketCaptureAdapterError(
            "codesign_identity_invalid", "installed Host codesign output lacks one CDHash"
        )
    required = (
        f"Executable={INSTALLED_EXECUTABLE}",
        f"Identifier={HOST_SIGNING_IDENTIFIER}",
        f"TeamIdentifier={HOST_TEAM_ID}",
    )
    lines = output.splitlines()
    if any(line not in lines for line in required):
        raise PacketCaptureAdapterError(
            "codesign_identity_invalid", "installed Host code identity differs"
        )
    return {
        "executable": INSTALLED_EXECUTABLE,
        "team_id": HOST_TEAM_ID,
        "signing_identifier": HOST_SIGNING_IDENTIFIER,
        "cdhash": matches[0],
    }


def _state_relative(case_id: str, restored: bool) -> str:
    suffix = "restore-state" if restored else "product-state"
    return f"{OBSERVATION_DIRECTORY}/{case_id}-{suffix}.json"


def capture_product_state_observation(
    *,
    session: PhysicalCaptureSession,
    context: object,
    case_id: str,
    restored: bool = False,
    observed_at: datetime | None = None,
) -> PacketStateObservation:
    """Read, authenticate, validate and archive the latest Host state event."""

    if not isinstance(session, PhysicalCaptureSession):
        raise PacketCaptureAdapterError(
            "invalid_session", "packet state capture requires PhysicalCaptureSession"
        )
    if case_id not in REQUIRED_CASES:
        raise PacketCaptureAdapterError(
            "unknown_packet_case", "packet state case is not source-pinned"
        )
    try:
        capture = session.observation_capture()
        validated_context = validate_context(context)
    except (
        OSError,
        PhysicalCaptureSessionError,
        PhysicalCollectorRequestError,
    ) as error:
        raise PacketCaptureAdapterError(
            "packet_context_invalid", "packet state context/session failed revalidation"
        ) from error
    now = datetime.now(timezone.utc) if observed_at is None else observed_at
    if now.tzinfo is None or now.utcoffset() is None:
        raise PacketCaptureAdapterError(
            "invalid_observation_time", "packet observed_at must be timezone-aware"
        )
    now = now.astimezone(timezone.utc)
    query_spec = _product_query_spec(
        session.archive.repository, now - PRODUCT_QUERY_LOOKBACK, now
    )
    codesign_spec = _codesign_spec(session.archive.repository)
    try:
        query_result = capture.run_command(query_spec)
        codesign_result = capture.run_command(codesign_spec)
    except (PhysicalObservationError, PhysicalCaptureSessionError, ProbeExecutionError) as error:
        raise PacketCaptureAdapterError(
            "product_observation_command_failed",
            "fixed Host observation commands failed closed",
        ) from error
    query_receipt = _command_receipt(
        query_result, query_spec, output_limit=PRODUCT_QUERY_OUTPUT_LIMIT
    )
    if query_receipt["stderr"]:
        raise PacketCaptureAdapterError(
            "product_log_stderr", "Unified Log query produced unexpected stderr"
        )
    log_entry, event = _latest_product_event(
        _parse_log_entries(query_receipt["stdout"])
    )
    codesign_receipt = _command_receipt(
        codesign_result, codesign_spec, output_limit=CODESIGN_OUTPUT_LIMIT
    )
    candidate = validated_context["candidate"]
    observation = {
        "schema_version": 1,
        "document": PACKET_STATE_DOCUMENT,
        "case_id": case_id,
        "log_entry": log_entry,
        "query_command": query_receipt,
        "codesign_command": codesign_receipt,
        "signing_identity": _codesign_identity(codesign_receipt),
        "event": event,
    }
    try:
        parsed = validate_packet_state_observation(
            observation,
            case_id=case_id,
            candidate={
                "version": candidate["version"],
                "build_number": candidate["build_number"],
            },
            restored=restored,
        )
        data = canonical_json(observation) + b"\n"
        subject = f"{case_id}:{'restore-state' if restored else 'product-state'}"
        artifact = capture.write_bytes(
            subject=subject,
            kind="packet-product-state-observation",
            relative=_state_relative(case_id, restored),
            data=data,
        )
    except (PacketEvidenceError, RawArtifactError, PhysicalObservationError) as error:
        raise PacketCaptureAdapterError(
            "product_observation_invalid",
            "latest Host state cannot form one valid packet observation",
        ) from error
    return PacketStateObservation(
        case_id=case_id,
        artifact=artifact,
        event_recorded_at=log_entry["timestamp"],
        generation=parsed["state"]["generation"],
        config_digest=parsed["state"]["config_digest"],
        sequence=parsed["sequence"],
        state=dict(parsed["state"]),
    )


def _route_spec(repository: Path, remote_address: str) -> CommandSpec:
    address = str(ipaddress.ip_address(remote_address))
    return CommandSpec(
        role="packet-route-observation",
        argv=("/sbin/route", "-n", "get", address),
        cwd=repository,
        timeout_seconds=PACKET_COMMAND_TIMEOUT_SECONDS,
        stdout_limit=64 * 1024,
        stderr_limit=0,
    )


def _interface_spec(
    repository: Path,
    interface_name: str,
    *,
    role: str = "packet-interface-observation",
) -> CommandSpec:
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,31}", interface_name) is None:
        raise PacketCaptureAdapterError(
            "interface_invalid", "capture interface name is not canonical"
        )
    return CommandSpec(
        role=role,
        argv=("/sbin/ifconfig", "-v", interface_name),
        cwd=repository,
        timeout_seconds=PACKET_COMMAND_TIMEOUT_SECONDS,
        stdout_limit=256 * 1024,
        stderr_limit=0,
    )


def _capture_spec(
    repository: Path,
    *,
    case_id: str,
    tokens: tuple[str, str, str],
    lan_endpoint_address: str | None = None,
) -> CommandSpec:
    spec = REQUIRED_CASES.get(case_id)
    if spec is None or spec.protocol == "dns":
        raise PacketCaptureAdapterError(
            "capture_spec_invalid", "local capture case is not source-owned"
        )
    try:
        capture_filter = packet_capture_filter_argv(
            case_id=case_id,
            tokens=tokens,
            lan_endpoint_address=lan_endpoint_address,
        )
    except PacketEvidenceError as error:
        raise PacketCaptureAdapterError(
            "capture_spec_invalid", "local capture filter is not source-owned"
        ) from error
    count = 2 if not spec.token_observed else 3
    return CommandSpec(
        role="packet-capture",
        argv=(
            "/usr/sbin/tcpdump",
            "-i",
            PACKET_LOCAL_CAPTURE_DEVICE,
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
        ),
        cwd=repository,
        timeout_seconds=PACKET_CAPTURE_TIMEOUT_SECONDS,
        stdout_limit=1024 * 1024,
        stderr_limit=256 * 1024,
    )


def _remote_service_parts(plan: PacketEndpointPlan) -> tuple[str, str, str, str]:
    match = re.fullmatch(
        r"gce://([a-z][a-z0-9-]{0,62})/"
        r"([a-z][a-z0-9-]{0,62})/"
        r"([a-z][a-z0-9-]{0,62})/([1-9][0-9]{0,19})",
        plan.endpoint_service_id,
    )
    if (
        match is None
        or plan.capture_location != "remote-server"
        or plan.expected_interface != "ens4"
        or plan.remote_capture_service_account != PACKET_CAPTURE_SERVICE_ACCOUNT
        or plan.remote_capture_service_account_unique_id
        != PACKET_CAPTURE_SERVICE_ACCOUNT_UNIQUE_ID
        or plan.remote_capture_os_login_role != PACKET_CAPTURE_OS_LOGIN_ROLE
        or plan.remote_capture_iap_role != PACKET_CAPTURE_IAP_ROLE
        or plan.remote_capture_iap_destination_port
        != PACKET_CAPTURE_IAP_DESTINATION_PORT
    ):
        raise PacketCaptureAdapterError(
            "remote_capture_policy_invalid",
            "remote Packet capture plan lacks its exact instance-scoped identity",
        )
    return match.groups()


def _remote_key_path(session: PhysicalCaptureSession) -> Path:
    if not isinstance(session, PhysicalCaptureSession):
        raise PacketCaptureAdapterError(
            "remote_capture_key_path_invalid",
            "remote Packet capture key path requires the locked physical session",
        )
    root = (
        session.archive.repository
        / "target"
        / session.archive.root_relative_to_target
    )
    value = root / "runtime" / "packet-remote-capture" / PACKET_CAPTURE_KEY_BASENAME
    if not value.is_absolute() or len(str(value).encode("utf-8")) > 4096:
        raise PacketCaptureAdapterError(
            "remote_capture_key_path_invalid",
            "remote Packet capture key path is not session-derived and canonical",
        )
    return value


def _remote_key_import_spec(
    session: PhysicalCaptureSession,
    *,
    plan: PacketEndpointPlan,
) -> CommandSpec:
    project, _zone, _instance_name, _instance_id = _remote_service_parts(plan)
    private_key = _remote_key_path(session)
    return CommandSpec(
        role="packet-remote-key-import",
        argv=(
            str(PACKET_GCLOUD_PATH),
            "--verbosity=error",
            "--quiet",
            "compute",
            "os-login",
            "ssh-keys",
            "add",
            "--project",
            project,
            f"--impersonate-service-account={PACKET_CAPTURE_SERVICE_ACCOUNT}",
            f"--key-file={private_key}.pub",
            f"--ttl={PACKET_CAPTURE_KEY_TTL}",
            "--format=value(loginProfile.name)",
        ),
        cwd=session.archive.repository,
        timeout_seconds=PACKET_COMMAND_TIMEOUT_SECONDS,
        stdout_limit=64 * 1024,
        stderr_limit=0,
    )


def _remote_key_generation_spec(session: PhysicalCaptureSession) -> CommandSpec:
    return CommandSpec(
        role="packet-remote-key-generate",
        argv=(
            "/usr/bin/openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
        ),
        cwd=session.archive.repository,
        timeout_seconds=PACKET_COMMAND_TIMEOUT_SECONDS,
        stdout_limit=PACKET_PRIVATE_KEY_MAXIMUM,
        stderr_limit=64 * 1024,
    )


def _remote_public_key_spec(session: PhysicalCaptureSession) -> CommandSpec:
    return CommandSpec(
        role="packet-remote-public-key",
        argv=(
            "/usr/bin/ssh-keygen",
            "-y",
            "-f",
            str(_remote_key_path(session)),
        ),
        cwd=session.archive.repository,
        timeout_seconds=PACKET_COMMAND_TIMEOUT_SECONDS,
        stdout_limit=16 * 1024,
        stderr_limit=64 * 1024,
    )


def _remote_ssh_spec(
    session: PhysicalCaptureSession,
    *,
    plan: PacketEndpointPlan,
    role: str,
    remote_command: str,
    stdout_limit: int,
    stderr_limit: int,
) -> CommandSpec:
    project, zone, instance_name, instance_id = _remote_service_parts(plan)
    private_key = _remote_key_path(session)
    return CommandSpec(
        role=role,
        argv=(
            str(PACKET_GCLOUD_PATH),
            "--verbosity=error",
            "--quiet",
            "compute",
            "ssh",
            f"{PACKET_CAPTURE_POSIX_USERNAME}@{instance_name}",
            "--zone",
            zone,
            "--project",
            project,
            "--tunnel-through-iap",
            f"--impersonate-service-account={PACKET_CAPTURE_SERVICE_ACCOUNT}",
            f"--ssh-key-file={private_key}",
            "--plain",
            f"--command={remote_command}",
            "--",
            "-T",
            "-F",
            "/dev/null",
            "-i",
            str(private_key),
            "-o",
            "CheckHostIP=no",
            "-o",
            "HashKnownHosts=no",
            "-o",
            f"HostKeyAlias=compute.{instance_id}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={PACKET_KNOWN_HOSTS_PATH}",
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
        ),
        cwd=session.archive.repository,
        timeout_seconds=PACKET_CAPTURE_TIMEOUT_SECONDS,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
    )


def _remote_interface_spec(
    session: PhysicalCaptureSession,
    *,
    plan: PacketEndpointPlan,
) -> CommandSpec:
    interface = plan.expected_interface
    if interface != "ens4":
        raise PacketCaptureAdapterError(
            "remote_capture_policy_invalid", "remote capture interface is not exact"
        )
    return _remote_ssh_spec(
        session,
        plan=plan,
        role="packet-interface-observation",
        remote_command=f"/sbin/ifconfig -v {interface}",
        stdout_limit=256 * 1024,
        stderr_limit=0,
    )


def _remote_capture_spec(
    session: PhysicalCaptureSession,
    *,
    plan: PacketEndpointPlan,
) -> CommandSpec:
    interface = plan.expected_interface
    if interface != "ens4" or plan.remote_port != PACKET_ENDPOINT_DNS_PORT:
        raise PacketCaptureAdapterError(
            "remote_capture_policy_invalid", "remote DNS capture tuple is not exact"
        )
    command = (
        f"sudo -n /usr/bin/tcpdump -i {interface} -n -U -s 0 "
        "-c 6 -w - udp and port 53"
    )
    return _remote_ssh_spec(
        session,
        plan=plan,
        role="packet-remote-capture",
        remote_command=command,
        stdout_limit=1024 * 1024,
        stderr_limit=64 * 1024,
    )


def _send_spec(
    repository: Path,
    *,
    case_id: str,
    stage: str,
    plan: PacketEndpointPlan,
    local: ObservedLocalEndpoint,
    token: str,
) -> CommandSpec:
    spec = REQUIRED_CASES[case_id]
    try:
        local_address = ipaddress.ip_address(local.address)
    except ValueError as error:
        raise PacketCaptureAdapterError(
            "local_endpoint_invalid", "derived local endpoint address is invalid"
        ) from error
    expected_version = 4 if spec.family == "ipv4" else 6
    direct_stage = (
        case_id in {"excluded-routes", "lan-bypass"}
        or case_id in {"stop-cleanup", "ipv6-disabled-absence"}
        and stage == "target"
    )
    expected_local_interface = "non-utun" if direct_stage else "utun*"
    if (
        local_address.version != expected_version
        or (
            expected_local_interface == "non-utun"
            and local.interface_name.startswith("utun")
        )
        or (
            expected_local_interface == "utun*"
            and not local.interface_name.startswith("utun")
        )
    ):
        raise PacketCaptureAdapterError(
            "local_endpoint_invalid",
            "derived local endpoint differs from the source-pinned interface policy",
        )
    helper = repository / "scripts/physical_capture/packet_sender.py"
    quic_version = 1 if spec.protocol == "quic" else 0
    if stage not in {"start", "target", "end"}:
        raise PacketCaptureAdapterError(
            "send_stage_invalid", "Packet sender stage is not source-owned"
        )
    absence_window = (
        3000
        if not spec.token_observed and stage == "target"
        else 0
    )
    identity = (
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        str(helper),
        "--case",
        case_id,
        "--stage",
        stage,
        "--protocol",
        spec.protocol,
        "--family",
        spec.family,
        "--resolver-role",
        spec.resolver_role,
    )
    remote_address = _resolved_remote_address(plan)
    socket_arguments = (
        ()
        if spec.protocol == "dns"
        else (
            "--local-address",
            str(local_address),
            "--local-port",
            "0",
            "--remote-address",
            remote_address,
            "--remote-port",
            str(plan.remote_port),
        )
    )
    evidence_arguments = (
        "--token",
        token,
        "--quic-version",
        str(quic_version),
        "--absence-window-ms",
        str(absence_window),
    )
    return CommandSpec(
        role=f"packet-send-{spec.protocol}-{stage}",
        argv=identity + socket_arguments + evidence_arguments,
        cwd=repository,
        timeout_seconds=PACKET_CAPTURE_TIMEOUT_SECONDS,
        stdout_limit=64 * 1024,
        stderr_limit=64 * 1024,
    )


def _recorded_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _capture_timestamp(value: object) -> str:
    numerator = getattr(value, "numerator", None)
    denominator = getattr(value, "denominator", None)
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise PacketCaptureAdapterError(
            "capture_timestamp_invalid", "pcap marker timestamp is not an exact fraction"
        )
    seconds, remainder = divmod(numerator, denominator)
    microseconds, residual = divmod(remainder * 1_000_000, denominator)
    if residual:
        raise PacketCaptureAdapterError(
            "capture_timestamp_invalid", "pcap marker timestamp is not microsecond-exact"
        )
    try:
        value = datetime.fromtimestamp(seconds, timezone.utc).replace(
            microsecond=microseconds
        )
    except (OverflowError, OSError, ValueError) as error:
        raise PacketCaptureAdapterError(
            "capture_timestamp_invalid", "pcap marker timestamp is outside UTC range"
        ) from error
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _case_tokens(seen: set[str]) -> tuple[str, str, str]:
    tokens: list[str] = []
    prefixes = {token[:4] for token in seen}
    for stage_prefix in ("s", "t", "e"):
        for _attempt in range(128):
            token = stage_prefix + secrets.token_hex(16)[:19]
            if token not in seen and token[:4] not in prefixes:
                seen.add(token)
                prefixes.add(token[:4])
                tokens.append(token)
                break
        else:
            raise PacketCaptureAdapterError(
                "packet_token_generation_failed",
                "unique Packet token generation exhausted its fixed attempt bound",
            )
    return tokens[0], tokens[1], tokens[2]


def _parse_route_interface(stdout: str) -> str:
    interfaces = re.findall(r"^\s*interface:\s*(\S+)\s*$", stdout, re.MULTILINE)
    if len(interfaces) != 1 or re.fullmatch(
        r"[A-Za-z][A-Za-z0-9._-]{0,31}", interfaces[0]
    ) is None:
        raise PacketCaptureAdapterError(
            "route_observation_invalid", "route output does not select one canonical interface"
        )
    return interfaces[0]


def _parse_interface(stdout: str, *, expected_name: str) -> ObservedNetworkInterface:
    lines = stdout.splitlines()
    if not lines:
        raise PacketCaptureAdapterError(
            "interface_observation_invalid", "ifconfig output is empty"
        )
    match = re.fullmatch(
        rf"{re.escape(expected_name)}: flags=[0-9a-fA-F]+<([^>]+)> "
        r"mtu [0-9]+ index ([0-9]+)(?: .*)?",
        lines[0],
    )
    if match is None:
        raise PacketCaptureAdapterError(
            "interface_observation_invalid", "ifconfig first line is not canonical"
        )
    flags = tuple(match.group(1).split(","))
    if len(set(flags)) != len(flags) or not {"UP", "RUNNING"} <= set(flags):
        raise PacketCaptureAdapterError(
            "interface_observation_invalid", "route-selected interface is not ready"
        )
    addresses: dict[str, list[str]] = {"ipv4": [], "ipv6": []}
    for raw in lines[1:]:
        line = raw.strip()
        family = "ipv4" if line.startswith("inet ") else "ipv6" if line.startswith("inet6 ") else None
        if family is None:
            continue
        text = line.split()[1].split("%", 1)[0]
        try:
            address = ipaddress.ip_address(text)
        except ValueError as error:
            raise PacketCaptureAdapterError(
                "interface_observation_invalid", "ifconfig contains an invalid address"
            ) from error
        if address.is_link_local:
            continue
        marker = " temporary "
        if family == "ipv6" and marker in f" {line} ":
            continue
        addresses[family].append(str(address))
    for values in addresses.values():
        values.sort()
    return ObservedNetworkInterface(
        name=expected_name,
        index=int(match.group(2)),
        link_type=0 if expected_name.startswith("utun") else 1,
        flags=flags,
        addresses={key: tuple(value) for key, value in addresses.items()},
    )


def _parse_remote_interface(
    stdout: str, *, expected_name: str
) -> ObservedNetworkInterface:
    lines = stdout.splitlines()
    first = lines[0] if lines else ""
    match = re.fullmatch(
        rf"{re.escape(expected_name)}: flags=[0-9a-fA-F]+<([^>]+)>\s+"
        r"mtu [0-9]+(?:\s+.*)?",
        first,
    )
    index_match = re.search(r"(?:^|\s)index ([0-9]+)(?:\s|$)", first)
    if match is None or index_match is None:
        raise PacketCaptureAdapterError(
            "remote_interface_observation_invalid",
            "remote ifconfig output lacks exact flags and kernel index",
        )
    flags = tuple(match.group(1).split(","))
    if len(set(flags)) != len(flags) or not {"UP", "RUNNING"} <= set(flags):
        raise PacketCaptureAdapterError(
            "remote_interface_observation_invalid", "remote capture interface is not ready"
        )
    return ObservedNetworkInterface(
        name=expected_name,
        index=int(index_match.group(1)),
        link_type=1,
        flags=flags,
        addresses={"ipv4": (), "ipv6": ()},
    )


def _select_local_address(
    interface: ObservedNetworkInterface, *, family: str, direct: bool
) -> str:
    values = interface.addresses[family]
    expected_tunnel = TUNNEL_CAPTURE_LOCAL_ADDRESSES[family]
    if direct:
        values = tuple(value for value in values if value != expected_tunnel)
        if len(values) != 1:
            raise PacketCaptureAdapterError(
                "local_endpoint_ambiguous",
                "physical route interface does not have one stable non-link-local address",
            )
        return values[0]
    if values != (expected_tunnel,):
        raise PacketCaptureAdapterError(
            "local_endpoint_invalid",
            "tunnel route interface does not expose the source-pinned tunnel address",
        )
    return expected_tunnel


def _host_snapshot_mapping(snapshot: PacketHostSnapshot) -> dict[str, object]:
    return {
        "config_digest": snapshot.config_digest,
        "desired_mode": snapshot.desired_mode,
        "generation": snapshot.generation,
        "ipv6_enabled": snapshot.ipv6_enabled,
        "owner": snapshot.owner,
        "phase": snapshot.phase,
        "ready": snapshot.ready,
    }


def _require_observation_matches_host(
    observation: PacketStateObservation,
    snapshot: PacketHostSnapshot,
    sequence: int,
) -> None:
    if observation.sequence != sequence or dict(observation.state) != _host_snapshot_mapping(snapshot):
        raise PacketCaptureAdapterError(
            "product_observation_host_mismatch",
            "Unified Log state differs from the authenticated Host stage",
        )


def _require_baseline(snapshot: PacketHostSnapshot) -> None:
    if (
        snapshot.desired_mode != "tunnel"
        or snapshot.phase != "tunnel_active"
        or snapshot.owner != "packet_tunnel_system_extension"
        or snapshot.ready is not True
        or snapshot.ipv6_enabled is not True
        or snapshot.generation < 1
        or snapshot.config_digest is None
    ):
        raise PacketCaptureAdapterError(
            "packet_baseline_invalid", "Host baseline is not one ready IPv6 tunnel"
        )


def _same_effective_snapshot(
    left: PacketHostSnapshot, right: PacketHostSnapshot
) -> bool:
    left_value = _host_snapshot_mapping(left)
    right_value = _host_snapshot_mapping(right)
    del left_value["generation"]
    del right_value["generation"]
    return left_value == right_value


def _private_key_write(path: Path, data: bytes) -> None:
    if not data or len(data) > PACKET_PRIVATE_KEY_MAXIMUM:
        raise PacketCaptureAdapterError(
            "remote_key_invalid", "generated remote key bytes are outside the bound"
        )
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short private-key write")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OSError("unsafe private-key file identity")
    except OSError as error:
        raise PacketCaptureAdapterError(
            "remote_key_write_failed", "ephemeral remote key cannot be stored safely"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _remove_private_key_files(path: Path) -> None:
    parent_fd = -1
    try:
        try:
            parent_fd = os.open(
                path.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except FileNotFoundError:
            return
        for name in (path.name, f"{path.name}.pub"):
            try:
                metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
            ):
                raise OSError("unsafe ephemeral key cleanup target")
            os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as error:
        raise PacketCaptureAdapterError(
            "remote_key_cleanup_failed", "ephemeral remote key cleanup could not be proven"
        ) from error
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


class _PacketCaseCoordinator:
    """Own one case's capture resources across authenticated Host stages."""

    def __init__(
        self,
        *,
        session: PhysicalCaptureSession,
        context: object,
        case_id: str,
        plan: PacketEndpointPlan,
        tokens: tuple[str, str, str],
    ) -> None:
        self.session = session
        self.context = context
        self.spec = REQUIRED_CASES[case_id]
        self.capture_boundary = session.observation_capture()
        self.runtime = PacketCaseRuntime(case_id, plan, tokens)
        self.failed = False

    def _admit_ios_lan_peer(self) -> None:
        if self.runtime.case_id != "lan-bypass":
            return
        try:
            if (
                self.runtime.plan.remote_address is not None
                or self.runtime.plan.runtime_endpoint_source
                != ios_packet_lan_peer_adapter.READY_DOCUMENT
            ):
                raise PacketCaptureAdapterError(
                    "lan_peer_endpoint_unresolved",
                    "iPhone LAN endpoint policy is not runtime-bound",
                )
            self.runtime.ios_peer_lease = (
                ios_packet_lan_peer_adapter.admit_ios_packet_lan_peer(
                runner=self.capture_boundary,
                    tokens=self.runtime.tokens,
                    expected_source=SOURCE_IOS_LAN_PEER_IDENTITY,
                )
            )
            self.runtime.ios_peer_admission = self.runtime.ios_peer_lease.as_document()
            self.runtime.plan = replace(
                self.runtime.plan,
                remote_address=self.runtime.ios_peer_lease.peer_ipv4,
            )
        except ios_packet_lan_peer_adapter.IOSPacketLanPeerError as error:
            raise PacketCaptureAdapterError(
                "lan_peer_admission_failed",
                "the source-pinned iPhone LAN peer could not be admitted",
            ) from error

    def _revalidate_ios_peer_before_capture(self) -> None:
        lease = self.runtime.ios_peer_lease
        if self.runtime.case_id != "lan-bypass" or lease is None:
            return
        try:
            self.runtime.ios_peer_before_capture = lease.revalidate_before_capture()
        except ios_packet_lan_peer_adapter.IOSPacketLanPeerError as error:
            raise PacketCaptureAdapterError(
                "lan_peer_before_capture_failed",
                "iPhone LAN peer identity drifted before packet capture",
            ) from error

    def _revalidate_ios_peer_after_capture(self) -> None:
        lease = self.runtime.ios_peer_lease
        if self.runtime.case_id != "lan-bypass" or lease is None:
            return
        try:
            if self.runtime.stages is None:
                raise PacketCaptureAdapterError(
                    "packet_stage_set_invalid",
                    "Packet sender stages are unavailable for iPhone reconciliation",
                )
            self.runtime.ios_peer_after_capture = lease.revalidate_after_capture(
                self.runtime.stages
            )
        except ios_packet_lan_peer_adapter.IOSPacketLanPeerError as error:
            raise PacketCaptureAdapterError(
                "lan_peer_after_capture_failed",
                "iPhone LAN peer result did not reconcile after packet capture",
            ) from error

    def _close_ios_peer(self) -> None:
        lease = self.runtime.ios_peer_lease
        if self.runtime.case_id != "lan-bypass" or lease is None:
            return
        try:
            self.runtime.ios_peer_admission = lease.as_document()
            self.runtime.ios_peer_cleanup = lease.close_with_receipt()
        except Exception as error:
            raise PacketCaptureAdapterError(
                "lan_peer_cleanup_failed",
                "iPhone LAN peer cleanup could not be proven",
            ) from error
        finally:
            if lease.is_closed:
                self.runtime.ios_peer_lease = None

    def _start_capture(self) -> None:
        runtime = self.runtime
        if self.spec.protocol == "dns":
            self._prepare_remote_access()
            capture_spec = _remote_capture_spec(self.session, plan=runtime.plan)
            readiness = ReadinessSpec(
                stream="stderr",
                line=PACKET_REMOTE_CAPTURE_READY,
                timeout_seconds=PACKET_CAPTURE_READINESS_SECONDS,
            )
        else:
            capture_spec = _capture_spec(
                self.session.archive.repository,
                case_id=runtime.case_id,
                tokens=runtime.tokens,
                lan_endpoint_address=(
                    _resolved_remote_address(runtime.plan)
                    if runtime.case_id == "lan-bypass"
                    else None
                ),
            )
            readiness = ReadinessSpec(
                stream="stderr",
                line=PACKET_LOCAL_CAPTURE_READY,
                timeout_seconds=PACKET_CAPTURE_READINESS_SECONDS,
            )
        command = self.capture_boundary.start_command(capture_spec)
        try:
            command.wait_for_readiness(readiness)
        except BaseException:
            command.cancel()
            raise
        runtime.capture_spec = capture_spec
        runtime.capture = command
        runtime.capture_alive_at = _recorded_now()

    def _prepare_remote_access(self) -> None:
        runtime = self.runtime
        key_path = _remote_key_path(self.session)
        self.session.archive.ensure_directory("runtime/packet-remote-capture")
        generation_spec = _remote_key_generation_spec(self.session)
        generation_result = self.capture_boundary.run_command(generation_spec)
        if re.fullmatch(rb"[.+*\n]*", generation_result.stderr) is None:
            raise PacketCaptureAdapterError(
                "remote_key_generation_failed",
                "OpenSSL key generation emitted an unexpected diagnostic",
            )
        runtime.key_generation = _command_receipt(
            generation_result,
            generation_spec,
            output_limit=PACKET_PRIVATE_KEY_MAXIMUM,
            binary_stdout=True,
        )
        _private_key_write(key_path, generation_result.stdout)
        public_spec = _remote_public_key_spec(self.session)
        public_result = self.capture_boundary.run_command(public_spec)
        public_receipt = _command_receipt(
            public_result, public_spec, output_limit=16 * 1024
        )
        public_text = public_receipt["stdout"]
        if (
            not isinstance(public_text, str)
            or re.fullmatch(r"ssh-rsa [A-Za-z0-9+/]+={0,2}\n", public_text) is None
            or public_receipt["stderr"]
        ):
            raise PacketCaptureAdapterError(
                "remote_public_key_invalid", "derived SSH public key is not canonical RSA"
            )
        _private_key_write(Path(f"{key_path}.pub"), public_result.stdout)
        runtime.public_key = public_receipt
        import_spec = _remote_key_import_spec(self.session, plan=runtime.plan)
        import_result = self.capture_boundary.run_command(import_spec)
        runtime.key_import = _command_receipt(
            import_result, import_spec, output_limit=64 * 1024
        )
        if (
            runtime.key_import["stdout"]
            != f"{PACKET_CAPTURE_SERVICE_ACCOUNT_UNIQUE_ID}\n"
            or runtime.key_import["stderr"]
        ):
            raise PacketCaptureAdapterError(
                "remote_key_import_invalid", "OS Login key import receipt is not exact"
            )
        interface_spec = _remote_interface_spec(self.session, plan=runtime.plan)
        interface_result = self.capture_boundary.run_command(interface_spec)
        runtime.remote_interface_command = _command_receipt(
            interface_result, interface_spec, output_limit=256 * 1024
        )
        if runtime.remote_interface_command["stderr"]:
            raise PacketCaptureAdapterError(
                "remote_interface_observation_invalid",
                "remote interface observation emitted stderr",
            )
        remote_interface = _parse_remote_interface(
            runtime.remote_interface_command["stdout"], expected_name="ens4"
        )
        runtime.remote_interface = remote_interface.as_dict()

    def _run_stage(self, stage: str, token: str, host_stage: str) -> None:
        runtime = self.runtime
        remote_address = _resolved_remote_address(runtime.plan)
        route_spec = _route_spec(
            self.session.archive.repository, remote_address
        )
        route_result = self.capture_boundary.run_command(route_spec)
        route_receipt = _command_receipt(route_result, route_spec, output_limit=64 * 1024)
        if route_receipt["stderr"]:
            raise PacketCaptureAdapterError(
                "route_observation_invalid", "route observation emitted stderr"
            )
        interface_name = _parse_route_interface(route_receipt["stdout"])
        interface_spec = _interface_spec(
            self.session.archive.repository,
            interface_name,
            role="packet-send-interface-observation",
        )
        interface_result = self.capture_boundary.run_command(interface_spec)
        interface_receipt = _command_receipt(
            interface_result, interface_spec, output_limit=256 * 1024
        )
        if interface_receipt["stderr"]:
            raise PacketCaptureAdapterError(
                "interface_observation_invalid", "ifconfig observation emitted stderr"
            )
        interface = _parse_interface(
            interface_receipt["stdout"], expected_name=interface_name
        )
        direct = (
            runtime.case_id in {"lan-bypass", "excluded-routes"}
            or runtime.case_id in {"stop-cleanup", "ipv6-disabled-absence"}
            and stage == "target"
        )
        local_address = _select_local_address(
            interface, family=self.spec.family, direct=direct
        )
        send_spec = _send_spec(
            self.session.archive.repository,
            case_id=runtime.case_id,
            stage=stage,
            plan=runtime.plan,
            local=ObservedLocalEndpoint(local_address, interface_name),
            token=token,
        )
        send_result = self.capture_boundary.run_command(send_spec)
        send_receipt = _command_receipt(send_result, send_spec, output_limit=64 * 1024)
        if send_receipt["stderr"]:
            raise PacketCaptureAdapterError(
                "packet_send_failed", "fixed packet sender emitted stderr"
            )
        try:
            result = load_json_bytes(send_result.stdout, f"{runtime.case_id}.{stage} send")
            if canonical_json(result) + b"\n" != send_result.stdout:
                raise RawArtifactError("sender output is not canonical JSON")
        except RawArtifactError as error:
            raise PacketCaptureAdapterError(
                "packet_send_result_invalid", "fixed packet sender result is not canonical"
            ) from error
        endpoint_set: list[dict[str, object]] | None
        if self.spec.protocol == "dns":
            endpoint_set = None
        else:
            if (
                not isinstance(result, dict)
                or result.get("local_address") != local_address
                or type(result.get("local_port")) is not int
                or not 49152 <= result["local_port"] <= 65535
                or result.get("remote_address") != remote_address
                or result.get("remote_port") != runtime.plan.remote_port
            ):
                raise PacketCaptureAdapterError(
                    "packet_send_result_invalid", "sender endpoint receipt differs"
                )
            transport = "tcp" if self.spec.protocol == "tcp" else "udp"
            endpoint_set = [
                {
                    "role": "local",
                    "address": local_address,
                    "port": result["local_port"],
                    "transport": transport,
                },
                {
                    "role": "remote",
                    "address": remote_address,
                    "port": runtime.plan.remote_port,
                    "transport": transport,
                },
            ]
        if runtime.stages is None:
            raise PacketCaptureAdapterError(
                "packet_runtime_invalid", "Packet stage accumulator is unavailable"
            )
        runtime.stages.append(
            {
                "stage": stage,
                "host_stage": host_stage,
                "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
                "endpoint_set": endpoint_set,
                "route_command": route_receipt,
                "interface_command": interface_receipt,
                "interface": interface.as_dict(),
                "command": send_receipt,
            }
        )

    def begin_capture(self, baseline: PacketHostBaseline) -> PacketCaptureDisposition:
        try:
            if baseline.case_id != self.runtime.case_id:
                raise PacketCaptureAdapterError(
                    "host_case_mismatch", "Host baseline case differs"
                )
            _require_baseline(baseline.baseline)
            self.runtime.baseline_host = baseline
            self._admit_ios_lan_peer()
            self._start_capture()
            self._revalidate_ios_peer_before_capture()
            for index, host_stage in enumerate(CASE_STAGE_PLANS[self.runtime.case_id]):
                if host_stage == "baseline":
                    self._run_stage(("start", "target", "end")[index], self.runtime.tokens[index], host_stage)
            return PacketCaptureDisposition.COMPLETE
        except Exception:
            self.failed = True
            raise

    def exercise_test(self, test: PacketHostTestReady) -> PacketCaptureDisposition:
        try:
            if test.case_id != self.runtime.case_id:
                raise PacketCaptureAdapterError("host_case_mismatch", "Host test case differs")
            self.runtime.test_host = test
            observed = capture_product_state_observation(
                session=self.session,
                context=self.context,
                case_id=self.runtime.case_id,
            )
            _require_observation_matches_host(
                observed, test.test, test.test_observation_sequence
            )
            self.runtime.test_state = observed
            for index, host_stage in enumerate(CASE_STAGE_PLANS[self.runtime.case_id]):
                if host_stage == "test":
                    self._run_stage(("start", "target", "end")[index], self.runtime.tokens[index], host_stage)
            return PacketCaptureDisposition.COMPLETE
        except Exception:
            self.failed = True
            raise

    def finish_capture(
        self, restored: PacketHostRestored | PacketHostAborted
    ) -> PacketCaptureDisposition:
        try:
            if isinstance(restored, PacketHostAborted):
                self.failed = True
                self.cleanup()
                return PacketCaptureDisposition.COMPLETE
            self.runtime.restored_host = restored
            if self.failed:
                self.cleanup()
                return PacketCaptureDisposition.CANCELLED
            if (
                restored.case_id != self.runtime.case_id
                or self.runtime.baseline_host is None
                or restored.baseline != self.runtime.baseline_host.baseline
                or self.runtime.test_host is None
                or restored.test != self.runtime.test_host.test
                or not _same_effective_snapshot(restored.restore, restored.baseline)
                or not (
                    restored.baseline.generation
                    < restored.test.generation
                    < restored.restore.generation
                )
                or restored.restore_observation_sequence
                <= restored.baseline_observation_sequence
            ):
                raise PacketCaptureAdapterError(
                    "host_restore_mismatch", "Host restored stage differs from baseline"
                )
            if not self.spec.token_observed:
                observed = capture_product_state_observation(
                    session=self.session,
                    context=self.context,
                    case_id=self.runtime.case_id,
                    restored=True,
                )
                _require_observation_matches_host(
                    observed, restored.restore, restored.restore_observation_sequence
                )
                self.runtime.restore_state = observed
            for index, host_stage in enumerate(CASE_STAGE_PLANS[self.runtime.case_id]):
                if host_stage == "restored":
                    self._run_stage(("start", "target", "end")[index], self.runtime.tokens[index], host_stage)
            self._finish_and_archive_capture()
            self._revalidate_ios_peer_after_capture()
            self._close_ios_peer()
            self._cleanup_keys()
            return PacketCaptureDisposition.COMPLETE
        except Exception:
            self.failed = True
            raise

    def _finish_and_archive_capture(self) -> None:
        runtime = self.runtime
        if runtime.capture is None or runtime.capture_spec is None:
            raise PacketCaptureAdapterError(
                "packet_capture_missing", "Packet capture command was not started"
            )
        result = runtime.capture.finish()
        runtime.capture = None
        runtime.capture_receipt = _command_receipt(
            result,
            runtime.capture_spec,
            output_limit=1024 * 1024,
            binary_stdout=True,
        )
        if not result.stdout:
            raise PacketCaptureAdapterError(
                "packet_capture_empty", "Packet capture command produced no pcap bytes"
            )
        runtime.capture_artifact = self.capture_boundary.write_bytes(
            subject=runtime.case_id,
            kind="packet-pcap",
            relative=f"{OBSERVATION_DIRECTORY}/{runtime.case_id}.pcap",
            data=result.stdout,
        )
        if self.spec.protocol == "dns":
            endpoints = dns_stage_endpoints(
                result.stdout,
                "packet-pcap",
                family=self.spec.family,
                remote_address=_resolved_remote_address(runtime.plan),
                tokens=tuple(token.encode("ascii") for token in runtime.tokens),
            )
            if runtime.stages is None or len(runtime.stages) != 3:
                raise PacketCaptureAdapterError(
                    "packet_stage_set_invalid", "DNS sender stages are incomplete"
                )
            by_name = {stage["stage"]: stage for stage in runtime.stages}
            for endpoint in endpoints:
                by_name[endpoint.stage]["endpoint_set"] = [
                    {
                        "role": "local",
                        "address": endpoint.local_address,
                        "port": endpoint.local_port,
                        "transport": "udp",
                    },
                    {
                        "role": "remote",
                        "address": endpoint.remote_address,
                        "port": endpoint.remote_port,
                        "transport": "udp",
                    },
                ]

    def _cleanup_keys(self) -> None:
        if self.spec.protocol == "dns":
            _remove_private_key_files(_remote_key_path(self.session))

    def cleanup(self) -> None:
        cleanup_error: Exception | None = None
        if self.runtime.capture is not None:
            try:
                self.runtime.capture.cancel()
            except Exception as error:
                cleanup_error = error
            self.runtime.capture = None
        if self.runtime.ios_peer_lease is not None:
            lease = self.runtime.ios_peer_lease
            try:
                self.runtime.ios_peer_cleanup = lease.abort()
            except Exception as error:
                if lease.is_closed:
                    self.runtime.ios_peer_lease = None
                cleanup_error = cleanup_error or error
            else:
                self.runtime.ios_peer_lease = None
        if self.spec.protocol == "dns":
            try:
                _remove_private_key_files(_remote_key_path(self.session))
            except Exception as error:
                cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            raise PacketCaptureAdapterError(
                "packet_cleanup_failed", "Packet case resource cleanup failed"
            ) from cleanup_error

    def finalize(self, receipt: PacketHostReceipt) -> dict[str, dict[str, object]]:
        runtime = self.runtime
        if (
            self.failed
            or runtime.capture_artifact is None
            or runtime.capture_receipt is None
            or runtime.capture_spec is None
            or runtime.capture_alive_at is None
            or runtime.test_state is None
            or runtime.baseline_host is None
            or runtime.test_host is None
            or runtime.restored_host is None
            or runtime.stages is None
            or len(runtime.stages) != 3
            or receipt.case_id != runtime.case_id
            or receipt.baseline != runtime.baseline_host.baseline
            or receipt.test != runtime.test_host.test
            or receipt.restore != runtime.restored_host.restore
        ):
            raise PacketCaptureAdapterError(
                "packet_case_incomplete", "Host transaction did not produce one complete case"
            )
        stages = sorted(
            runtime.stages,
            key=lambda stage: ("start", "target", "end").index(stage["stage"]),
        )
        if [stage["stage"] for stage in stages] != ["start", "target", "end"] or any(
            stage["endpoint_set"] is None for stage in stages
        ):
            raise PacketCaptureAdapterError(
                "packet_stage_set_invalid", "Packet sender stage set is incomplete"
            )
        capture_bytes = self.session.archive.read_bytes(
            runtime.capture_artifact.descriptor.path,
            maximum=1024 * 1024,
        )
        endpoints = tuple(
            StagedCaptureEndpoint(
                stage=stage["stage"],
                local_address=stage["endpoint_set"][0]["address"],
                local_port=stage["endpoint_set"][0]["port"],
                remote_address=stage["endpoint_set"][1]["address"],
                remote_port=stage["endpoint_set"][1]["port"],
            )
            for stage in stages
        )
        try:
            started_at, completed_at = staged_marker_window(
                capture_bytes,
                runtime.capture_artifact.descriptor.kind,
                protocol=self.spec.protocol,
                family=self.spec.family,
                endpoints=endpoints,
                start_marker=runtime.tokens[0].encode("ascii"),
                end_marker=runtime.tokens[2].encode("ascii"),
            )
        except PacketCaptureError as error:
            raise PacketCaptureAdapterError(
                "packet_capture_invalid", "pcap marker window cannot be proven"
            ) from error
        host_transaction = {
            "session_id": receipt.session_id,
            "baseline": _host_snapshot_mapping(receipt.baseline),
            "baseline_observation_sequence": receipt.baseline_observation_sequence,
            "test": _host_snapshot_mapping(receipt.test),
            "test_observation_sequence": receipt.test_observation_sequence,
            "restore": _host_snapshot_mapping(receipt.restore),
            "restore_observation_sequence": receipt.restore_observation_sequence,
            "candidate_observation_sequence": receipt.candidate_observation_sequence,
        }
        capture_filter = list(
            packet_capture_filter_argv(
                case_id=runtime.case_id,
                tokens=runtime.tokens,
                lan_endpoint_address=(
                    _resolved_remote_address(runtime.plan)
                    if runtime.case_id == "lan-bypass"
                    else None
                ),
            )
        )
        remote_fields = self._remote_provenance_fields()
        provenance = {
            "schema_version": 4,
            "document": PACKET_PROVENANCE_DOCUMENT,
            "case_id": runtime.case_id,
            "state_observation_sha256": runtime.test_state.artifact.descriptor.sha256,
            "capture_artifact_sha256": runtime.capture_artifact.descriptor.sha256,
            "endpoint_identity_sha256": runtime.plan.endpoint_service_identity_sha256,
            "capture_device": (
                {
                    "name": "ens4",
                    "link_type": 1,
                    "scope": "exact-remote-interface",
                }
                if self.spec.protocol == "dns"
                else {
                    "name": PACKET_LOCAL_CAPTURE_DEVICE,
                    "link_type": PACKET_LOCAL_CAPTURE_LINK_TYPE,
                    "scope": "all-interfaces-source-filtered-raw",
                }
            ),
            "capture_point": self.spec.vantage,
            "resolver_role": self.spec.resolver_role,
            "capture_filter_argv": capture_filter,
            "capture_filter_sha256": hashlib.sha256(
                canonical_json(capture_filter)
            ).hexdigest(),
            **remote_fields,
            "capture_command": runtime.capture_receipt,
            "capture_alive_at": runtime.capture_alive_at,
            "started_at": _capture_timestamp(started_at),
            "completed_at": _capture_timestamp(completed_at),
            "quic_version": 1 if self.spec.protocol == "quic" else None,
            "host_transaction": host_transaction,
        }
        runtime.provenance_artifact = self.capture_boundary.write_bytes(
            subject=f"{runtime.case_id}:capture-provenance",
            kind="packet-capture-provenance",
            relative=f"{OBSERVATION_DIRECTORY}/{runtime.case_id}-capture-provenance.json",
            data=canonical_json(provenance) + b"\n",
        )
        attempt = {
            "schema_version": 4,
            "document": PACKET_ATTEMPT_DOCUMENT,
            "case_id": runtime.case_id,
            "state_observation_sha256": runtime.test_state.artifact.descriptor.sha256,
            "capture_provenance_sha256": runtime.provenance_artifact.descriptor.sha256,
            "stages": stages,
            "recorded_at": _recorded_now(),
            "absence_window_completed_at": (
                None
                if self.spec.token_observed
                else stages[1]["command"]["completed_at"]
            ),
        }
        runtime.attempt_artifact = self.capture_boundary.write_bytes(
            subject=f"{runtime.case_id}:send-attempt",
            kind="packet-send-attempt",
            relative=f"{OBSERVATION_DIRECTORY}/{runtime.case_id}-send-attempt.json",
            data=canonical_json(attempt) + b"\n",
        )
        result = {
            runtime.capture_artifact.subject: runtime.capture_artifact.descriptor.as_dict(),
            **runtime.test_state.descriptor_mapping(),
            runtime.provenance_artifact.subject: runtime.provenance_artifact.descriptor.as_dict(),
            runtime.attempt_artifact.subject: runtime.attempt_artifact.descriptor.as_dict(),
        }
        if runtime.restore_state is not None:
            result.update(runtime.restore_state.descriptor_mapping())
        return result

    def _remote_provenance_fields(self) -> dict[str, object]:
        runtime = self.runtime
        if runtime.case_id == "lan-bypass":
            if any(
                value is None
                for value in (
                    runtime.ios_peer_admission,
                    runtime.ios_peer_before_capture,
                    runtime.ios_peer_after_capture,
                    runtime.ios_peer_cleanup,
                )
            ):
                raise PacketCaptureAdapterError(
                    "lan_peer_provenance_incomplete",
                    "iPhone LAN peer admission and cleanup receipts are incomplete",
                )
            peer_ipv4 = _resolved_remote_address(runtime.plan)
            return {
                "remote_key_generation_command": None,
                "remote_public_key_command": None,
                "remote_key_import_command": None,
                "remote_interface": None,
                "remote_interface_command": None,
                "remote_access": {
                    "schema_version": 1,
                    "document": ios_packet_lan_peer_adapter.PROVENANCE_DOCUMENT,
                    "evidence_role": ios_packet_lan_peer_adapter.EVIDENCE_ROLE,
                    "claim_eligible": False,
                    "source_identity_sha256": (
                        SOURCE_IOS_LAN_PEER_IDENTITY.identity_sha256
                    ),
                    "source_identity_file_sha256": (
                        SOURCE_IOS_LAN_PEER_IDENTITY.file_sha256
                    ),
                    "runtime_endpoint_source": (
                        runtime.plan.runtime_endpoint_source
                    ),
                    "network": {
                        "interface_name": "en0",
                        "ipv4": peer_ipv4,
                        "listener_port": ios_packet_lan_peer_adapter.LISTENER_PORT,
                        "transport": ios_packet_lan_peer_adapter.TRANSPORT,
                    },
                    "admission": runtime.ios_peer_admission,
                    "before_capture": runtime.ios_peer_before_capture,
                    "after_capture": runtime.ios_peer_after_capture,
                    "cleanup": runtime.ios_peer_cleanup,
                },
                "capture_offload_context": "ios-coredevice-localnetwork-packet-peer-v1",
            }
        if self.spec.protocol != "dns":
            return {
                "remote_key_generation_command": None,
                "remote_public_key_command": None,
                "remote_key_import_command": None,
                "remote_interface": None,
                "remote_interface_command": None,
                "remote_access": None,
                "capture_offload_context": None,
            }
        if any(
            value is None
            for value in (
                runtime.key_generation,
                runtime.public_key,
                runtime.key_import,
                runtime.remote_interface,
                runtime.remote_interface_command,
            )
        ):
            raise PacketCaptureAdapterError(
                "remote_capture_incomplete", "remote capture setup receipt is incomplete"
            )
        project, zone, instance, instance_id = _remote_service_parts(runtime.plan)
        key_path = _remote_key_path(self.session)
        return {
            "remote_key_generation_command": runtime.key_generation,
            "remote_public_key_command": runtime.public_key,
            "remote_key_import_command": runtime.key_import,
            "remote_interface": runtime.remote_interface,
            "remote_interface_command": runtime.remote_interface_command,
            "remote_access": {
                "project": project,
                "zone": zone,
                "instance_name": instance,
                "instance_id": instance_id,
                "internal_ip_address": runtime.plan.remote_capture_internal_ipv4_address,
                "host_alias": f"compute.{instance_id}",
                "host_key_bytes_sha256": runtime.plan.remote_host_key_sha256,
                "service_account": PACKET_CAPTURE_SERVICE_ACCOUNT,
                "service_account_unique_id": PACKET_CAPTURE_SERVICE_ACCOUNT_UNIQUE_ID,
                "posix_username": PACKET_CAPTURE_POSIX_USERNAME,
                "os_login_profile_id": PACKET_CAPTURE_SERVICE_ACCOUNT_UNIQUE_ID,
                "known_hosts_snapshot_path": str(PACKET_KNOWN_HOSTS_PATH),
                "known_hosts_snapshot_sha256": PACKET_KNOWN_HOSTS_SHA256,
                "ssh_key_file_path": str(key_path),
                "ssh_key_file_path_sha256": hashlib.sha256(
                    str(key_path).encode("utf-8")
                ).hexdigest(),
                "gcloud_path": str(PACKET_GCLOUD_PATH),
                "sudoers_policy_sha256": PACKET_ENDPOINT_CAPTURE_SUDOERS_SHA256,
                "tcpdump_binary_sha256": _TCPDUMP_PACKAGE_SHA256,
                "private_key_size": runtime.key_generation["stdout_size"],
                "private_key_sha256": runtime.key_generation["stdout_sha256"],
                "public_key_sha256": runtime.public_key["stdout_sha256"],
            },
            "capture_offload_context": "linux-gce-tx-checksum-offload-prestack-v1",
        }


def capture_packet_observations(
    *,
    session: PhysicalCaptureSession,
    context: object,
) -> dict[str, dict[str, object]]:
    """Capture the exact 13-case matrix through the authenticated Host actor."""

    if not isinstance(session, PhysicalCaptureSession):
        raise PacketCaptureAdapterError(
            "invalid_session", "packet capture requires PhysicalCaptureSession"
        )
    try:
        session.require_collection_open()
        validated = validate_context(context)
    except (
        OSError,
        PhysicalCaptureSessionError,
        PhysicalCollectorRequestError,
    ) as error:
        raise PacketCaptureAdapterError(
            "packet_context_invalid", "packet matrix context/session is invalid"
        ) from error
    if UNRESOLVED_PACKET_CONTROLS or UNRESOLVED_PACKET_CASES:
        raise PacketCaptureAdapterError(
            "packet_source_policy_incomplete",
            "Packet production remains blocked by an unresolved source-owned case/control",
        )
    _revalidate_source_pins()
    _validate_endpoint_policy(SOURCE_PINNED_ENDPOINTS)
    descriptors: dict[str, dict[str, object]] = {}
    seen_tokens: set[str] = set()
    for case_id in REQUIRED_CASES:
        coordinator = _PacketCaseCoordinator(
            session=session,
            context=validated,
            case_id=case_id,
            plan=SOURCE_PINNED_ENDPOINTS[case_id],
            tokens=_case_tokens(seen_tokens),
        )
        try:
            receipt = run_fixed_host_transaction(
                case_id=case_id,
                begin_capture=coordinator.begin_capture,
                exercise_test=coordinator.exercise_test,
                finish_capture=coordinator.finish_capture,
            )
            case_descriptors = coordinator.finalize(receipt)
        except PacketCaptureAdapterError:
            raise
        except (
            OSError,
            PacketCaptureError,
            PacketHostError,
            PhysicalCaptureSessionError,
            PhysicalObservationError,
            ProbeExecutionError,
            RawArtifactError,
        ) as error:
            raise PacketCaptureAdapterError(
                "packet_case_failed",
                f"authenticated Packet case {case_id} failed closed",
            ) from error
        finally:
            coordinator.cleanup()
        overlap = set(descriptors) & set(case_descriptors)
        if overlap:
            raise PacketCaptureAdapterError(
                "packet_observation_set_invalid", "Packet case subjects overlap"
            )
        descriptors.update(case_descriptors)
    subjects = set(descriptors)
    paths = {
        descriptor.get("path")
        for descriptor in descriptors.values()
        if isinstance(descriptor, dict)
    }
    digests = {
        descriptor.get("sha256")
        for descriptor in descriptors.values()
        if isinstance(descriptor, dict)
    }
    if (
        not EXPECTED_PACKET_RAW_SUBJECTS <= subjects
        or not subjects
        <= EXPECTED_PACKET_RAW_SUBJECTS | OPTIONAL_PACKET_RAW_SUBJECTS
        or len(paths) != len(descriptors)
        or len(digests) != len(descriptors)
        or None in paths
        or None in digests
    ):
        raise PacketCaptureAdapterError(
            "packet_observation_set_invalid",
            "Packet raw subjects, paths, or digests are incomplete or reused",
        )
    session.require_collection_open()
    return descriptors


__all__ = [
    "PacketCaptureAdapterError",
    "PacketStateObservation",
    "capture_packet_observations",
    "capture_product_state_observation",
]
