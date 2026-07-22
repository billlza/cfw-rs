"""Exact keychain entitlement contract for signed macOS release components."""

from collections.abc import Mapping
from typing import Any


KEYCHAIN_ACCESS_GROUPS = "keychain-access-groups"
SUPPORTED_COMPONENT_KINDS = frozenset({"host", "packet-tunnel", "proxy-agent"})


class EntitlementContractError(ValueError):
    """Raised when a component exceeds its keychain trust boundary."""


def _host_group(expected_proxy_agent_group: str) -> str:
    suffix = ".proxy-agent"
    if not expected_proxy_agent_group.endswith(suffix):
        raise EntitlementContractError("proxy-agent Keychain group cannot derive the host group")
    return expected_proxy_agent_group[: -len(suffix)]


def _credential_group(expected_proxy_agent_group: str) -> str:
    return f"{_host_group(expected_proxy_agent_group)}.credentials"


def _expected_groups(kind: str, expected_proxy_agent_group: str) -> list[str]:
    credential_group = _credential_group(expected_proxy_agent_group)
    return {
        "host": [_host_group(expected_proxy_agent_group), credential_group],
        "proxy-agent": [expected_proxy_agent_group, credential_group],
    }[kind]


def verify_signed_keychain_access_group(
    entitlements: Mapping[str, Any],
    kind: str,
    expected_proxy_agent_group: str,
    expected_packet_tunnel_group: str,
) -> None:
    """Require exact user-context groups and no sysex Data Protection group."""
    if kind not in SUPPORTED_COMPONENT_KINDS:
        raise EntitlementContractError(f"unknown entitlement profile kind: {kind}")

    actual = entitlements.get(KEYCHAIN_ACCESS_GROUPS)
    if kind == "packet-tunnel":
        if actual is not None:
            raise EntitlementContractError(
                f"{kind} entitlement {KEYCHAIN_ACCESS_GROUPS!r} is {actual!r}; "
                "a system extension must not claim a Data Protection Keychain group"
            )
        return

    expected = _expected_groups(kind, expected_proxy_agent_group)
    if actual != expected:
        raise EntitlementContractError(
            f"{kind} entitlement {KEYCHAIN_ACCESS_GROUPS!r} is {actual!r}, "
            f"expected {expected!r}"
        )


def verify_profile_keychain_access_group(
    entitlements: Mapping[str, Any],
    kind: str,
    expected_proxy_agent_group: str,
    expected_packet_tunnel_group: str,
    team_id: str,
) -> None:
    """Ensure profile authorization cannot broaden a signed component boundary."""
    if kind not in SUPPORTED_COMPONENT_KINDS:
        raise EntitlementContractError(f"unknown entitlement profile kind: {kind}")
    if kind == "packet-tunnel":
        actual = entitlements.get(KEYCHAIN_ACCESS_GROUPS)
        if actual not in (None, [f"{team_id}.*"]):
            raise EntitlementContractError(
                f"{kind} profile entitlement {KEYCHAIN_ACCESS_GROUPS!r} is {actual!r}; "
                "only Apple's unused exact Team wildcard authorization is tolerated"
            )
        return
    expected_groups = _expected_groups(kind, expected_proxy_agent_group)
    actual = entitlements.get(KEYCHAIN_ACCESS_GROUPS)
    if (
        not isinstance(actual, list)
        or not actual
        or any(not isinstance(group, str) or not group for group in actual)
    ):
        raise EntitlementContractError(
            f"{kind} profile entitlement {KEYCHAIN_ACCESS_GROUPS!r} is {actual!r}; "
            "expected a nonempty string allowlist"
        )

    team_wildcard = f"{team_id}.*"
    product_groups = {
        _host_group(expected_proxy_agent_group),
        expected_proxy_agent_group,
        expected_packet_tunnel_group,
        _credential_group(expected_proxy_agent_group),
    }
    cross_component_groups = sorted((set(actual) & product_groups) - set(expected_groups))
    if cross_component_groups:
        raise EntitlementContractError(
            f"{kind} profile entitlement {KEYCHAIN_ACCESS_GROUPS!r} authorizes another "
            f"product component: {cross_component_groups!r}"
        )
    uncontrolled_wildcards = [
        group for group in actual if group == "*" or (group.endswith(".*") and group != team_wildcard)
    ]
    if uncontrolled_wildcards:
        raise EntitlementContractError(
            f"{kind} profile entitlement {KEYCHAIN_ACCESS_GROUPS!r} contains "
            f"uncontrolled wildcard authorization: {uncontrolled_wildcards!r}"
        )
    if team_wildcard not in actual and not set(expected_groups).issubset(actual):
        raise EntitlementContractError(
            f"{kind} profile entitlement {KEYCHAIN_ACCESS_GROUPS!r} is {actual!r}; "
            f"it must authorize {expected_groups!r} or {team_wildcard!r}"
        )
