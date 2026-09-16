"""Exact keychain entitlement contract for signed macOS release components."""

from collections.abc import Mapping
from typing import Any


KEYCHAIN_ACCESS_GROUPS = "keychain-access-groups"
APPLICATION_GROUPS = "com.apple.security.application-groups"
NETWORK_EXTENSION = "com.apple.developer.networking.networkextension"
SYSTEM_EXTENSION_INSTALL = "com.apple.developer.system-extension.install"
SUPPORTED_COMPONENT_KINDS = frozenset({"host", "packet-tunnel", "proxy-agent"})

# Enabling Network Extensions for a Developer ID App ID currently causes the
# portal to authorize the complete, Apple-defined macOS distribution set.  The
# signed product must still request only its reviewed role, but the profile is
# an authorization ceiling and is therefore expected to be a superset.
KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS = frozenset(
    {
        "app-proxy-provider-systemextension",
        "content-filter-provider-systemextension",
        "dns-proxy-systemextension",
        "dns-settings",
        "hotspot-provider",
        "packet-tunnel-provider-systemextension",
        "relay",
        "url-filter-provider",
    }
)


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


def _require_unique_string_list(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise EntitlementContractError(f"{label} must be a nonempty string allowlist")
    if len(set(value)) != len(value):
        raise EntitlementContractError(f"{label} contains duplicate entries")
    return value


def verify_profile_capability_authorizations(
    profile_entitlements: Mapping[str, Any],
    signed_entitlements: Mapping[str, Any],
    kind: str,
    team_id: str,
    expected_app_group: str,
) -> None:
    """Verify the profile ceiling while keeping signed capabilities minimal.

    Developer ID profiles authorize restricted entitlements; they are not an
    exact copy of the final code signature.  In particular, Apple's portal
    emits a Network Extension superset and may emit a Team-ID wildcard for the
    unrestricted macOS App Group entitlement.  Unknown or cross-product
    authorizations still fail closed.
    """
    if kind not in SUPPORTED_COMPONENT_KINDS:
        raise EntitlementContractError(f"unknown entitlement profile kind: {kind}")

    application_identifier_keys = {
        key
        for key in ("com.apple.application-identifier", "application-identifier")
        if key in profile_entitlements
    }
    if len(application_identifier_keys) != 1:
        raise EntitlementContractError(
            f"{kind} profile must contain exactly one application identifier entitlement"
        )

    allowed_keys = {
        "com.apple.developer.team-identifier",
        *application_identifier_keys,
        APPLICATION_GROUPS,
        KEYCHAIN_ACCESS_GROUPS,
    }
    if kind in {"host", "packet-tunnel"}:
        allowed_keys.add(NETWORK_EXTENSION)
    if kind == "host":
        allowed_keys.add(SYSTEM_EXTENSION_INSTALL)
    unexpected = set(profile_entitlements) - allowed_keys
    if unexpected:
        raise EntitlementContractError(
            f"{kind} profile contains unexpected entitlements: {sorted(unexpected)!r}"
        )

    profile_app_groups = profile_entitlements.get(APPLICATION_GROUPS)
    if profile_app_groups is not None:
        groups = _require_unique_string_list(
            profile_app_groups, f"{kind} profile entitlement {APPLICATION_GROUPS!r}"
        )
        team_prefix = f"{team_id}."
        if not expected_app_group.startswith(team_prefix):
            raise EntitlementContractError(
                "expected macOS App Group is not rooted at the signing Team ID"
            )
        registered_group = expected_app_group.removeprefix(team_prefix)
        allowed_groups = {expected_app_group, registered_group, f"{team_id}.*"}
        unauthorized_groups = sorted(set(groups) - allowed_groups)
        if unauthorized_groups:
            raise EntitlementContractError(
                f"{kind} profile entitlement {APPLICATION_GROUPS!r} contains "
                f"unrelated authorization: {unauthorized_groups!r}"
            )

    profile_network_extension = profile_entitlements.get(NETWORK_EXTENSION)
    signed_network_extension = signed_entitlements.get(NETWORK_EXTENSION)
    if kind in {"host", "packet-tunnel"}:
        authorized_roles = _require_unique_string_list(
            profile_network_extension,
            f"{kind} profile entitlement {NETWORK_EXTENSION!r}",
        )
        requested_roles = _require_unique_string_list(
            signed_network_extension,
            f"{kind} signed entitlement {NETWORK_EXTENSION!r}",
        )
        unknown_roles = sorted(
            set(authorized_roles) - KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS
        )
        if unknown_roles:
            raise EntitlementContractError(
                f"{kind} profile entitlement {NETWORK_EXTENSION!r} contains "
                f"unknown authorization: {unknown_roles!r}"
            )
        missing_roles = sorted(set(requested_roles) - set(authorized_roles))
        if missing_roles:
            raise EntitlementContractError(
                f"{kind} profile does not authorize signed Network Extension roles: "
                f"{missing_roles!r}"
            )
    elif profile_network_extension is not None:
        raise EntitlementContractError(
            "proxy-agent profile must not authorize Network Extensions"
        )

    profile_system_extension = profile_entitlements.get(SYSTEM_EXTENSION_INSTALL)
    if kind == "host":
        if profile_system_extension is not True:
            raise EntitlementContractError(
                "host profile must authorize System Extension installation"
            )
        if signed_entitlements.get(SYSTEM_EXTENSION_INSTALL) is not True:
            raise EntitlementContractError(
                "host signature must request System Extension installation"
            )
    elif SYSTEM_EXTENSION_INSTALL in profile_entitlements:
        raise EntitlementContractError(
            f"{kind} profile must not authorize System Extension installation"
        )
