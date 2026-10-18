#!/usr/bin/env python3
"""Generate exact frozen signing entitlements for native release components.

Only the fixed Proxy Agent and Packet Tunnel release roles are supported.  The
tracked entitlement file supplies functional grants, while an already-decoded
Developer ID profile supplies public Team/application identity.  No signing,
notarization, or secret-bearing Keychain operation occurs here.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from scripts.release_entitlement_contract import (
    EntitlementContractError,
    verify_profile_capability_authorizations,
    verify_profile_keychain_access_group,
    verify_signed_keychain_access_group,
)
from scripts.release_profile_entitlements import (
    APP_PREFIX,
    ReleaseProfileEntitlementError,
    TEAM_IDENTIFIER_KEY,
    TEAM_PREFIX,
    load_plist,
    read_regular_text,
    resolve_entitlement_prefixes,
    signing_identity_sha1,
    validate_release_profile,
    write_release_xcent,
)


TEAM_ID = "YKUPL7Z869"
HOST_BUNDLE_ID = "com.bill.clashformac"
APP_GROUP = f"{TEAM_ID}.group.{HOST_BUNDLE_ID}"
PROXY_AGENT_GROUP = f"{TEAM_ID}.{HOST_BUNDLE_ID}.proxy-agent"
PACKET_TUNNEL_GROUP = f"{TEAM_ID}.{HOST_BUNDLE_ID}.packet-tunnel"

APP_GROUPS_KEY = "com.apple.security.application-groups"
KEYCHAIN_GROUPS_KEY = "keychain-access-groups"
NETWORK_EXTENSION_KEY = "com.apple.developer.networking.networkextension"


class ReleaseComponentEntitlementError(ValueError):
    """A component input cannot produce the fixed release entitlement set."""


@dataclass(frozen=True)
class ComponentSpecification:
    role: str
    bundle_id: str
    functional_template: Mapping[str, Any]


COMPONENTS: Mapping[str, ComponentSpecification] = {
    "proxy-agent": ComponentSpecification(
        role="proxy-agent",
        bundle_id=f"{HOST_BUNDLE_ID}.proxy-agent",
        functional_template={
            APP_GROUPS_KEY: [f"{TEAM_PREFIX}group.{HOST_BUNDLE_ID}"],
            KEYCHAIN_GROUPS_KEY: [
                f"{APP_PREFIX}{HOST_BUNDLE_ID}.proxy-agent",
                f"{APP_PREFIX}{HOST_BUNDLE_ID}.credentials",
            ],
        },
    ),
    "packet-tunnel": ComponentSpecification(
        role="packet-tunnel",
        bundle_id=f"{HOST_BUNDLE_ID}.packet-tunnel",
        functional_template={
            NETWORK_EXTENSION_KEY: ["packet-tunnel-provider-systemextension"],
            "com.apple.security.app-sandbox": True,
            APP_GROUPS_KEY: [f"{TEAM_PREFIX}group.{HOST_BUNDLE_ID}"],
            "com.apple.security.network.client": True,
            "com.apple.security.network.server": True,
        },
    ),
}


def component_specification(role: str) -> ComponentSpecification:
    try:
        return COMPONENTS[role]
    except KeyError as error:
        raise ReleaseComponentEntitlementError(
            f"unknown release component role: {role}"
        ) from error


def build_release_component_entitlements(
    role: str,
    profile: Mapping[str, Any],
    reviewed_functional_entitlements: Mapping[str, Any],
    *,
    expected_profile_uuid: str,
    signing_certificate_sha1: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate frozen public inputs and return the exact component xcent."""
    specification = component_specification(role)
    if reviewed_functional_entitlements != specification.functional_template:
        raise ReleaseComponentEntitlementError(
            f"reviewed {role} entitlements do not match the exact functional template"
        )

    try:
        identity, profile_entitlements = validate_release_profile(
            profile,
            profile_description=f"{role} provisioning profile",
            expected_team_id=TEAM_ID,
            expected_bundle_id=specification.bundle_id,
            expected_profile_uuid=expected_profile_uuid,
            signing_certificate_sha1=signing_certificate_sha1,
            now=now,
        )
        functional = resolve_entitlement_prefixes(
            dict(reviewed_functional_entitlements),
            team_id=identity.team_id,
            application_identifier_prefix=identity.application_identifier_prefix,
        )
        release_entitlements = {
            identity.application_identifier_key: identity.application_identifier,
            TEAM_IDENTIFIER_KEY: identity.team_id,
            **functional,
        }

        verify_profile_keychain_access_group(
            profile_entitlements,
            specification.role,
            PROXY_AGENT_GROUP,
            PACKET_TUNNEL_GROUP,
            identity.team_id,
        )
        verify_profile_capability_authorizations(
            profile_entitlements,
            release_entitlements,
            specification.role,
            identity.team_id,
            APP_GROUP,
        )
        verify_signed_keychain_access_group(
            release_entitlements,
            specification.role,
            PROXY_AGENT_GROUP,
            PACKET_TUNNEL_GROUP,
        )
    except (ReleaseProfileEntitlementError, EntitlementContractError) as error:
        raise ReleaseComponentEntitlementError(
            f"{role} release entitlement validation failed: {error}"
        ) from error
    return release_entitlements


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a validated Proxy Agent or Packet Tunnel Developer ID "
            "release xcent"
        )
    )
    parser.add_argument("--role", required=True)
    parser.add_argument("--decoded-profile", required=True, type=Path)
    parser.add_argument("--reviewed-entitlements", required=True, type=Path)
    parser.add_argument("--signing-identities", required=True, type=Path)
    parser.add_argument("--signing-identity", required=True)
    parser.add_argument("--expected-profile-uuid", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        specification = component_specification(arguments.role)
        identity_listing = read_regular_text(
            arguments.signing_identities, "codesigning identity listing"
        )
        certificate_sha1 = signing_identity_sha1(
            identity_listing, arguments.signing_identity
        )
        release_entitlements = build_release_component_entitlements(
            specification.role,
            load_plist(
                arguments.decoded_profile,
                f"decoded {specification.role} provisioning profile",
            ),
            load_plist(
                arguments.reviewed_entitlements,
                f"reviewed {specification.role} entitlements",
            ),
            expected_profile_uuid=arguments.expected_profile_uuid,
            signing_certificate_sha1=certificate_sha1,
        )
        write_release_xcent(
            arguments.output,
            release_entitlements,
            description=f"{specification.role} release xcent",
        )
    except (ReleaseComponentEntitlementError, ReleaseProfileEntitlementError) as error:
        raise SystemExit(f"error: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
