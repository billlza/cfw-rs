#!/usr/bin/env python3
"""Build the exact Host entitlements used by the final Developer ID signature.

The tracked Host entitlement plist is the authority for functional grants.  A
validated Developer ID provisioning profile is the authority for the Team and
application identifiers.  The generated xcent is never assembled by merging
arbitrary profile entitlements into the release signature.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
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


APP_GROUPS_KEY = "com.apple.security.application-groups"
KEYCHAIN_GROUPS_KEY = "keychain-access-groups"
NETWORK_EXTENSION_KEY = "com.apple.developer.networking.networkextension"
SYSTEM_EXTENSION_INSTALL_KEY = "com.apple.developer.system-extension.install"

HostReleaseEntitlementError = ReleaseProfileEntitlementError


def _expected_functional_template(bundle_id: str) -> dict[str, Any]:
    return {
        NETWORK_EXTENSION_KEY: ["packet-tunnel-provider-systemextension"],
        SYSTEM_EXTENSION_INSTALL_KEY: True,
        APP_GROUPS_KEY: [f"{TEAM_PREFIX}group.{bundle_id}"],
        KEYCHAIN_GROUPS_KEY: [
            f"{APP_PREFIX}{bundle_id}",
            f"{APP_PREFIX}{bundle_id}.credentials",
        ],
    }


def _functional_entitlements(
    reviewed: Mapping[str, Any],
    tauri: Mapping[str, Any],
    *,
    team_id: str,
    application_identifier_prefix: str,
    bundle_id: str,
) -> dict[str, Any]:
    expected_template = _expected_functional_template(bundle_id)
    if reviewed != expected_template:
        raise HostReleaseEntitlementError(
            "reviewed Host.entitlements does not match the exact Host functional "
            "contract"
        )
    resolved = resolve_entitlement_prefixes(
        dict(reviewed),
        team_id=team_id,
        application_identifier_prefix=application_identifier_prefix,
    )
    if tauri != resolved:
        raise HostReleaseEntitlementError(
            "Tauri Host entitlements are not semantically equivalent to reviewed "
            "Host.entitlements"
        )
    return resolved


def build_host_release_entitlements(
    profile: Mapping[str, Any],
    reviewed_functional_entitlements: Mapping[str, Any],
    tauri_functional_entitlements: Mapping[str, Any],
    *,
    expected_team_id: str,
    expected_bundle_id: str,
    signing_certificate_sha1: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate all inputs and return the exact final Host entitlement dictionary."""
    identity, profile_entitlements = validate_release_profile(
        profile,
        profile_description="host provisioning profile",
        expected_team_id=expected_team_id,
        expected_bundle_id=expected_bundle_id,
        expected_profile_uuid=None,
        signing_certificate_sha1=signing_certificate_sha1,
        now=now or datetime.now(timezone.utc),
    )
    functional = _functional_entitlements(
        reviewed_functional_entitlements,
        tauri_functional_entitlements,
        team_id=identity.team_id,
        application_identifier_prefix=identity.application_identifier_prefix,
        bundle_id=expected_bundle_id,
    )

    proxy_agent_group = f"{identity.team_id}.{expected_bundle_id}.proxy-agent"
    packet_tunnel_group = f"{identity.team_id}.{expected_bundle_id}.packet-tunnel"
    release_entitlements = {
        identity.application_identifier_key: identity.application_identifier,
        TEAM_IDENTIFIER_KEY: identity.team_id,
        **functional,
    }
    try:
        verify_profile_keychain_access_group(
            profile_entitlements,
            "host",
            proxy_agent_group,
            packet_tunnel_group,
            identity.team_id,
        )
        verify_profile_capability_authorizations(
            profile_entitlements,
            release_entitlements,
            "host",
            identity.team_id,
            functional[APP_GROUPS_KEY][0],
        )
    except EntitlementContractError as error:
        raise HostReleaseEntitlementError(
            f"host provisioning profile {error}"
        ) from error

    try:
        verify_signed_keychain_access_group(
            release_entitlements,
            "host",
            proxy_agent_group,
            packet_tunnel_group,
        )
    except EntitlementContractError as error:
        raise HostReleaseEntitlementError(str(error)) from error
    return release_entitlements


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the validated Host Developer ID release xcent"
    )
    parser.add_argument("--decoded-profile", required=True, type=Path)
    parser.add_argument("--reviewed-entitlements", required=True, type=Path)
    parser.add_argument("--tauri-entitlements", required=True, type=Path)
    parser.add_argument("--signing-identities", required=True, type=Path)
    parser.add_argument("--signing-identity", required=True)
    parser.add_argument("--expected-team-id", required=True)
    parser.add_argument("--expected-bundle-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        identity_listing = read_regular_text(
            arguments.signing_identities, "codesigning identity listing"
        )
        certificate_sha1 = signing_identity_sha1(
            identity_listing, arguments.signing_identity
        )
        entitlements = build_host_release_entitlements(
            load_plist(arguments.decoded_profile, "decoded Host provisioning profile"),
            load_plist(arguments.reviewed_entitlements, "reviewed Host entitlements"),
            load_plist(arguments.tauri_entitlements, "Tauri Host entitlements"),
            expected_team_id=arguments.expected_team_id,
            expected_bundle_id=arguments.expected_bundle_id,
            signing_certificate_sha1=certificate_sha1,
        )
        write_release_xcent(
            arguments.output, entitlements, description="Host release xcent"
        )
    except HostReleaseEntitlementError as error:
        raise SystemExit(f"error: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
