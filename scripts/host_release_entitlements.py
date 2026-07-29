#!/usr/bin/env python3
"""Build the exact Host entitlements used by the final Developer ID signature.

The tracked Host entitlement plist is the authority for functional grants.  A
validated Developer ID provisioning profile is the authority for the Team and
application identifiers.  The generated xcent is never assembled by merging
arbitrary profile entitlements into the release signature.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import plistlib
import re
from typing import Any, Mapping, Sequence

from scripts.release_entitlement_contract import (
    EntitlementContractError,
    verify_profile_capability_authorizations,
    verify_profile_keychain_access_group,
    verify_signed_keychain_access_group,
)


APPLICATION_IDENTIFIER_KEYS = (
    "com.apple.application-identifier",
    "application-identifier",
)
TEAM_IDENTIFIER_KEY = "com.apple.developer.team-identifier"
APP_GROUPS_KEY = "com.apple.security.application-groups"
KEYCHAIN_GROUPS_KEY = "keychain-access-groups"
NETWORK_EXTENSION_KEY = "com.apple.developer.networking.networkextension"
SYSTEM_EXTENSION_INSTALL_KEY = "com.apple.developer.system-extension.install"

TEAM_PREFIX = "$(TeamIdentifierPrefix)"
APP_PREFIX = "$(AppIdentifierPrefix)"

_IDENTITY_LINE = re.compile(
    r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"([^"]+)"\s*$'
)


class HostReleaseEntitlementError(ValueError):
    """Raised when release inputs cannot produce an exact Host entitlement set."""


@dataclass(frozen=True)
class HostProfileIdentity:
    team_id: str
    application_identifier_key: str
    application_identifier: str


def load_plist(path: Path, description: str) -> dict[str, Any]:
    """Load a regular, non-symlink plist dictionary with contextual errors."""
    if path.is_symlink() or not path.is_file():
        raise HostReleaseEntitlementError(
            f"{description} must be a regular non-symlink file: {path}"
        )
    try:
        with path.open("rb") as handle:
            value = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as error:
        raise HostReleaseEntitlementError(
            f"cannot read {description} {path}: {error}"
        ) from error
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise HostReleaseEntitlementError(
            f"{description} must contain a plist dictionary with string keys"
        )
    return value


def signing_identity_sha1(identity_listing: str, signing_identity: str) -> str:
    """Return the unambiguous certificate SHA-1 selected by codesign."""
    matches = [
        match.group(1).upper()
        for line in identity_listing.splitlines()
        if (match := _IDENTITY_LINE.fullmatch(line))
        and match.group(2) == signing_identity
    ]
    if len(matches) != 1:
        raise HostReleaseEntitlementError(
            "the requested signing identity must have exactly one valid Keychain "
            f"certificate, found {len(matches)}"
        )
    return matches[0]


def _utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise HostReleaseEntitlementError(
            f"host provisioning profile has no valid {field}"
        )
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _profile_identity(
    profile: Mapping[str, Any],
    *,
    expected_team_id: str,
    expected_bundle_id: str,
    signing_certificate_sha1: str,
    now: datetime,
) -> tuple[HostProfileIdentity, Mapping[str, Any]]:
    teams = profile.get("TeamIdentifier")
    if teams != [expected_team_id]:
        raise HostReleaseEntitlementError(
            "host provisioning TeamIdentifier does not exactly match the "
            "release Team ID"
        )
    prefixes = profile.get("ApplicationIdentifierPrefix")
    if prefixes != [expected_team_id]:
        raise HostReleaseEntitlementError(
            "host provisioning application prefix does not exactly match the "
            "release Team ID"
        )
    if profile.get("ProvisionsAllDevices") is not True or profile.get(
        "ProvisionedDevices"
    ):
        raise HostReleaseEntitlementError(
            "host must use an all-device Developer ID provisioning profile"
        )

    platforms = profile.get("Platform")
    if (
        not isinstance(platforms, list)
        or any(not isinstance(platform, str) for platform in platforms)
        or not ({"OSX", "macOS"} & set(platforms))
    ):
        raise HostReleaseEntitlementError(
            "host provisioning profile is not a macOS profile"
        )
    profile_uuid = profile.get("UUID")
    if not isinstance(profile_uuid, str) or not profile_uuid:
        raise HostReleaseEntitlementError("host provisioning profile has no UUID")

    current_time = _utc(now, "validation time")
    creation = _utc(profile.get("CreationDate"), "creation date")
    expiration = _utc(profile.get("ExpirationDate"), "expiration date")
    if creation > current_time:
        raise HostReleaseEntitlementError(
            "host provisioning profile creation date is in the future"
        )
    if expiration <= current_time:
        raise HostReleaseEntitlementError("host provisioning profile has expired")

    certificates = profile.get("DeveloperCertificates")
    if (
        not isinstance(certificates, list)
        or not certificates
        or any(
            not isinstance(certificate, bytes) or not certificate
            for certificate in certificates
        )
    ):
        raise HostReleaseEntitlementError(
            "host provisioning profile has no valid DeveloperCertificates"
        )
    authorized_fingerprints = {
        hashlib.sha1(certificate).hexdigest().upper() for certificate in certificates
    }
    if signing_certificate_sha1.upper() not in authorized_fingerprints:
        raise HostReleaseEntitlementError(
            "the selected Developer ID signing certificate is not authorized by the "
            "host provisioning profile"
        )

    profile_entitlements = profile.get("Entitlements")
    if not isinstance(profile_entitlements, dict) or any(
        not isinstance(key, str) for key in profile_entitlements
    ):
        raise HostReleaseEntitlementError(
            "host provisioning profile has no entitlement dictionary"
        )
    if profile_entitlements.get(TEAM_IDENTIFIER_KEY) != expected_team_id:
        raise HostReleaseEntitlementError(
            "host provisioning Team ID entitlement does not match the release Team ID"
        )
    identifier_keys = [
        key for key in APPLICATION_IDENTIFIER_KEYS if key in profile_entitlements
    ]
    if len(identifier_keys) != 1:
        raise HostReleaseEntitlementError(
            "host provisioning profile must contain exactly one application identifier"
        )
    application_identifier_key = identifier_keys[0]
    application_identifier = profile_entitlements[application_identifier_key]
    expected_application_identifier = f"{expected_team_id}.{expected_bundle_id}"
    if application_identifier != expected_application_identifier:
        raise HostReleaseEntitlementError(
            "host provisioning application identifier does not exactly match "
            f"{expected_application_identifier}"
        )
    if profile_entitlements.get("get-task-allow") or profile_entitlements.get(
        "com.apple.security.get-task-allow"
    ):
        raise HostReleaseEntitlementError(
            "host provisioning profile permits debugging"
        )

    return (
        HostProfileIdentity(
            team_id=expected_team_id,
            application_identifier_key=application_identifier_key,
            application_identifier=application_identifier,
        ),
        profile_entitlements,
    )


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


def _resolve_prefixes(value: Any, team_id: str) -> Any:
    if isinstance(value, str):
        return value.replace(TEAM_PREFIX, f"{team_id}.").replace(
            APP_PREFIX, f"{team_id}."
        )
    if isinstance(value, list):
        return [_resolve_prefixes(item, team_id) for item in value]
    if isinstance(value, dict):
        return {key: _resolve_prefixes(item, team_id) for key, item in value.items()}
    return value


def _functional_entitlements(
    reviewed: Mapping[str, Any],
    tauri: Mapping[str, Any],
    *,
    team_id: str,
    bundle_id: str,
) -> dict[str, Any]:
    expected_template = _expected_functional_template(bundle_id)
    if reviewed != expected_template:
        raise HostReleaseEntitlementError(
            "reviewed Host.entitlements does not match the exact Host functional "
            "contract"
        )
    resolved = _resolve_prefixes(dict(reviewed), team_id)
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
    if not re.fullmatch(r"[A-Z0-9]{10}", expected_team_id):
        raise HostReleaseEntitlementError("release Team ID is malformed")
    if not expected_bundle_id or "*" in expected_bundle_id:
        raise HostReleaseEntitlementError("release Host bundle identifier is malformed")
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", signing_certificate_sha1):
        raise HostReleaseEntitlementError(
            "selected signing certificate fingerprint is malformed"
        )

    identity, profile_entitlements = _profile_identity(
        profile,
        expected_team_id=expected_team_id,
        expected_bundle_id=expected_bundle_id,
        signing_certificate_sha1=signing_certificate_sha1,
        now=now or datetime.now(timezone.utc),
    )
    functional = _functional_entitlements(
        reviewed_functional_entitlements,
        tauri_functional_entitlements,
        team_id=identity.team_id,
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


def write_release_xcent(path: Path, entitlements: Mapping[str, Any]) -> None:
    """Create a private deterministic XML xcent without comments or overwrites."""
    payload = plistlib.dumps(dict(entitlements), fmt=plistlib.FMT_XML, sort_keys=True)
    if b"<!--" in payload:
        raise HostReleaseEntitlementError(
            "generated Host release xcent contains comments"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise HostReleaseEntitlementError(
            f"cannot create Host release xcent {path}: {error}"
        ) from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
    except OSError as error:
        try:
            path.unlink(missing_ok=True)
        except OSError as cleanup_error:
            raise HostReleaseEntitlementError(
                f"cannot write or remove incomplete Host release xcent {path}: "
                f"write failed with {error}; cleanup failed with {cleanup_error}"
            ) from cleanup_error
        raise HostReleaseEntitlementError(
            f"cannot write Host release xcent {path}: {error}"
        ) from error


def _read_text(path: Path, description: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise HostReleaseEntitlementError(
            f"{description} must be a regular non-symlink file: {path}"
        )
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise HostReleaseEntitlementError(
            f"cannot read {description} {path}: {error}"
        ) from error


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
        identity_listing = _read_text(
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
        write_release_xcent(arguments.output, entitlements)
    except HostReleaseEntitlementError as error:
        raise SystemExit(f"error: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
