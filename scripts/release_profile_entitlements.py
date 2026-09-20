#!/usr/bin/env python3
"""Shared validation and durable xcent output for macOS release profiles.

This module is deliberately limited to public signing metadata.  It validates
an already-decoded Developer ID provisioning profile and a codesigning
identity listing, resolves Apple's Team/App prefix placeholders, and writes a
new deterministic entitlement plist.  It never invokes codesign, notarytool,
or a Keychain operation that can disclose secret material.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import plistlib
import re
import stat
from typing import Any, Mapping
import uuid


APPLICATION_IDENTIFIER_KEYS = (
    "com.apple.application-identifier",
    "application-identifier",
)
TEAM_IDENTIFIER_KEY = "com.apple.developer.team-identifier"
TEAM_PREFIX = "$(TeamIdentifierPrefix)"
APP_PREFIX = "$(AppIdentifierPrefix)"

_IDENTITY_LINE = re.compile(
    r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"([^"\r\n]+)"\s*$'
)
_TEAM_IDENTIFIER = re.compile(r"[A-Z0-9]{10}")
_BUNDLE_IDENTIFIER = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)


class ReleaseProfileEntitlementError(ValueError):
    """A public signing input cannot produce an exact release xcent."""


@dataclass(frozen=True)
class ReleaseProfileIdentity:
    """Identity fields authorized by one validated Developer ID profile."""

    team_id: str
    application_identifier_prefix: str
    application_identifier_key: str
    application_identifier: str
    profile_uuid: str


def _validate_regular_file_identity(
    identity: os.stat_result, path: Path, description: str
) -> None:
    if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1:
        raise ReleaseProfileEntitlementError(
            f"{description} must be a regular non-symlink, non-hardlinked file: "
            f"{path}"
        )


def _open_regular_file(
    path: Path, description: str
) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseProfileEntitlementError(
            f"cannot open {description} {path}: {error}"
        ) from error
    try:
        identity = os.fstat(descriptor)
        _validate_regular_file_identity(identity, path, description)
    except (OSError, ReleaseProfileEntitlementError):
        os.close(descriptor)
        raise
    return descriptor, identity


def read_regular_bytes(path: Path, description: str) -> bytes:
    """Read one regular single-link file without following the final symlink."""
    descriptor, identity_before = _open_regular_file(path, description)
    try:
        with os.fdopen(descriptor, "rb") as handle:
            payload = handle.read()
            identity_after = os.fstat(handle.fileno())
    except OSError as error:
        raise ReleaseProfileEntitlementError(
            f"cannot read {description} {path}: {error}"
        ) from error
    _validate_regular_file_identity(identity_after, path, description)
    stable_fields_before = (
        identity_before.st_dev,
        identity_before.st_ino,
        identity_before.st_mode,
        identity_before.st_size,
        identity_before.st_mtime_ns,
        identity_before.st_ctime_ns,
    )
    stable_fields_after = (
        identity_after.st_dev,
        identity_after.st_ino,
        identity_after.st_mode,
        identity_after.st_size,
        identity_after.st_mtime_ns,
        identity_after.st_ctime_ns,
    )
    if (
        stable_fields_before != stable_fields_after
        or len(payload) != identity_after.st_size
    ):
        raise ReleaseProfileEntitlementError(
            f"{description} changed while it was being read: {path}"
        )
    return payload


def read_regular_text(path: Path, description: str) -> str:
    """Read one strict UTF-8 regular single-link file."""
    payload = read_regular_bytes(path, description)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseProfileEntitlementError(
            f"{description} is not valid UTF-8: {path}"
        ) from error


def load_plist(path: Path, description: str) -> dict[str, Any]:
    """Load a regular single-link plist dictionary with contextual errors."""
    payload = read_regular_bytes(path, description)
    try:
        value = plistlib.loads(payload)
    except plistlib.InvalidFileException as error:
        raise ReleaseProfileEntitlementError(
            f"cannot parse {description} {path}: {error}"
        ) from error
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ReleaseProfileEntitlementError(
            f"{description} must contain a plist dictionary with string keys"
        )
    return value


def signing_identity_sha1(identity_listing: str, signing_identity: str) -> str:
    """Return the one certificate SHA-1 selected by the exact identity name."""
    matches = [
        match.group(1).upper()
        for line in identity_listing.splitlines()
        if (match := _IDENTITY_LINE.fullmatch(line))
        and match.group(2) == signing_identity
    ]
    if len(matches) != 1:
        raise ReleaseProfileEntitlementError(
            "the requested signing identity must have exactly one valid Keychain "
            f"certificate, found {len(matches)}"
        )
    return matches[0]


def _utc(value: object, field: str, profile_description: str) -> datetime:
    if not isinstance(value, datetime):
        raise ReleaseProfileEntitlementError(
            f"{profile_description} has no valid {field}"
        )
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_uuid(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise ReleaseProfileEntitlementError(f"{description} is not a UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ReleaseProfileEntitlementError(
            f"{description} is not a UUID"
        ) from error
    canonical = str(parsed)
    if value != canonical:
        raise ReleaseProfileEntitlementError(
            f"{description} is not in canonical lowercase form"
        )
    return canonical


def validate_release_profile(
    profile: Mapping[str, Any],
    *,
    profile_description: str,
    expected_team_id: str,
    expected_bundle_id: str,
    expected_profile_uuid: str | None,
    signing_certificate_sha1: str,
    now: datetime | None = None,
) -> tuple[ReleaseProfileIdentity, Mapping[str, Any]]:
    """Validate profile identity, lifetime, distribution, and certificate binding."""
    if _TEAM_IDENTIFIER.fullmatch(expected_team_id) is None:
        raise ReleaseProfileEntitlementError("release Team ID is malformed")
    if (
        _BUNDLE_IDENTIFIER.fullmatch(expected_bundle_id) is None
        or "*" in expected_bundle_id
    ):
        raise ReleaseProfileEntitlementError("release bundle identifier is malformed")
    if re.fullmatch(r"[0-9A-Fa-f]{40}", signing_certificate_sha1) is None:
        raise ReleaseProfileEntitlementError(
            "selected signing certificate fingerprint is malformed"
        )

    teams = profile.get("TeamIdentifier")
    if teams != [expected_team_id]:
        raise ReleaseProfileEntitlementError(
            f"{profile_description} TeamIdentifier does not exactly match the "
            "release Team ID"
        )
    prefixes = profile.get("ApplicationIdentifierPrefix")
    if prefixes != [expected_team_id]:
        raise ReleaseProfileEntitlementError(
            f"{profile_description} application prefix does not exactly match the "
            "release Team ID"
        )
    application_identifier_prefix = prefixes[0]
    if (
        profile.get("ProvisionsAllDevices") is not True
        or "ProvisionedDevices" in profile
    ):
        raise ReleaseProfileEntitlementError(
            f"{profile_description} must be an all-device Developer ID profile"
        )

    platforms = profile.get("Platform")
    if platforms not in (["OSX"], ["macOS"]):
        raise ReleaseProfileEntitlementError(
            f"{profile_description} is not a macOS profile"
        )

    profile_uuid = _canonical_uuid(
        profile.get("UUID"), f"{profile_description} UUID"
    )
    if expected_profile_uuid is not None:
        expected_uuid = _canonical_uuid(
            expected_profile_uuid, f"expected {profile_description} UUID"
        )
        if profile_uuid != expected_uuid:
            raise ReleaseProfileEntitlementError(
                f"{profile_description} UUID does not match the expected profile UUID"
            )

    current_time = _utc(
        now or datetime.now(timezone.utc), "validation time", profile_description
    )
    creation = _utc(profile.get("CreationDate"), "creation date", profile_description)
    expiration = _utc(
        profile.get("ExpirationDate"), "expiration date", profile_description
    )
    if creation > current_time:
        raise ReleaseProfileEntitlementError(
            f"{profile_description} creation date is in the future"
        )
    if expiration <= creation:
        raise ReleaseProfileEntitlementError(
            f"{profile_description} lifetime is invalid"
        )
    if expiration <= current_time:
        raise ReleaseProfileEntitlementError(f"{profile_description} has expired")

    certificates = profile.get("DeveloperCertificates")
    if (
        not isinstance(certificates, list)
        or not certificates
        or any(
            not isinstance(certificate, bytes) or not certificate
            for certificate in certificates
        )
    ):
        raise ReleaseProfileEntitlementError(
            f"{profile_description} has no valid DeveloperCertificates"
        )
    authorized_fingerprints = [
        hashlib.sha1(certificate).hexdigest().upper()
        for certificate in certificates
    ]
    if len(set(authorized_fingerprints)) != len(authorized_fingerprints):
        raise ReleaseProfileEntitlementError(
            f"{profile_description} repeats a DeveloperCertificate"
        )
    if signing_certificate_sha1.upper() not in authorized_fingerprints:
        raise ReleaseProfileEntitlementError(
            "the selected Developer ID signing certificate is not authorized by the "
            f"{profile_description}"
        )

    profile_entitlements = profile.get("Entitlements")
    if not isinstance(profile_entitlements, dict) or any(
        not isinstance(key, str) for key in profile_entitlements
    ):
        raise ReleaseProfileEntitlementError(
            f"{profile_description} has no entitlement dictionary"
        )
    if profile_entitlements.get(TEAM_IDENTIFIER_KEY) != expected_team_id:
        raise ReleaseProfileEntitlementError(
            f"{profile_description} Team ID entitlement does not match the "
            "release Team ID"
        )
    identifier_keys = [
        key for key in APPLICATION_IDENTIFIER_KEYS if key in profile_entitlements
    ]
    if len(identifier_keys) != 1:
        raise ReleaseProfileEntitlementError(
            f"{profile_description} must contain exactly one application identifier"
        )
    application_identifier_key = identifier_keys[0]
    application_identifier = profile_entitlements[application_identifier_key]
    expected_application_identifier = (
        f"{application_identifier_prefix}.{expected_bundle_id}"
    )
    if application_identifier != expected_application_identifier:
        raise ReleaseProfileEntitlementError(
            f"{profile_description} application identifier does not exactly match "
            f"{expected_application_identifier}"
        )
    if profile_entitlements.get("get-task-allow") or profile_entitlements.get(
        "com.apple.security.get-task-allow"
    ):
        raise ReleaseProfileEntitlementError(
            f"{profile_description} permits debugging"
        )

    return (
        ReleaseProfileIdentity(
            team_id=expected_team_id,
            application_identifier_prefix=application_identifier_prefix,
            application_identifier_key=application_identifier_key,
            application_identifier=application_identifier,
            profile_uuid=profile_uuid,
        ),
        profile_entitlements,
    )


def resolve_entitlement_prefixes(
    value: Any,
    *,
    team_id: str,
    application_identifier_prefix: str,
) -> Any:
    """Resolve exact Apple prefix placeholders throughout a plist value."""
    if isinstance(value, str):
        return value.replace(TEAM_PREFIX, f"{team_id}.").replace(
            APP_PREFIX, f"{application_identifier_prefix}."
        )
    if isinstance(value, list):
        return [
            resolve_entitlement_prefixes(
                item,
                team_id=team_id,
                application_identifier_prefix=application_identifier_prefix,
            )
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: resolve_entitlement_prefixes(
                item,
                team_id=team_id,
                application_identifier_prefix=application_identifier_prefix,
            )
            for key, item in value.items()
        }
    return value


def _remove_created_output(parent_descriptor: int, name: str) -> str | None:
    try:
        os.unlink(name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError as error:
        return str(error)
    return None


def write_release_xcent(
    path: Path,
    entitlements: Mapping[str, Any],
    *,
    description: str = "release xcent",
) -> None:
    """Exclusively create a private deterministic XML xcent and sync its parent."""
    payload = plistlib.dumps(dict(entitlements), fmt=plistlib.FMT_XML, sort_keys=True)
    if b"<!--" in payload:
        raise ReleaseProfileEntitlementError(
            f"generated {description} contains comments"
        )
    if path.name in {"", ".", ".."}:
        raise ReleaseProfileEntitlementError(f"{description} output path is malformed")

    parent_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        parent_flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        parent_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(path.parent, parent_flags)
    except OSError as error:
        raise ReleaseProfileEntitlementError(
            f"cannot open {description} parent directory {path.parent}: {error}"
        ) from error

    output_descriptor = -1
    created = False
    try:
        parent_identity = os.fstat(parent_descriptor)
        if not stat.S_ISDIR(parent_identity.st_mode):
            raise ReleaseProfileEntitlementError(
                f"{description} parent must be a non-symlink directory: {path.parent}"
            )

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            output_descriptor = os.open(
                path.name, flags, 0o600, dir_fd=parent_descriptor
            )
            created = True
            os.fchmod(output_descriptor, 0o600)
            with os.fdopen(output_descriptor, "wb", closefd=True) as handle:
                output_descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
                written_identity = os.fstat(handle.fileno())

            output_identity = os.stat(
                path.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(output_identity.st_mode)
                or output_identity.st_nlink != 1
                or stat.S_IMODE(output_identity.st_mode) != 0o600
                or output_identity.st_dev != written_identity.st_dev
                or output_identity.st_ino != written_identity.st_ino
            ):
                raise ReleaseProfileEntitlementError(
                    f"created {description} is not a private single-link regular file"
                )
            os.fsync(parent_descriptor)
        except (OSError, ReleaseProfileEntitlementError) as error:
            if output_descriptor >= 0:
                os.close(output_descriptor)
                output_descriptor = -1
            cleanup_error = (
                _remove_created_output(parent_descriptor, path.name)
                if created
                else None
            )
            detail = f"; cleanup failed with {cleanup_error}" if cleanup_error else ""
            raise ReleaseProfileEntitlementError(
                f"cannot create {description} {path}: {error}{detail}"
            ) from error
    finally:
        if output_descriptor >= 0:
            os.close(output_descriptor)
        os.close(parent_descriptor)
