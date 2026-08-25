#!/usr/bin/env python3
"""Read-only, fail-closed release-signing material preflight.

The preflight resolves the exact Developer ID identity and provisioning
profiles needed by the macOS release before a candidate-freeze intent may be
committed.  It also proves that the fixed notary profile is usable and that the
updater key/password custody paths satisfy their metadata-only policy.

Private-key and password bytes are never opened, read, hashed, printed, or
placed in the result.  The only updater-key observations are filesystem
metadata and deny-only ACL output.  Keychain access is metadata-only and never
uses a password-output option.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import subprocess
import sys
from typing import Callable, Mapping, Sequence
import uuid


if __package__:
    from .macos_durability import full_fsync
    from .publication.bounded_process import BoundedProcessError, run_bounded_process
    from .release_entitlement_contract import (
        KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS,
    )
    from .updater_signing_launcher import (
        KEYCHAIN_ACCOUNT,
        KEYCHAIN_SERVICE,
        LOGIN_KEYCHAIN_RELATIVE,
        PRIVATE_KEY_RELATIVE,
    )
else:
    from macos_durability import full_fsync
    from publication.bounded_process import BoundedProcessError, run_bounded_process
    from release_entitlement_contract import (
        KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS,
    )
    from updater_signing_launcher import (
        KEYCHAIN_ACCOUNT,
        KEYCHAIN_SERVICE,
        LOGIN_KEYCHAIN_RELATIVE,
        PRIVATE_KEY_RELATIVE,
    )


TEAM_ID = "YKUPL7Z869"
NOTARY_PROFILE = "clashformac-notary"
DOCUMENT = "cfm-release-signing-preflight-v1"

SECURITY = "/usr/bin/security"
XCRUN = "/usr/bin/xcrun"
LS = "/bin/ls"
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
DEVELOPER_DIR = "/Applications/Xcode.app/Contents/Developer"

HOST_BUNDLE_ID = "com.bill.clashformac"
PACKET_TUNNEL_BUNDLE_ID = "com.bill.clashformac.packet-tunnel"
PROXY_AGENT_BUNDLE_ID = "com.bill.clashformac.proxy-agent"
APP_GROUPS = frozenset({"group.com.bill.clashformac", f"{TEAM_ID}.*"})
TEAM_KEYCHAIN_GROUP = [f"{TEAM_ID}.*"]

MAX_PROFILE_BYTES = 1024 * 1024
MAX_CMS_BYTES = 2 * 1024 * 1024
MAX_IDENTITY_BYTES = 64 * 1024
MAX_NOTARY_BYTES = 2 * 1024 * 1024
MAX_KEYCHAIN_METADATA_BYTES = 64 * 1024
MAX_PREFLIGHT_MANIFEST_BYTES = 4 * 1024 * 1024
PROCESS_TIMEOUT_SECONDS = 120

SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
CERTIFICATE_SHA1_RE = re.compile(r"\A[0-9A-F]{40}\Z")
CERTIFICATE_SHA256_RE = re.compile(r"\A[0-9A-F]{64}\Z")
PROFILE_MANIFEST_FIELDS = frozenset(
    {
        "authorizedCertificateSha256",
        "bundleId",
        "creation",
        "expiration",
        "fileSha256",
        "fileSize",
        "name",
        "path",
        "role",
        "selectedCertificateSha256",
        "uuid",
    }
)
PROFILE_ROLES = frozenset({"host", "packet-tunnel", "proxy-agent"})
FILE_METADATA_FIELDS = frozenset(
    {
        "changedNs",
        "device",
        "gid",
        "inode",
        "links",
        "mode",
        "modifiedNs",
        "path",
        "size",
        "uid",
    }
)

PROFILE_TOP_LEVEL_KEYS = frozenset(
    {
        "AppIDName",
        "ApplicationIdentifierPrefix",
        "CreationDate",
        "DER-Encoded-Profile",
        "DeveloperCertificates",
        "Entitlements",
        "ExpirationDate",
        "IsXcodeManaged",
        "Name",
        "PPQCheck",
        "Platform",
        "ProvisionsAllDevices",
        "TeamIdentifier",
        "TeamName",
        "TimeToLive",
        "UUID",
        "Version",
    }
)
BASE_PROFILE_ENTITLEMENT_KEYS = frozenset(
    {
        "com.apple.application-identifier",
        "com.apple.developer.team-identifier",
        "com.apple.security.application-groups",
        "keychain-access-groups",
    }
)
NETWORK_EXTENSION_KEY = "com.apple.developer.networking.networkextension"
SYSTEM_EXTENSION_INSTALL_KEY = "com.apple.developer.system-extension.install"

IDENTITY_RE = re.compile(
    rf"^Developer ID Application: [^\"\r\n]{{1,160}} \({TEAM_ID}\)$"
)
IDENTITY_LINE_RE = re.compile(
    r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"([^"\r\n]+)"\s*$'
)
IDENTITY_COUNT_RE = re.compile(r"^\s*\d+ valid identities found\s*$")
ACL_ENTRY_RE = re.compile(r"^[ \t]*\d+:[ \t]+")
ACL_ACTION_RE = re.compile(r"[ \t](allow|deny)[ \t]")
ProcessRunner = Callable[..., subprocess.CompletedProcess[bytes]]


class SigningPreflightError(RuntimeError):
    """A release-signing input is unavailable, ambiguous, or unsafe."""


@dataclass(frozen=True)
class FileMetadata:
    path: str
    device: int
    inode: int
    mode: str
    uid: int
    gid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, path: Path, value: os.stat_result) -> "FileMetadata":
        return cls(
            path=str(path),
            device=value.st_dev,
            inode=value.st_ino,
            mode=f"{stat.S_IMODE(value.st_mode):04o}",
            uid=value.st_uid,
            gid=value.st_gid,
            links=value.st_nlink,
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            changed_ns=value.st_ctime_ns,
        )

    def as_manifest(self) -> dict[str, object]:
        return {
            "changedNs": self.changed_ns,
            "device": self.device,
            "gid": self.gid,
            "inode": self.inode,
            "links": self.links,
            "mode": self.mode,
            "modifiedNs": self.modified_ns,
            "path": self.path,
            "size": self.size,
            "uid": self.uid,
        }


@dataclass(frozen=True)
class ProfilePreflight:
    role: str
    path: str
    file_sha256: str
    file_size: int
    name: str
    uuid: str
    bundle_id: str
    creation: str
    expiration: str
    selected_certificate_sha256: str
    authorized_certificate_sha256: tuple[str, ...]

    def as_manifest(self) -> dict[str, object]:
        return {
            "authorizedCertificateSha256": list(
                self.authorized_certificate_sha256
            ),
            "bundleId": self.bundle_id,
            "creation": self.creation,
            "expiration": self.expiration,
            "fileSha256": self.file_sha256,
            "fileSize": self.file_size,
            "name": self.name,
            "path": self.path,
            "role": self.role,
            "selectedCertificateSha256": self.selected_certificate_sha256,
            "uuid": self.uuid,
        }


@dataclass(frozen=True)
class SigningPreflightResult:
    signing_identity: str
    certificate_sha1: str
    certificate_sha256: str
    profiles: tuple[ProfilePreflight, ...]
    notary_profile: str
    updater_ancestors: tuple[FileMetadata, ...]
    updater_key: FileMetadata
    login_keychain: FileMetadata

    def as_manifest(self) -> dict[str, object]:
        return {
            "document": DOCUMENT,
            "identity": {
                "certificateSha1": self.certificate_sha1,
                "certificateSha256": self.certificate_sha256,
                "name": self.signing_identity,
            },
            "notary": {
                "historyProbe": "passed",
                "profile": self.notary_profile,
            },
            "profiles": {
                profile.role: profile.as_manifest() for profile in self.profiles
            },
            "teamId": TEAM_ID,
            "updater": {
                "ancestors": [item.as_manifest() for item in self.updater_ancestors],
                "key": self.updater_key.as_manifest(),
                "passwordKeychain": {
                    "account": KEYCHAIN_ACCOUNT,
                    "file": self.login_keychain.as_manifest(),
                    "service": KEYCHAIN_SERVICE,
                    "synchronizable": False,
                },
            },
        }

    def canonical_manifest(self) -> bytes:
        return canonical_manifest(self.as_manifest())


def canonical_manifest(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise SigningPreflightError(
            "signing preflight result is not canonical JSON"
        ) from error
    return encoded + b"\n"


def write_preflight_manifest(path: Path, result: SigningPreflightResult) -> None:
    """Durably create one private canonical manifest without replacement."""
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise SigningPreflightError(
            "signing preflight output parent is unavailable"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or parent.is_symlink():
        raise SigningPreflightError("signing preflight output parent is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        payload = result.canonical_manifest()
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short signing preflight manifest write")
            offset += written
        full_fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            full_fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise SigningPreflightError(
            "cannot durably create signing preflight manifest"
        ) from error


def _strict_json(data: bytes, label: str) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise SigningPreflightError(f"{label} repeats a JSON field")
            result[key] = item
        return result

    def reject_constant(token: str) -> object:
        raise SigningPreflightError(f"{label} contains {token}")

    try:
        return json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except SigningPreflightError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SigningPreflightError(f"{label} is not strict JSON") from error


def _read_stable_regular_file(
    path: Path,
    label: str,
    *,
    maximum_size: int,
    modes: frozenset[int],
) -> bytes:
    expected = _require_regular_metadata(
        path,
        label,
        owner=os.geteuid(),
        modes=modes,
        maximum_size=maximum_size,
    )
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        if FileMetadata.from_stat(path, os.fstat(descriptor)) != expected:
            raise SigningPreflightError(f"{label} changed before it was read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_size:
                raise SigningPreflightError(f"{label} exceeds its fixed bound")
            chunks.append(chunk)
        if (
            FileMetadata.from_stat(path, os.fstat(descriptor)) != expected
            or total != expected.size
        ):
            raise SigningPreflightError(f"{label} changed while it was read")
        return b"".join(chunks)
    except SigningPreflightError:
        raise
    except OSError as error:
        raise SigningPreflightError(f"cannot securely read {label}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def verify_materialized_profiles(
    manifest_path: Path,
    profiles: Mapping[str, Path],
) -> dict[str, dict[str, object]]:
    """Bind copied candidate profiles to the exact successful preflight."""

    if set(profiles) != PROFILE_ROLES:
        raise SigningPreflightError(
            "materialized provisioning profile roles are incomplete"
        )
    value = load_preflight_manifest(manifest_path)
    manifest_profiles = value["profiles"]

    verified: dict[str, dict[str, object]] = {}
    for role in sorted(PROFILE_ROLES):
        expected = manifest_profiles[role]
        expected_sha256 = expected["fileSha256"]
        expected_size = expected["fileSize"]
        materialized = profiles[role]
        identity = _profile_file_identity(materialized, role, os.geteuid())
        observed_sha256 = _hash_profile(materialized, identity)
        if identity.size != expected_size or observed_sha256 != expected_sha256:
            raise SigningPreflightError(
                f"materialized {role} provisioning profile differs from preflight"
            )
        verified[role] = dict(expected)
    return verified


def load_preflight_manifest(manifest_path: Path) -> dict[str, object]:
    data = _read_stable_regular_file(
        manifest_path,
        "signing preflight manifest",
        maximum_size=MAX_PREFLIGHT_MANIFEST_BYTES,
        modes=frozenset({0o600}),
    )
    value = _strict_json(data, "signing preflight manifest")
    if type(value) is not dict or set(value) != {
        "document",
        "identity",
        "notary",
        "profiles",
        "teamId",
        "updater",
    }:
        raise SigningPreflightError(
            "signing preflight manifest has an unexpected field set"
        )
    if data != canonical_manifest(value):
        raise SigningPreflightError("signing preflight manifest is not canonical JSON")
    if value["document"] != DOCUMENT or value["teamId"] != TEAM_ID:
        raise SigningPreflightError("signing preflight manifest identity is invalid")
    identity = value["identity"]
    if (
        type(identity) is not dict
        or set(identity) != {"certificateSha1", "certificateSha256", "name"}
        or not isinstance(identity["certificateSha1"], str)
        or not CERTIFICATE_SHA1_RE.fullmatch(identity["certificateSha1"])
        or not isinstance(identity["certificateSha256"], str)
        or not CERTIFICATE_SHA256_RE.fullmatch(identity["certificateSha256"])
        or not isinstance(identity["name"], str)
        or not IDENTITY_RE.fullmatch(identity["name"])
    ):
        raise SigningPreflightError(
            "signing preflight manifest certificate identity is invalid"
        )
    manifest_profiles = value["profiles"]
    if type(manifest_profiles) is not dict or set(manifest_profiles) != PROFILE_ROLES:
        raise SigningPreflightError(
            "signing preflight manifest profile roles are invalid"
        )

    verified: dict[str, dict[str, object]] = {}
    for role in sorted(PROFILE_ROLES):
        expected = manifest_profiles[role]
        if type(expected) is not dict or set(expected) != PROFILE_MANIFEST_FIELDS:
            raise SigningPreflightError(
                f"{role} signing preflight profile record is invalid"
            )
        expected_sha256 = expected["fileSha256"]
        expected_size = expected["fileSize"]
        if (
            expected["role"] != role
            or not isinstance(expected_sha256, str)
            or not SHA256_RE.fullmatch(expected_sha256)
            or type(expected_size) is not int
            or expected_size < 1
            or expected_size > MAX_PROFILE_BYTES
        ):
            raise SigningPreflightError(
                f"{role} signing preflight profile identity is invalid"
            )
        expected_bundle_id = {
            "host": HOST_BUNDLE_ID,
            "packet-tunnel": PACKET_TUNNEL_BUNDLE_ID,
            "proxy-agent": PROXY_AGENT_BUNDLE_ID,
        }[role]
        authorized = expected["authorizedCertificateSha256"]
        selected = expected["selectedCertificateSha256"]
        profile_path = expected["path"]
        profile_uuid = expected["uuid"]
        if (
            expected["bundleId"] != expected_bundle_id
            or selected != identity["certificateSha256"]
            or type(authorized) is not list
            or not authorized
            or any(
                not isinstance(item, str)
                or not CERTIFICATE_SHA256_RE.fullmatch(item)
                for item in authorized
            )
            or len(set(authorized)) != len(authorized)
            or authorized.count(selected) != 1
            or not isinstance(profile_path, str)
            or not Path(profile_path).is_absolute()
            or not isinstance(profile_uuid, str)
        ):
            raise SigningPreflightError(
                f"{role} signing preflight profile provenance is invalid"
            )
        try:
            if str(uuid.UUID(profile_uuid)) != profile_uuid.lower():
                raise ValueError("noncanonical profile UUID")
            creation = datetime.fromisoformat(expected["creation"].replace("Z", "+00:00"))
            expiration = datetime.fromisoformat(
                expected["expiration"].replace("Z", "+00:00")
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise SigningPreflightError(
                f"{role} signing preflight profile dates or UUID are invalid"
            ) from error
        if (
            creation.tzinfo is None
            or expiration.tzinfo is None
            or creation >= expiration
            or expiration <= datetime.now(timezone.utc)
        ):
            raise SigningPreflightError(
                f"{role} signing preflight profile is expired or temporally invalid"
            )
    notary = value["notary"]
    if notary != {"historyProbe": "passed", "profile": NOTARY_PROFILE}:
        raise SigningPreflightError("signing preflight notary proof is invalid")
    _validate_updater_manifest_schema(value["updater"])
    return value


def _metadata_record(value: object, label: str) -> FileMetadata:
    if type(value) is not dict or set(value) != FILE_METADATA_FIELDS:
        raise SigningPreflightError(f"{label} metadata field set is invalid")
    integer_fields = (
        "changedNs",
        "device",
        "gid",
        "inode",
        "links",
        "modifiedNs",
        "size",
        "uid",
    )
    if any(type(value[field]) is not int or value[field] < 0 for field in integer_fields):
        raise SigningPreflightError(f"{label} metadata integers are invalid")
    if (
        not isinstance(value["path"], str)
        or not Path(value["path"]).is_absolute()
        or not isinstance(value["mode"], str)
        or not re.fullmatch(r"[0-7]{4}", value["mode"])
    ):
        raise SigningPreflightError(f"{label} metadata path or mode is invalid")
    return FileMetadata(
        path=value["path"],
        device=value["device"],
        inode=value["inode"],
        mode=value["mode"],
        uid=value["uid"],
        gid=value["gid"],
        links=value["links"],
        size=value["size"],
        modified_ns=value["modifiedNs"],
        changed_ns=value["changedNs"],
    )


def _validate_updater_manifest_schema(value: object) -> None:
    if type(value) is not dict or set(value) != {
        "ancestors",
        "key",
        "passwordKeychain",
    }:
        raise SigningPreflightError("signing preflight updater field set is invalid")
    ancestors = value["ancestors"]
    password = value["passwordKeychain"]
    if type(ancestors) is not list or len(ancestors) != 6:
        raise SigningPreflightError("signing preflight updater ancestors are invalid")
    parsed_ancestors = [
        _metadata_record(item, "updater custody ancestor") for item in ancestors
    ]
    home = Path(parsed_ancestors[0].path)
    expected_paths = [
        home,
        home / "Library",
        home / "Library/Application Support",
        home / "Library/Application Support/Clash for Mac Release",
        home / PRIVATE_KEY_RELATIVE.parent,
        home / LOGIN_KEYCHAIN_RELATIVE.parent,
    ]
    if [Path(item.path) for item in parsed_ancestors] != expected_paths:
        raise SigningPreflightError(
            "signing preflight updater ancestor paths are invalid"
        )
    if (
        any(item.uid != os.geteuid() for item in parsed_ancestors)
        or int(parsed_ancestors[0].mode, 8) & 0o022
        or any(item.mode != "0700" for item in parsed_ancestors[1:5])
        or parsed_ancestors[5].mode not in {"0700", "0755"}
    ):
        raise SigningPreflightError(
            "signing preflight updater ancestor ownership or modes are invalid"
        )
    key = _metadata_record(value["key"], "updater private key")
    if (
        Path(key.path) != home / PRIVATE_KEY_RELATIVE
        or key.uid != os.geteuid()
        or key.mode != "0600"
        or key.links != 1
        or key.size < 1
        or key.size > 1024 * 1024
    ):
        raise SigningPreflightError("signing preflight updater key identity is invalid")
    if type(password) is not dict or set(password) != {
        "account",
        "file",
        "service",
        "synchronizable",
    }:
        raise SigningPreflightError(
            "signing preflight updater password metadata is invalid"
        )
    keychain = _metadata_record(password["file"], "login Keychain")
    if (
        password["account"] != KEYCHAIN_ACCOUNT
        or password["service"] != KEYCHAIN_SERVICE
        or password["synchronizable"] is not False
        or Path(keychain.path) != home / LOGIN_KEYCHAIN_RELATIVE
        or keychain.uid != os.geteuid()
        or keychain.mode not in {"0600", "0644"}
        or keychain.links != 1
        or keychain.size < 1
        or keychain.size > 512 * 1024 * 1024
    ):
        raise SigningPreflightError(
            "signing preflight updater password custody is invalid"
        )


def verify_custody_metadata(manifest_path: Path) -> dict[str, object]:
    value = load_preflight_manifest(manifest_path)
    updater = value["updater"]
    records = [
        *updater["ancestors"],
        updater["key"],
        updater["passwordKeychain"]["file"],
    ]
    for index, record in enumerate(records):
        expected = _metadata_record(record, "updater custody path")
        path = Path(expected.path)
        try:
            metadata = path.lstat()
        except OSError as error:
            raise SigningPreflightError(
                "updater custody path is unavailable after preflight"
            ) from error
        if path.is_symlink() or FileMetadata.from_stat(path, metadata) != expected:
            raise SigningPreflightError(
                "updater custody metadata differs from the signing preflight"
            )
        if index < len(updater["ancestors"]):
            if not stat.S_ISDIR(metadata.st_mode):
                raise SigningPreflightError(
                    "updater custody ancestor is not a directory"
                )
        elif not stat.S_ISREG(metadata.st_mode):
            raise SigningPreflightError("updater custody file is not regular")
    return value


def signing_certificate_digests(manifest_path: Path) -> tuple[str, str]:
    value = load_preflight_manifest(manifest_path)
    identity = value["identity"]
    return identity["certificateSha1"], identity["certificateSha256"]


def _command_environment(home: Path, *, notary: bool = False) -> dict[str, str]:
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": SYSTEM_PATH,
    }
    if notary:
        environment["DEVELOPER_DIR"] = DEVELOPER_DIR
    return environment


def _run(
    command: Sequence[str],
    label: str,
    *,
    runner: ProcessRunner,
    repository: Path,
    environment: Mapping[str, str],
    output_limit: int,
) -> bytes:
    if not command or command[0] not in {SECURITY, XCRUN, LS}:
        raise SigningPreflightError(f"{label} command is not fixed")
    try:
        result = runner(
            list(command),
            cwd=repository,
            environment=dict(environment),
            timeout=PROCESS_TIMEOUT_SECONDS,
            output_limit=output_limit,
        )
    except BoundedProcessError as error:
        raise SigningPreflightError(f"{label} process boundary failed") from error
    except OSError as error:
        raise SigningPreflightError(f"{label} could not start") from error
    if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes):
        raise SigningPreflightError(f"{label} returned non-byte output")
    if result.returncode != 0:
        raise SigningPreflightError(f"{label} failed with exit {result.returncode}")
    if result.stderr:
        raise SigningPreflightError(f"{label} emitted diagnostics")
    return result.stdout


def _home_directory(home: Path | None) -> Path:
    selected = Path(pwd.getpwuid(os.getuid()).pw_dir) if home is None else home
    if not selected.is_absolute():
        raise SigningPreflightError("release user home directory is not absolute")
    try:
        if selected.resolve(strict=True) != selected:
            raise SigningPreflightError(
                "release user home directory is not canonical"
            )
    except OSError as error:
        raise SigningPreflightError(
            "release user home directory is unavailable"
        ) from error
    return selected


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise SigningPreflightError(f"{label} is unavailable: {path}") from error


def _require_directory(
    path: Path,
    label: str,
    *,
    owner: int,
    exact_mode: int | None,
) -> FileMetadata:
    value = _lstat(path, label)
    mode = stat.S_IMODE(value.st_mode)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != owner:
        raise SigningPreflightError(f"{label} is not an owner-bound directory")
    if exact_mode is not None and mode != exact_mode:
        raise SigningPreflightError(
            f"{label} mode is {mode:04o}, expected {exact_mode:04o}"
        )
    if exact_mode is None and mode & 0o022:
        raise SigningPreflightError(f"{label} is group/other writable")
    return FileMetadata.from_stat(path, value)


def _require_regular_metadata(
    path: Path,
    label: str,
    *,
    owner: int,
    modes: frozenset[int],
    maximum_size: int,
) -> FileMetadata:
    value = _lstat(path, label)
    mode = stat.S_IMODE(value.st_mode)
    if not stat.S_ISREG(value.st_mode) or value.st_uid != owner:
        raise SigningPreflightError(
            f"{label} is not an owner-bound regular file"
        )
    if value.st_nlink != 1:
        raise SigningPreflightError(f"{label} must have exactly one hard link")
    if mode not in modes:
        expected = ", ".join(f"{item:04o}" for item in sorted(modes))
        raise SigningPreflightError(
            f"{label} mode is {mode:04o}, expected one of {expected}"
        )
    if value.st_size < 1 or value.st_size > maximum_size:
        raise SigningPreflightError(f"{label} size is outside its fixed bound")
    return FileMetadata.from_stat(path, value)


def _require_acl(
    path: Path,
    label: str,
    *,
    runner: ProcessRunner,
    repository: Path,
    environment: Mapping[str, str],
) -> None:
    output = _run(
        [LS, "-lde", "--", str(path)],
        f"{label} ACL inspection",
        runner=runner,
        repository=repository,
        environment=environment,
        output_limit=MAX_KEYCHAIN_METADATA_BYTES,
    )
    if not output:
        raise SigningPreflightError(f"{label} ACL inspection returned no metadata")
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise SigningPreflightError(f"{label} ACL metadata is not UTF-8") from error
    for line in lines:
        if not ACL_ENTRY_RE.match(line):
            continue
        if ACL_ACTION_RE.findall(line) != ["deny"]:
            raise SigningPreflightError(f"{label} ACL grants access")


def _profile_file_identity(path: Path, role: str, owner: int) -> FileMetadata:
    if not path.is_absolute():
        raise SigningPreflightError(f"{role} provisioning profile path is not absolute")
    try:
        if path.resolve(strict=True) != path:
            raise SigningPreflightError(
                f"{role} provisioning profile path is not canonical"
            )
    except OSError as error:
        raise SigningPreflightError(
            f"{role} provisioning profile path is unavailable"
        ) from error
    return _require_regular_metadata(
        path,
        f"{role} provisioning profile",
        owner=owner,
        modes=frozenset({0o400, 0o600, 0o644}),
        maximum_size=MAX_PROFILE_BYTES,
    )


def _hash_profile(path: Path, expected: FileMetadata) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        observed = FileMetadata.from_stat(path, before)
        if observed != expected:
            raise SigningPreflightError(
                "provisioning profile changed before identity capture"
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PROFILE_BYTES:
                raise SigningPreflightError(
                    "provisioning profile exceeds its fixed bound"
                )
            digest.update(chunk)
        after = FileMetadata.from_stat(path, os.fstat(descriptor))
        if after != expected or total != expected.size:
            raise SigningPreflightError(
                "provisioning profile changed while its identity was captured"
            )
        return digest.hexdigest()
    except SigningPreflightError:
        raise
    except OSError as error:
        raise SigningPreflightError(
            "cannot capture provisioning profile identity"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _bounded_text(value: object, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise SigningPreflightError(f"{label} is not bounded canonical text")
    return value


def _utc(value: object, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise SigningPreflightError(f"provisioning profile {label} is invalid")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_uuid(value: object, label: str) -> str:
    text = _bounded_text(value, label, 36)
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as error:
        raise SigningPreflightError(f"{label} is not a UUID") from error
    canonical = str(parsed)
    if text != canonical:
        raise SigningPreflightError(f"{label} is not a canonical lowercase UUID")
    return canonical


def _unique_string_set(value: object, label: str) -> frozenset[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise SigningPreflightError(f"{label} is not a unique string allowlist")
    return frozenset(value)


def _parse_identity_listing(data: bytes, requested: str) -> str:
    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise SigningPreflightError("codesigning identity metadata is not UTF-8") from error
    matches: list[str] = []
    count_lines = 0
    for line in lines:
        if not line.strip():
            continue
        if match := IDENTITY_LINE_RE.fullmatch(line):
            if match.group(2) == requested:
                matches.append(match.group(1).upper())
        elif IDENTITY_COUNT_RE.fullmatch(line):
            count_lines += 1
        else:
            raise SigningPreflightError(
                "codesigning identity metadata has an unexpected line"
            )
    if len(matches) != 1 or count_lines != 1:
        raise SigningPreflightError(
            "requested Developer ID identity is missing or ambiguous"
        )
    return matches[0]


def _parse_certificate(
    data: bytes,
    *,
    expected_sha1: str,
) -> tuple[str, bytes]:
    begin = b"-----BEGIN CERTIFICATE-----\n"
    end = b"-----END CERTIFICATE-----\n"
    if not data.startswith(begin) or not data.endswith(end):
        raise SigningPreflightError(
            "Developer ID certificate output is not one canonical PEM certificate"
        )
    payload = data[len(begin) : -len(end)]
    lines = payload.splitlines()
    if (
        not payload
        or len(payload) > MAX_IDENTITY_BYTES
        or b"-----BEGIN" in payload
        or any(
            not line or len(line) > 64
            for line in lines
        )
    ):
        raise SigningPreflightError("Developer ID certificate PEM is malformed")
    try:
        certificate = base64.b64decode(b"".join(lines), validate=True)
    except (ValueError, binascii.Error) as error:
        raise SigningPreflightError(
            "Developer ID certificate PEM is not strict base64"
        ) from error
    if not certificate or len(certificate) > MAX_IDENTITY_BYTES:
        raise SigningPreflightError("Developer ID certificate size is invalid")
    observed_sha1 = hashlib.sha1(certificate).hexdigest().upper()
    if observed_sha1 != expected_sha1:
        raise SigningPreflightError(
            "Developer ID certificate does not match the selected identity"
        )
    return hashlib.sha256(certificate).hexdigest().upper(), certificate


def _expected_profile_entitlement_keys(role: str) -> frozenset[str]:
    if role == "host":
        return BASE_PROFILE_ENTITLEMENT_KEYS | {
            NETWORK_EXTENSION_KEY,
            SYSTEM_EXTENSION_INSTALL_KEY,
        }
    if role == "packet-tunnel":
        return BASE_PROFILE_ENTITLEMENT_KEYS | {NETWORK_EXTENSION_KEY}
    if role == "proxy-agent":
        return BASE_PROFILE_ENTITLEMENT_KEYS
    raise SigningPreflightError(f"unknown signing profile role: {role}")


def _validate_profile(
    profile: object,
    *,
    role: str,
    path: Path,
    file_identity: FileMetadata,
    file_sha256: str,
    expected_bundle_id: str,
    expected_uuid: str | None,
    selected_certificate_sha1: str,
    selected_certificate_sha256: str,
    selected_certificate: bytes,
    now: datetime,
) -> ProfilePreflight:
    if not isinstance(profile, dict) or set(profile) != PROFILE_TOP_LEVEL_KEYS:
        raise SigningPreflightError(
            f"{role} provisioning profile has an unexpected top-level schema"
        )
    if (
        profile["Version"] != 1
        or profile["IsXcodeManaged"] is not False
        or profile["PPQCheck"] is not False
        or not isinstance(profile["TimeToLive"], int)
        or isinstance(profile["TimeToLive"], bool)
        or profile["TimeToLive"] <= 0
        or profile["Platform"] != ["OSX"]
        or profile["ProvisionsAllDevices"] is not True
        or profile["TeamIdentifier"] != [TEAM_ID]
        or profile["ApplicationIdentifierPrefix"] != [TEAM_ID]
        or not isinstance(profile["DER-Encoded-Profile"], bytes)
        or not profile["DER-Encoded-Profile"]
    ):
        raise SigningPreflightError(
            f"{role} provisioning profile distribution schema is invalid"
        )
    name = _bounded_text(profile["Name"], f"{role} profile name")
    _bounded_text(profile["AppIDName"], f"{role} profile App ID name")
    _bounded_text(profile["TeamName"], f"{role} profile Team name")
    profile_uuid = _canonical_uuid(profile["UUID"], f"{role} profile UUID")
    if expected_uuid is not None and profile_uuid != expected_uuid:
        raise SigningPreflightError(
            f"{role} provisioning profile UUID does not match its fixed cache path"
        )

    creation = _utc(profile["CreationDate"], "creation date")
    expiration = _utc(profile["ExpirationDate"], "expiration date")
    current = _utc(now, "validation time")
    if creation > current:
        raise SigningPreflightError(
            f"{role} provisioning profile creation date is in the future"
        )
    if expiration <= current:
        raise SigningPreflightError(f"{role} provisioning profile has expired")
    if expiration <= creation:
        raise SigningPreflightError(
            f"{role} provisioning profile lifetime is invalid"
        )
    if expiration - creation != timedelta(days=profile["TimeToLive"]):
        raise SigningPreflightError(
            f"{role} provisioning profile lifetime does not match TimeToLive"
        )

    certificates = profile["DeveloperCertificates"]
    if (
        not isinstance(certificates, list)
        or not certificates
        or any(not isinstance(item, bytes) or not item for item in certificates)
    ):
        raise SigningPreflightError(
            f"{role} provisioning profile DeveloperCertificates are invalid"
        )
    fingerprints = tuple(
        sorted(hashlib.sha256(item).hexdigest().upper() for item in certificates)
    )
    if len(set(fingerprints)) != len(fingerprints):
        raise SigningPreflightError(
            f"{role} provisioning profile repeats a DeveloperCertificate"
        )
    matching = [
        item
        for item in certificates
        if item == selected_certificate
    ]
    if (
        len(matching) != 1
        or hashlib.sha1(matching[0]).hexdigest().upper()
        != selected_certificate_sha1
        or hashlib.sha256(matching[0]).hexdigest().upper()
        != selected_certificate_sha256
    ):
        raise SigningPreflightError(
            f"{role} provisioning profile does not contain the selected Developer ID certificate"
        )

    entitlements = profile["Entitlements"]
    expected_keys = _expected_profile_entitlement_keys(role)
    if not isinstance(entitlements, dict) or set(entitlements) != expected_keys:
        raise SigningPreflightError(
            f"{role} provisioning profile entitlement schema is invalid"
        )
    if (
        entitlements["com.apple.application-identifier"]
        != f"{TEAM_ID}.{expected_bundle_id}"
        or entitlements["com.apple.developer.team-identifier"] != TEAM_ID
        or _unique_string_set(
            entitlements["com.apple.security.application-groups"],
            f"{role} application groups",
        )
        != APP_GROUPS
        or entitlements["keychain-access-groups"] != TEAM_KEYCHAIN_GROUP
    ):
        raise SigningPreflightError(
            f"{role} provisioning profile identity or group authorization is invalid"
        )
    if role in {"host", "packet-tunnel"}:
        authorizations = _unique_string_set(
            entitlements[NETWORK_EXTENSION_KEY],
            f"{role} Network Extension authorizations",
        )
        if authorizations != KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS:
            raise SigningPreflightError(
                f"{role} provisioning profile Network Extension authorization differs"
            )
    if role == "host" and entitlements[SYSTEM_EXTENSION_INSTALL_KEY] is not True:
        raise SigningPreflightError(
            "host provisioning profile does not authorize System Extension installation"
        )

    return ProfilePreflight(
        role=role,
        path=str(path),
        file_sha256=file_sha256,
        file_size=file_identity.size,
        name=name,
        uuid=profile_uuid,
        bundle_id=expected_bundle_id,
        creation=creation.isoformat().replace("+00:00", "Z"),
        expiration=expiration.isoformat().replace("+00:00", "Z"),
        selected_certificate_sha256=selected_certificate_sha256,
        authorized_certificate_sha256=fingerprints,
    )


def _decode_and_validate_profile(
    path: Path,
    *,
    role: str,
    expected_bundle_id: str,
    expected_uuid: str | None,
    selected_certificate_sha1: str,
    selected_certificate_sha256: str,
    selected_certificate: bytes,
    now: datetime,
    owner: int,
    runner: ProcessRunner,
    repository: Path,
    environment: Mapping[str, str],
) -> ProfilePreflight:
    identity = _profile_file_identity(path, role, owner)
    digest = _hash_profile(path, identity)
    decoded = _run(
        [SECURITY, "cms", "-D", "-i", str(path)],
        f"{role} provisioning profile CMS decode",
        runner=runner,
        repository=repository,
        environment=environment,
        output_limit=MAX_CMS_BYTES,
    )
    try:
        profile = plistlib.loads(decoded)
    except (plistlib.InvalidFileException, ValueError, OverflowError) as error:
        raise SigningPreflightError(
            f"{role} provisioning profile CMS payload is not a plist"
        ) from error
    if _profile_file_identity(path, role, owner) != identity:
        raise SigningPreflightError(
            f"{role} provisioning profile changed during preflight"
        )
    return _validate_profile(
        profile,
        role=role,
        path=path,
        file_identity=identity,
        file_sha256=digest,
        expected_bundle_id=expected_bundle_id,
        expected_uuid=expected_uuid,
        selected_certificate_sha1=selected_certificate_sha1,
        selected_certificate_sha256=selected_certificate_sha256,
        selected_certificate=selected_certificate,
        now=now,
    )


def _probe_notary(
    *,
    profile: str,
    runner: ProcessRunner,
    repository: Path,
    environment: Mapping[str, str],
) -> None:
    if profile != NOTARY_PROFILE:
        raise SigningPreflightError(
            f"NOTARY_PROFILE must be exactly {NOTARY_PROFILE}"
        )
    output = _run(
        [
            XCRUN,
            "notarytool",
            "history",
            "--keychain-profile",
            profile,
            "--output-format",
            "json",
            "--no-progress",
        ],
        "notary profile history probe",
        runner=runner,
        repository=repository,
        environment=environment,
        output_limit=MAX_NOTARY_BYTES,
    )
    value = _strict_json(output, "notary profile history response")
    if (
        not isinstance(value, dict)
        or set(value) != {"history", "message"}
        or value["message"] != "Successfully received submission history."
        or not isinstance(value["history"], list)
        or len(value["history"]) > 100
    ):
        raise SigningPreflightError(
            "notary profile history response has an unexpected schema"
        )


def _inspect_updater_custody(
    home: Path,
    *,
    runner: ProcessRunner,
    repository: Path,
    environment: Mapping[str, str],
) -> tuple[tuple[FileMetadata, ...], FileMetadata, FileMetadata]:
    owner = os.getuid()
    home_identity = _require_directory(
        home,
        "release user home",
        owner=owner,
        exact_mode=None,
    )
    relative_directories = (
        Path("Library"),
        Path("Library/Application Support"),
        Path("Library/Application Support/Clash for Mac Release"),
        PRIVATE_KEY_RELATIVE.parent,
    )
    ancestors = [home_identity]
    for relative in relative_directories:
        ancestors.append(
            _require_directory(
                home / relative,
                "updater credential ancestor",
                owner=owner,
                exact_mode=0o700,
            )
        )
    key_path = home / PRIVATE_KEY_RELATIVE
    key = _require_regular_metadata(
        key_path,
        "updater private key",
        owner=owner,
        modes=frozenset({0o600}),
        maximum_size=1024 * 1024,
    )

    library = home / "Library"
    keychains_directory = home / LOGIN_KEYCHAIN_RELATIVE.parent
    _require_directory(
        library,
        "Library trust anchor",
        owner=owner,
        exact_mode=0o700,
    )
    keychains_mode = stat.S_IMODE(_lstat(keychains_directory, "Keychains directory").st_mode)
    if keychains_mode not in {0o700, 0o755}:
        raise SigningPreflightError("Keychains directory has a nonstandard mode")
    keychains = _require_directory(
        keychains_directory,
        "Keychains directory",
        owner=owner,
        exact_mode=keychains_mode,
    )
    keychain_path = home / LOGIN_KEYCHAIN_RELATIVE
    keychain = _require_regular_metadata(
        keychain_path,
        "login Keychain",
        owner=owner,
        modes=frozenset({0o600, 0o644}),
        maximum_size=512 * 1024 * 1024,
    )

    acl_paths = [Path(item.path) for item in ancestors[1:]] + [
        key_path,
        keychains_directory,
        keychain_path,
    ]
    for path in acl_paths:
        _require_acl(
            path,
            "updater custody path",
            runner=runner,
            repository=repository,
            environment=environment,
        )

    metadata = _run(
        [
            SECURITY,
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            str(keychain_path),
        ],
        "updater password Keychain metadata lookup",
        runner=runner,
        repository=repository,
        environment=environment,
        output_limit=MAX_KEYCHAIN_METADATA_BYTES,
    )
    try:
        rendered = metadata.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SigningPreflightError(
            "updater password Keychain metadata is not UTF-8"
        ) from error
    if (
        rendered.count(f'keychain: "{keychain_path}"') != 1
        or rendered.count('class: "genp"') != 1
        or rendered.count(f'"acct"<blob>="{KEYCHAIN_ACCOUNT}"') != 1
        or rendered.count(f'"svce"<blob>="{KEYCHAIN_SERVICE}"') != 1
        or '"sync"' in rendered
    ):
        raise SigningPreflightError(
            "updater password Keychain item is missing, duplicated, or synchronizable"
        )

    current_ancestors = [
        _require_directory(
            Path(item.path),
            "updater credential ancestor",
            owner=owner,
            exact_mode=(None if index == 0 else 0o700),
        )
        for index, item in enumerate(ancestors)
    ]
    current_key = _require_regular_metadata(
        key_path,
        "updater private key",
        owner=owner,
        modes=frozenset({0o600}),
        maximum_size=1024 * 1024,
    )
    current_keychain = _require_regular_metadata(
        keychain_path,
        "login Keychain",
        owner=owner,
        modes=frozenset({0o600, 0o644}),
        maximum_size=512 * 1024 * 1024,
    )
    current_keychains = _require_directory(
        keychains_directory,
        "Keychains directory",
        owner=owner,
        exact_mode=keychains_mode,
    )
    for path in acl_paths:
        _require_acl(
            path,
            "updater custody path",
            runner=runner,
            repository=repository,
            environment=environment,
        )
    if (
        current_ancestors != ancestors
        or current_key != key
        or current_keychain != keychain
        or current_keychains != keychains
    ):
        raise SigningPreflightError("updater custody metadata changed during preflight")
    # Keep the Keychains directory in the observed boundary even though it is
    # not an ancestor of the updater private-key path.
    return tuple([*ancestors, keychains]), key, keychain


def _required_environment(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None:
        raise SigningPreflightError(f"required release environment is missing {name}")
    return _bounded_text(value, name)


def _run_preflight_with_runtime(
    *,
    source_environment: Mapping[str, str],
    home: Path | None,
    repository: Path | None,
    runner: ProcessRunner,
    now: datetime | None,
) -> SigningPreflightResult:
    signing_identity = _required_environment(
        source_environment, "MACOS_SIGN_IDENTITY"
    )
    if not IDENTITY_RE.fullmatch(signing_identity):
        raise SigningPreflightError(
            f"MACOS_SIGN_IDENTITY is not a Developer ID Application identity for {TEAM_ID}"
        )
    host_profile_text = _required_environment(
        source_environment, "HOST_PROVISIONING_PROFILE_PATH"
    )
    host_profile = Path(host_profile_text)
    if not host_profile.is_absolute():
        raise SigningPreflightError("HOST_PROVISIONING_PROFILE_PATH must be absolute")
    proxy_uuid = _canonical_uuid(
        _required_environment(
            source_environment, "PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER"
        ),
        "ProxyAgent profile specifier",
    )
    packet_uuid = _canonical_uuid(
        _required_environment(
            source_environment, "PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER"
        ),
        "Packet Tunnel profile specifier",
    )
    notary_profile = _required_environment(source_environment, "NOTARY_PROFILE")

    fixed_home = _home_directory(home)
    fixed_repository = (
        Path(__file__).resolve().parent.parent if repository is None else repository
    )
    if not fixed_repository.is_absolute() or not fixed_repository.is_dir():
        raise SigningPreflightError("release repository is not an absolute directory")
    command_environment = _command_environment(fixed_home)
    keychain_path = fixed_home / LOGIN_KEYCHAIN_RELATIVE

    identity_output = _run(
        [SECURITY, "find-identity", "-v", "-p", "codesigning", str(keychain_path)],
        "Developer ID identity lookup",
        runner=runner,
        repository=fixed_repository,
        environment=command_environment,
        output_limit=MAX_IDENTITY_BYTES,
    )
    certificate_sha1 = _parse_identity_listing(identity_output, signing_identity)
    certificate_output = _run(
        [
            SECURITY,
            "find-certificate",
            "-c",
            signing_identity,
            "-p",
            str(keychain_path),
        ],
        "Developer ID certificate metadata lookup",
        runner=runner,
        repository=fixed_repository,
        environment=command_environment,
        output_limit=MAX_IDENTITY_BYTES,
    )
    certificate_sha256, certificate = _parse_certificate(
        certificate_output,
        expected_sha1=certificate_sha1,
    )

    cache = fixed_home / "Library/Developer/Xcode/UserData/Provisioning Profiles"
    proxy_profile = cache / f"{proxy_uuid}.provisionprofile"
    packet_profile = cache / f"{packet_uuid}.provisionprofile"
    validation_time = now or datetime.now(timezone.utc)
    owner = os.getuid()
    profiles = (
        _decode_and_validate_profile(
            host_profile,
            role="host",
            expected_bundle_id=HOST_BUNDLE_ID,
            expected_uuid=None,
            selected_certificate_sha1=certificate_sha1,
            selected_certificate_sha256=certificate_sha256,
            selected_certificate=certificate,
            now=validation_time,
            owner=owner,
            runner=runner,
            repository=fixed_repository,
            environment=command_environment,
        ),
        _decode_and_validate_profile(
            packet_profile,
            role="packet-tunnel",
            expected_bundle_id=PACKET_TUNNEL_BUNDLE_ID,
            expected_uuid=packet_uuid,
            selected_certificate_sha1=certificate_sha1,
            selected_certificate_sha256=certificate_sha256,
            selected_certificate=certificate,
            now=validation_time,
            owner=owner,
            runner=runner,
            repository=fixed_repository,
            environment=command_environment,
        ),
        _decode_and_validate_profile(
            proxy_profile,
            role="proxy-agent",
            expected_bundle_id=PROXY_AGENT_BUNDLE_ID,
            expected_uuid=proxy_uuid,
            selected_certificate_sha1=certificate_sha1,
            selected_certificate_sha256=certificate_sha256,
            selected_certificate=certificate,
            now=validation_time,
            owner=owner,
            runner=runner,
            repository=fixed_repository,
            environment=command_environment,
        ),
    )

    _probe_notary(
        profile=notary_profile,
        runner=runner,
        repository=fixed_repository,
        environment=_command_environment(fixed_home, notary=True),
    )
    updater_ancestors, updater_key, login_keychain = _inspect_updater_custody(
        fixed_home,
        runner=runner,
        repository=fixed_repository,
        environment=command_environment,
    )
    return SigningPreflightResult(
        signing_identity=signing_identity,
        certificate_sha1=certificate_sha1,
        certificate_sha256=certificate_sha256,
        profiles=profiles,
        notary_profile=notary_profile,
        updater_ancestors=updater_ancestors,
        updater_key=updater_key,
        login_keychain=login_keychain,
    )


def run_preflight(
    *,
    source_environment: Mapping[str, str] | None = None,
) -> SigningPreflightResult:
    """Run the production preflight with source-fixed tools and local paths."""

    return _run_preflight_with_runtime(
        source_environment=(
            os.environ if source_environment is None else source_environment
        ),
        home=None,
        repository=None,
        runner=run_bounded_process,
        now=None,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit a canonical nonsecret release-signing preflight manifest."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--output", type=Path)
    mode.add_argument("--verify-manifest", type=Path)
    mode.add_argument("--print-certificate-sha1", type=Path)
    mode.add_argument("--print-certificate-sha256", type=Path)
    parser.add_argument("--host-profile", type=Path)
    parser.add_argument("--proxy-agent-profile", type=Path)
    parser.add_argument("--packet-tunnel-profile", type=Path)
    arguments = parser.parse_args(argv)
    materialized_paths = (
        arguments.host_profile,
        arguments.proxy_agent_profile,
        arguments.packet_tunnel_profile,
    )
    if arguments.verify_manifest is None and any(
        path is not None for path in materialized_paths
    ):
        parser.error("materialized profiles require --verify-manifest")
    if arguments.verify_manifest is not None and any(
        path is None for path in materialized_paths
    ):
        parser.error("--verify-manifest requires all three materialized profiles")
    if arguments.verify_manifest is not None:
        try:
            verify_materialized_profiles(
                arguments.verify_manifest,
                {
                    "host": arguments.host_profile,
                    "proxy-agent": arguments.proxy_agent_profile,
                    "packet-tunnel": arguments.packet_tunnel_profile,
                },
            )
        except SigningPreflightError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        print("materialized release provisioning profiles verified")
        return 0
    if arguments.print_certificate_sha1 is not None:
        try:
            certificate_sha1, _certificate_sha256 = signing_certificate_digests(
                arguments.print_certificate_sha1
            )
        except SigningPreflightError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        print(certificate_sha1)
        return 0
    if arguments.print_certificate_sha256 is not None:
        try:
            _certificate_sha1, certificate_sha256 = signing_certificate_digests(
                arguments.print_certificate_sha256
            )
        except SigningPreflightError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        print(certificate_sha256)
        return 0
    try:
        result = run_preflight()
    except SigningPreflightError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if arguments.output is None:
        sys.stdout.buffer.write(result.canonical_manifest())
    else:
        try:
            write_preflight_manifest(arguments.output, result)
        except SigningPreflightError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DOCUMENT",
    "NOTARY_PROFILE",
    "SigningPreflightError",
    "SigningPreflightResult",
    "canonical_manifest",
    "load_preflight_manifest",
    "run_preflight",
    "signing_certificate_digests",
    "verify_custody_metadata",
    "verify_materialized_profiles",
    "write_preflight_manifest",
]
