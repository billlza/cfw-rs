#!/usr/bin/env python3
"""Create and verify the fixed, freeze-bound GA signing plan.

The tracked native signing-order document is the architecture authority.  This
module binds that document to the exact provisioning profiles and generated
release xcent files without performing a signing operation.  Candidate freeze
recomputes the component digests through this module instead of trusting
caller-supplied digest strings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Final, Mapping, Sequence

if __package__:
    from .macos_durability import full_fsync
    from .release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        ga_preflight_root,
        ga_root,
    )
else:
    from macos_durability import full_fsync
    from release_build_identity import ACTIVE_RELEASE_IDENTITY, ga_preflight_root, ga_root


DOCUMENT: Final = "cfm-ga-signing-plan-v1"
SCHEMA_VERSION: Final = 1
SOURCE_PLAN_RELATIVE: Final = Path("native/macos/Config/signing-order.json")
PLAN_RELATIVE: Final = Path("signing-plan.json")
COMPONENT_ORDER: Final = (
    "native-bridge",
    "global-authority",
    "proxy-agent",
    "packet-tunnel",
    "legacy-tombstone",
    "host",
)
COMPONENT_INPUTS: Final[dict[str, tuple[str | None, str | None]]] = {
    "native-bridge": (None, None),
    "global-authority": ("entitlements/GlobalAuthority.entitlements", None),
    "proxy-agent": (
        "entitlements/ProxyAgent.release.xcent",
        "profiles/proxy-agent.provisionprofile",
    ),
    "packet-tunnel": (
        "entitlements/PacketTunnel.release.xcent",
        "profiles/packet-tunnel.provisionprofile",
    ),
    "legacy-tombstone": (None, None),
    "host": (
        "entitlements/Host.release.xcent",
        "profiles/host.provisionprofile",
    ),
}
PLAN_FIELDS: Final = frozenset(
    {"components", "document", "order", "product", "schema_version"}
)
PRODUCT_FIELDS: Final = frozenset({"build_number", "version"})
SOURCE_PLAN_FIELDS: Final = frozenset(
    {"description", "nested", "outer", "schemaVersion", "teamIdentifier"}
)
MAX_INPUT_BYTES: Final = 4 * 1024 * 1024


class SigningPlanError(ValueError):
    """The fixed signing plan or one of its material inputs is invalid."""


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        raise SigningPlanError("signing plan cannot be canonical JSON") from error
    return encoded + b"\n"


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SigningPlanError(f"signing plan input repeats field {key!r}")
        result[key] = value
    return result


def _reject_constant(token: str) -> Any:
    raise SigningPlanError(f"signing plan input contains {token}")


def _read_regular(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SigningPlanError(f"{label} is unavailable: {path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_size < 1
        or metadata.st_size > MAX_INPUT_BYTES
    ):
        raise SigningPlanError(f"{label} is not a bounded owned regular file")
    try:
        data = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise SigningPlanError(f"cannot read {label}: {path}") from error
    if _file_identity(metadata) != _file_identity(after) or len(data) != metadata.st_size:
        raise SigningPlanError(f"{label} changed while it was read")
    return data


def _strict_json(path: Path, label: str, *, canonical: bool) -> dict[str, Any]:
    data = _read_regular(path, label)
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except SigningPlanError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SigningPlanError(f"{label} is not strict JSON") from error
    if type(value) is not dict:
        raise SigningPlanError(f"{label} is not a JSON object")
    if canonical and data != canonical_json(value):
        raise SigningPlanError(f"{label} is not canonical JSON")
    return value


def _sha256(path: Path, label: str) -> str:
    return hashlib.sha256(_read_regular(path, label)).hexdigest()


def _source_plan_sha256(repository: Path, candidate_root: Path) -> str:
    source = repository / SOURCE_PLAN_RELATIVE
    candidate = candidate_root / "entitlements/signing-order.json"
    source_value = _strict_json(source, "tracked signing-order document", canonical=False)
    if set(source_value) != SOURCE_PLAN_FIELDS:
        raise SigningPlanError("tracked signing-order document field set changed")
    if (
        source_value["schemaVersion"] != 1
        or source_value["teamIdentifier"] != "YKUPL7Z869"
        or type(source_value["nested"]) is not list
        or len(source_value["nested"]) != 5
        or type(source_value["outer"]) is not dict
        or source_value["outer"].get("signedLast") is not True
    ):
        raise SigningPlanError("tracked signing-order document is incompatible")
    source_data = _read_regular(source, "tracked signing-order document")
    candidate_data = _read_regular(candidate, "candidate signing-order document")
    if candidate_data != source_data:
        raise SigningPlanError("candidate signing-order document differs from source")
    return hashlib.sha256(source_data).hexdigest()


def _component_digest(
    candidate_root: Path,
    component: str,
    source_plan_sha256: str,
) -> str:
    entitlement_relative, profile_relative = COMPONENT_INPUTS[component]
    payload = {
        "component": component,
        "entitlements_sha256": (
            None
            if entitlement_relative is None
            else _sha256(
                candidate_root / entitlement_relative,
                f"{component} release entitlements",
            )
        ),
        "profile_sha256": (
            None
            if profile_relative is None
            else _sha256(
                candidate_root / profile_relative,
                f"{component} provisioning profile",
            )
        ),
        "source_plan_sha256": source_plan_sha256,
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def expected_plan(repository: Path, candidate_root: Path) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    candidate_root = candidate_root.resolve(strict=True)
    source_plan_sha256 = _source_plan_sha256(repository, candidate_root)
    return {
        "components": {
            component: _component_digest(
                candidate_root, component, source_plan_sha256
            )
            for component in COMPONENT_ORDER
        },
        "document": DOCUMENT,
        "order": list(COMPONENT_ORDER),
        "product": {
            "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            "version": ACTIVE_RELEASE_IDENTITY.product_version,
        },
        "schema_version": SCHEMA_VERSION,
    }


def validate_plan(
    repository: Path,
    candidate_root: Path,
    value: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    expected = expected_plan(repository, candidate_root)
    if value is None:
        observed = _strict_json(
            candidate_root / PLAN_RELATIVE,
            "candidate signing plan",
            canonical=True,
        )
    else:
        observed = dict(value)
    if set(observed) != PLAN_FIELDS:
        raise SigningPlanError("candidate signing plan field set changed")
    product = observed.get("product")
    if type(product) is not dict or set(product) != PRODUCT_FIELDS:
        raise SigningPlanError("candidate signing plan product field set changed")
    if observed != expected:
        raise SigningPlanError(
            "candidate signing plan differs from the fixed signing inputs"
        )
    return observed


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short signing-plan write")
        offset += written


def create_plan(repository: Path, candidate_root: Path) -> Path:
    plan = expected_plan(repository, candidate_root)
    destination = candidate_root / PLAN_RELATIVE
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(destination, flags, 0o600)
        _write_all(descriptor, canonical_json(plan))
        full_fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        parent = os.open(
            destination.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            full_fsync(parent)
        finally:
            os.close(parent)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise SigningPlanError("cannot durably create candidate signing plan") from error
    validate_plan(repository, candidate_root)
    return destination


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("create", "verify-preflight", "verify-frozen"))
    arguments = parser.parse_args(argv)
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "create":
            path = create_plan(repository, ga_preflight_root(repository))
            print(f"GA signing plan created: {path.relative_to(repository)}")
        elif arguments.command == "verify-preflight":
            validate_plan(repository, ga_preflight_root(repository))
            print("GA preflight signing plan verified")
        else:
            validate_plan(repository, ga_root(repository))
            print("frozen GA signing plan verified")
    except (OSError, SigningPlanError, ValueError) as error:
        raise SystemExit(f"error: GA signing plan: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
