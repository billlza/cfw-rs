#!/usr/bin/env python3
"""Prove that Developer ID signing changed only signatures and fixed profiles.

The frozen and signed Host applications are copied into private temporary
directories.  The fixed six code objects are normalized with the system
``codesign --remove-signature`` operation, the three exact embedded profiles
are removed only from the signed copy, and the resulting tree-v2 manifests
must be identical.  A durable receipt records the exact transformation before
the first app-notarization submission is allowed to start.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import tempfile
from typing import Any, Callable, Final, Sequence

if __package__:
    from .candidate_freeze import (
        CandidateFreezeError,
        FrozenCandidate,
        verify_frozen_candidate,
    )
    from .hash_artifact import build_manifest
    from .publication.bounded_process import (
        BoundedProcessError,
        run_bounded_process,
    )
    from .publication.common import PublicationError
    from .publication.durable_file import (
        RootedDirectoryChanged,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from .release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        SIGNED_APP_WITHIN_OUTPUT,
        SIGNING_OUTPUT_RELATIVE,
        candidate_signing_output,
        ga_root,
    )
    from .release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )
else:
    from candidate_freeze import (
        CandidateFreezeError,
        FrozenCandidate,
        verify_frozen_candidate,
    )
    from hash_artifact import build_manifest
    from publication.bounded_process import BoundedProcessError, run_bounded_process
    from publication.common import PublicationError
    from publication.durable_file import (
        RootedDirectoryChanged,
        exclusive_rooted_directory_lock,
        read_private_pending_locked,
        write_private_pending_locked,
    )
    from release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        SIGNED_APP_WITHIN_OUTPUT,
        SIGNING_OUTPUT_RELATIVE,
        candidate_signing_output,
        ga_root,
    )
    from release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )


DOCUMENT: Final = "cfm-ga-signing-transformation-v2"
SCHEMA_VERSION: Final = 2
RECEIPT_NAME: Final = "signing-transformation.json"
RECEIPT_RELATIVE: Final = SIGNING_OUTPUT_RELATIVE / RECEIPT_NAME
PRE_SIGN_APP_RELATIVE: Final = Path("pre-sign/Clash for Mac.app")
PRE_SIGN_MANIFEST_RELATIVE: Final = Path(
    "pre-sign/Clash for Mac.app.manifest.json"
)
SIGNED_APP_RELATIVE: Final = SIGNING_OUTPUT_RELATIVE / SIGNED_APP_WITHIN_OUTPUT
MAX_JSON_BYTES: Final = 64 * 1024 * 1024
MAX_PROFILE_BYTES: Final = 16 * 1024 * 1024
MAX_MACHO_BYTES: Final = 512 * 1024 * 1024
MAX_CODESIGN_OUTPUT: Final = 1024 * 1024
SHA256_RE: Final = re.compile(r"\A[0-9a-f]{64}\Z")

MH_MAGIC_64: Final = 0xFEEDFACF
CPU_TYPE_ARM64: Final = 0x0100000C
MH_EXECUTE: Final = 0x2
MH_DYLIB: Final = 0x6
LC_SEGMENT_64: Final = 0x19
LC_CODE_SIGNATURE: Final = 0x1D
MACH_HEADER_64_SIZE: Final = 32
SEGMENT_COMMAND_64_SIZE: Final = 72
SECTION_64_SIZE: Final = 80
LINKEDIT_DATA_COMMAND_SIZE: Final = 16
ARM64_SEGMENT_ALIGNMENT: Final = 0x4000
LINKEDIT_SEGMENT_NAME: Final = b"__LINKEDIT" + (b"\0" * 6)


@dataclass(frozen=True)
class _CodeObjectSpec:
    code_object: str
    executable: str
    signature_directory: str | None


# This order is the frozen signing-plan order: all nested objects, then Host.
CODE_OBJECT_SPECS: Final = (
    _CodeObjectSpec(
        code_object="Contents/Frameworks/CFWNativeBridge.framework",
        executable=(
            "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/"
            "CFWNativeBridge"
        ),
        signature_directory=(
            "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/"
            "_CodeSignature"
        ),
    ),
    _CodeObjectSpec(
        code_object="Contents/Library/HelperTools/CFWGlobalAuthority",
        executable="Contents/Library/HelperTools/CFWGlobalAuthority",
        signature_directory=None,
    ),
    _CodeObjectSpec(
        code_object="Contents/Library/LoginItems/CFWProxyAgent.app",
        executable=(
            "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/"
            "CFWProxyAgent"
        ),
        signature_directory=(
            "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/"
            "_CodeSignature"
        ),
    ),
    _CodeObjectSpec(
        code_object=(
            "Contents/Library/SystemExtensions/"
            "com.bill.clashformac.packet-tunnel.systemextension"
        ),
        executable=(
            "Contents/Library/SystemExtensions/"
            "com.bill.clashformac.packet-tunnel.systemextension/Contents/MacOS/"
            "CFWPacketTunnel"
        ),
        signature_directory=(
            "Contents/Library/SystemExtensions/"
            "com.bill.clashformac.packet-tunnel.systemextension/Contents/"
            "_CodeSignature"
        ),
    ),
    _CodeObjectSpec(
        code_object="Contents/Library/HelperTools/cfw-helper-tombstone",
        executable="Contents/Library/HelperTools/cfw-helper-tombstone",
        signature_directory=None,
    ),
    _CodeObjectSpec(
        code_object=".",
        executable="Contents/MacOS/clash-for-mac",
        signature_directory="Contents/_CodeSignature",
    ),
)
CODE_OBJECTS: Final = tuple(spec.code_object for spec in CODE_OBJECT_SPECS)
MACHO_EXECUTABLES: Final = tuple(
    spec.executable for spec in CODE_OBJECT_SPECS
)
DIRECTORY_CODE_OBJECTS: Final = frozenset(
    spec.code_object
    for spec in CODE_OBJECT_SPECS
    if spec.signature_directory is not None
)
SIGNATURE_DIRECTORY_BY_CODE_OBJECT: Final = {
    spec.code_object: spec.signature_directory
    for spec in CODE_OBJECT_SPECS
    if spec.signature_directory is not None
}
SIGNATURE_DIRECTORIES: Final = tuple(
    SIGNATURE_DIRECTORY_BY_CODE_OBJECT.values()
)
PROFILE_BINDINGS: Final = {
    "host": (
        "profiles/host.provisionprofile",
        "Contents/embedded.provisionprofile",
    ),
    "proxy_agent": (
        "profiles/proxy-agent.provisionprofile",
        (
            "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/"
            "embedded.provisionprofile"
        ),
    ),
    "packet_tunnel": (
        "profiles/packet-tunnel.provisionprofile",
        (
            "Contents/Library/SystemExtensions/"
            "com.bill.clashformac.packet-tunnel.systemextension/Contents/"
            "embedded.provisionprofile"
        ),
    ),
}
EMBEDDED_PROFILE_PATHS: Final = tuple(
    binding[1] for binding in PROFILE_BINDINGS.values()
)
RECEIPT_FIELDS: Final = frozenset(
    {
        "candidate_freeze_intent_sha256",
        "code_objects",
        "document",
        "normalized_app_tree_sha256",
        "pre_sign_app_manifest_sha256",
        "pre_sign_app_tree_sha256",
        "product",
        "profiles",
        "removed_signed_profiles",
        "schema_version",
        "signed_app_tree_sha256",
    }
)


class SigningTransformationError(RuntimeError):
    """The signed Host app cannot be proven equivalent to its frozen input."""


class SigningTransformationOutcomeUnknown(SigningTransformationError):
    """Receipt bytes may exist but their publication reply was not durable."""


CodeSignRunner = Callable[[tuple[str, ...], Path], None]
FreezeVerifier = Callable[[Path], FrozenCandidate]


@dataclass(frozen=True)
class _MachOLayout:
    cpu_subtype: int
    file_type: int
    file_size: int
    ncmds: int
    sizeofcmds: int
    linkedit_command_offset: int
    linkedit_vmaddr: int
    linkedit_vmsize: int
    linkedit_fileoff: int
    linkedit_filesize: int
    code_signature_command_offset: int | None
    code_signature_dataoff: int | None
    code_signature_datasize: int | None
    code_signature_prefix: bytes | None


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
        raise SigningTransformationError(
            "signing-transformation receipt cannot be canonical JSON"
        ) from error
    return encoded + b"\n"


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SigningTransformationError(
                f"signing-transformation JSON repeats field {key!r}"
            )
        result[key] = value
    return result


def _reject_constant(token: str) -> Any:
    raise SigningTransformationError(
        f"signing-transformation JSON contains non-finite constant {token}"
    )


def _parse_json(data: bytes, label: str, *, canonical: bool) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except SigningTransformationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SigningTransformationError(f"{label} is not strict JSON") from error
    if type(value) is not dict:
        raise SigningTransformationError(f"{label} is not a JSON object")
    if canonical and data != canonical_json(value):
        raise SigningTransformationError(f"{label} is not canonical JSON")
    return value


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


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
    )


def _read_regular(path: Path, label: str, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise SigningTransformationError(f"{label} is unavailable: {path}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_size < 1
        or before.st_size > maximum
    ):
        raise SigningTransformationError(
            f"{label} is not one bounded owned regular file"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise SigningTransformationError(f"{label} changed while opening")
        remaining = before.st_size + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        rebound = path.stat(follow_symlinks=False)
    except OSError as error:
        raise SigningTransformationError(f"cannot securely read {label}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(data) != before.st_size
        or _file_identity(after) != _file_identity(before)
        or _file_identity(rebound) != _file_identity(before)
    ):
        raise SigningTransformationError(f"{label} changed while reading")
    return data


def _align_up(value: int, alignment: int) -> int:
    if value < 0 or alignment <= 0 or alignment & (alignment - 1):
        raise SigningTransformationError("Mach-O alignment contract is invalid")
    return (value + alignment - 1) & ~(alignment - 1)


def _parse_macho(data: bytes, label: str) -> _MachOLayout:
    if len(data) < MACH_HEADER_64_SIZE or len(data) > MAX_MACHO_BYTES:
        raise SigningTransformationError(
            f"{label} is not one bounded thin arm64 Mach-O"
        )
    try:
        (
            magic,
            cpu_type,
            cpu_subtype,
            file_type,
            ncmds,
            sizeofcmds,
            _flags,
            _reserved,
        ) = struct.unpack_from("<8I", data, 0)
    except struct.error as error:
        raise SigningTransformationError(f"{label} Mach-O header is malformed") from error
    if (
        magic != MH_MAGIC_64
        or cpu_type != CPU_TYPE_ARM64
        or file_type not in {MH_EXECUTE, MH_DYLIB}
    ):
        raise SigningTransformationError(
            f"{label} is not one supported thin arm64 Mach-O"
        )
    commands_end = MACH_HEADER_64_SIZE + sizeofcmds
    if (
        ncmds < 1
        or sizeofcmds < ncmds * 8
        or sizeofcmds % 8 != 0
        or commands_end > len(data)
    ):
        raise SigningTransformationError(f"{label} Mach-O load commands are malformed")

    linkedit: tuple[int, int, int, int, int] | None = None
    code_signature: tuple[int, int, int] | None = None
    offset = MACH_HEADER_64_SIZE
    for _index in range(ncmds):
        if offset + 8 > commands_end:
            raise SigningTransformationError(
                f"{label} Mach-O load command header is out of bounds"
            )
        command, command_size = struct.unpack_from("<2I", data, offset)
        next_offset = offset + command_size
        if (
            command_size < 8
            or command_size % 8 != 0
            or next_offset > commands_end
        ):
            raise SigningTransformationError(
                f"{label} Mach-O load command is out of bounds"
            )
        if command == LC_SEGMENT_64:
            if command_size < SEGMENT_COMMAND_64_SIZE:
                raise SigningTransformationError(
                    f"{label} Mach-O segment command is truncated"
                )
            section_count = struct.unpack_from("<I", data, offset + 64)[0]
            expected_size = SEGMENT_COMMAND_64_SIZE + section_count * SECTION_64_SIZE
            if command_size != expected_size:
                raise SigningTransformationError(
                    f"{label} Mach-O segment section inventory is malformed"
                )
            segment_name = data[offset + 8 : offset + 24]
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<4Q", data, offset + 24
            )
            if fileoff > len(data) or filesize > len(data) - fileoff:
                raise SigningTransformationError(
                    f"{label} Mach-O segment file range is out of bounds"
                )
            if segment_name == LINKEDIT_SEGMENT_NAME:
                if linkedit is not None or section_count != 0 or vmsize < filesize:
                    raise SigningTransformationError(
                        f"{label} Mach-O __LINKEDIT segment is malformed"
                    )
                linkedit = (offset, vmaddr, vmsize, fileoff, filesize)
        elif command == LC_CODE_SIGNATURE:
            if command_size != LINKEDIT_DATA_COMMAND_SIZE or code_signature is not None:
                raise SigningTransformationError(
                    f"{label} Mach-O code-signature command is malformed"
                )
            dataoff, datasize = struct.unpack_from("<2I", data, offset + 8)
            code_signature = (offset, dataoff, datasize)
        offset = next_offset
    if offset != commands_end:
        raise SigningTransformationError(
            f"{label} Mach-O load-command inventory is malformed"
        )
    if linkedit is None:
        raise SigningTransformationError(
            f"{label} Mach-O must contain exactly one __LINKEDIT segment"
        )

    (
        linkedit_command_offset,
        linkedit_vmaddr,
        linkedit_vmsize,
        linkedit_fileoff,
        linkedit_filesize,
    ) = linkedit
    if code_signature is None:
        code_signature_command_offset = None
        code_signature_dataoff = None
        code_signature_datasize = None
        code_signature_prefix = None
    else:
        (
            code_signature_command_offset,
            code_signature_dataoff,
            code_signature_datasize,
        ) = code_signature
        code_signature_prefix = (
            data[max(linkedit_fileoff, code_signature_dataoff - 15) : code_signature_dataoff]
            if code_signature_dataoff <= len(data)
            else b""
        )
    return _MachOLayout(
        cpu_subtype=cpu_subtype,
        file_type=file_type,
        file_size=len(data),
        ncmds=ncmds,
        sizeofcmds=sizeofcmds,
        linkedit_command_offset=linkedit_command_offset,
        linkedit_vmaddr=linkedit_vmaddr,
        linkedit_vmsize=linkedit_vmsize,
        linkedit_fileoff=linkedit_fileoff,
        linkedit_filesize=linkedit_filesize,
        code_signature_command_offset=code_signature_command_offset,
        code_signature_dataoff=code_signature_dataoff,
        code_signature_datasize=code_signature_datasize,
        code_signature_prefix=code_signature_prefix,
    )


def _validate_signed_macho(data: bytes, label: str) -> _MachOLayout:
    layout = _parse_macho(data, label)
    command_offset = layout.code_signature_command_offset
    dataoff = layout.code_signature_dataoff
    datasize = layout.code_signature_datasize
    if command_offset is None or dataoff is None or datasize is None:
        raise SigningTransformationError(
            f"{label} does not contain one fixed code-signature command"
        )
    if (
        command_offset + LINKEDIT_DATA_COMMAND_SIZE
        != MACH_HEADER_64_SIZE + layout.sizeofcmds
        or dataoff % 16 != 0
        or datasize < 16
        or datasize % 16 != 0
        or dataoff < layout.linkedit_fileoff
        or dataoff + datasize != layout.file_size
        or layout.linkedit_fileoff + layout.linkedit_filesize != layout.file_size
        or layout.linkedit_fileoff % ARM64_SEGMENT_ALIGNMENT != 0
        or layout.linkedit_vmaddr % ARM64_SEGMENT_ALIGNMENT != 0
        or layout.linkedit_vmsize
        != _align_up(layout.linkedit_filesize, ARM64_SEGMENT_ALIGNMENT)
    ):
        raise SigningTransformationError(
            f"{label} code signature is not the fixed __LINKEDIT tail"
        )
    return layout


def _inspect_signed_macho(path: Path, label: str) -> _MachOLayout:
    return _validate_signed_macho(_read_regular(path, label, MAX_MACHO_BYTES), label)


def _patch_regular_file(
    path: Path,
    *,
    offset: int,
    expected: bytes,
    replacement: bytes,
    label: str,
) -> None:
    if len(expected) != len(replacement) or not expected:
        raise SigningTransformationError("Mach-O normalization patch is malformed")
    if expected == replacement:
        return
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 1
            or before.st_size > MAX_MACHO_BYTES
            or offset < 0
            or offset + len(expected) > before.st_size
        ):
            raise SigningTransformationError(
                f"{label} is not one writable private Mach-O copy"
            )
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _stable_file_identity(opened) != _stable_file_identity(before):
            raise SigningTransformationError(f"{label} changed while opening")
        if os.pread(descriptor, len(expected), offset) != expected:
            raise SigningTransformationError(
                f"{label} normalization field changed before replacement"
            )
        if os.pwrite(descriptor, replacement, offset) != len(replacement):
            raise SigningTransformationError(
                f"{label} normalization write made incomplete progress"
            )
        if os.pread(descriptor, len(replacement), offset) != replacement:
            raise SigningTransformationError(
                f"{label} normalization bytes cannot be reopened"
            )
        after = os.fstat(descriptor)
        rebound = path.stat(follow_symlinks=False)
        if (
            _stable_file_identity(after) != _stable_file_identity(before)
            or _stable_file_identity(rebound) != _stable_file_identity(before)
        ):
            raise SigningTransformationError(
                f"{label} changed while normalizing its signature envelope"
            )
    except OSError as error:
        raise SigningTransformationError(
            f"cannot normalize {label} in the private comparison copy"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _normalize_removed_signature_macho(
    path: Path,
    label: str,
    signed: _MachOLayout,
) -> None:
    data = _read_regular(path, label, MAX_MACHO_BYTES)
    unsigned = _parse_macho(data, label)
    dataoff = signed.code_signature_dataoff
    signature_prefix = signed.code_signature_prefix
    if dataoff is None or signature_prefix is None:
        raise SigningTransformationError(
            f"{label} signed Mach-O binding lost its signature offset"
        )
    signature_alignment_padding = dataoff - unsigned.file_size
    expected_filesize = unsigned.file_size - signed.linkedit_fileoff
    canonical_vmsize = _align_up(expected_filesize, ARM64_SEGMENT_ALIGNMENT)
    if (
        unsigned.code_signature_command_offset is not None
        or unsigned.code_signature_dataoff is not None
        or unsigned.code_signature_datasize is not None
        or unsigned.code_signature_prefix is not None
        or unsigned.cpu_subtype != signed.cpu_subtype
        or unsigned.file_type != signed.file_type
        or signature_alignment_padding < 0
        or signature_alignment_padding >= 16
        or not signature_prefix.endswith(b"\0" * signature_alignment_padding)
        or unsigned.ncmds != signed.ncmds - 1
        or unsigned.sizeofcmds != signed.sizeofcmds - LINKEDIT_DATA_COMMAND_SIZE
        or unsigned.linkedit_command_offset != signed.linkedit_command_offset
        or unsigned.linkedit_vmaddr != signed.linkedit_vmaddr
        or unsigned.linkedit_fileoff != signed.linkedit_fileoff
        or unsigned.linkedit_filesize != expected_filesize
        or unsigned.linkedit_fileoff + unsigned.linkedit_filesize
        != unsigned.file_size
        or unsigned.linkedit_vmsize not in {signed.linkedit_vmsize, canonical_vmsize}
    ):
        raise SigningTransformationError(
            f"{label} changed outside the removable Mach-O signature envelope"
        )

    field_offset = unsigned.linkedit_command_offset + 32
    _patch_regular_file(
        path,
        offset=field_offset,
        expected=struct.pack("<Q", unsigned.linkedit_vmsize),
        replacement=struct.pack("<Q", canonical_vmsize),
        label=label,
    )
    reopened = _parse_macho(_read_regular(path, label, MAX_MACHO_BYTES), label)
    if reopened != replace(unsigned, linkedit_vmsize=canonical_vmsize):
        raise SigningTransformationError(
            f"{label} Mach-O signature-envelope normalization is not exact"
        )


def _canonical_repository(repository: Path) -> Path:
    repository = Path(repository)
    try:
        resolved = repository.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        raise SigningTransformationError("release repository is unavailable") from error
    if (
        not repository.is_absolute()
        or repository != resolved
        or resolved.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise SigningTransformationError(
            "release repository must be one canonical owned directory"
        )
    return resolved


def _signing_output_path(
    repository: Path,
    signing_output: Path | None,
) -> Path:
    """Accept only the canonical output or one fixed private attempt workspace."""

    selected = (
        ga_root(repository) / SIGNING_OUTPUT_RELATIVE
        if signing_output is None
        else signing_output
    )
    try:
        return candidate_signing_output(repository, selected).root
    except (OSError, ValueError) as error:
        raise SigningTransformationError(
            f"signing-output path is invalid: {error}"
        ) from error


def _freeze_inputs(
    repository: Path,
    verifier: FreezeVerifier,
) -> tuple[FrozenCandidate, dict[str, Any]]:
    try:
        frozen = verifier(repository)
    except CandidateFreezeError as error:
        raise SigningTransformationError(
            f"active GA candidate freeze cannot be verified: {error}"
        ) from error
    root = ga_root(repository)
    expected_intent = root / "candidate-freeze/intent.json"
    if (
        not isinstance(frozen, FrozenCandidate)
        or frozen.root != root
        or frozen.intent_path != expected_intent
        or frozen.product_version != ACTIVE_RELEASE_IDENTITY.product_version
        or frozen.build_number != ACTIVE_RELEASE_IDENTITY.ga_build
        or SHA256_RE.fullmatch(frozen.intent_sha256) is None
    ):
        raise SigningTransformationError(
            "candidate freeze differs from the single active GA identity"
        )
    raw = _read_regular(expected_intent, "candidate-freeze intent", MAX_JSON_BYTES)
    if hashlib.sha256(raw).hexdigest() != frozen.intent_sha256:
        raise SigningTransformationError("candidate-freeze intent changed after verification")
    intent = _parse_json(raw, "candidate-freeze intent", canonical=True)
    if (
        intent.get("document") != "cfm-candidate-freeze-intent-v3"
        or type(intent.get("schema_version")) is not int
        or intent.get("schema_version") != 3
        or intent.get("consumption_state") != "candidate_frozen_consumed"
        or intent.get("product_version") != ACTIVE_RELEASE_IDENTITY.product_version
        or intent.get("build_number") != ACTIVE_RELEASE_IDENTITY.ga_build
        or not isinstance(intent.get("pre_sign_app_tree_sha256"), str)
        or SHA256_RE.fullmatch(intent["pre_sign_app_tree_sha256"]) is None
    ):
        raise SigningTransformationError("candidate-freeze intent identity is invalid")
    return frozen, intent


def _manifest_sha256(path: Path, app: Path) -> str:
    raw = _read_regular(path, "pre-sign application manifest", MAX_JSON_BYTES)
    value = _parse_json(raw, "pre-sign application manifest", canonical=False)
    algorithm = value.get("algorithm")
    metadata = value.get("metadata")
    if (
        algorithm != "sha256-tree-v1"
        or type(metadata) is not dict
        or metadata.get("artifactKind") != "pre-sign-application-v1"
        or metadata.get("buildNumber") != ACTIVE_RELEASE_IDENTITY.ga_build
        or metadata.get("version") != ACTIVE_RELEASE_IDENTITY.product_version
        or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in metadata.items()
        )
    ):
        raise SigningTransformationError("pre-sign application manifest identity is invalid")
    try:
        observed = build_manifest(app, metadata=dict(metadata), algorithm=algorithm)
    except (OSError, ValueError) as error:
        raise SigningTransformationError(
            "pre-sign application cannot be reopened through its manifest"
        ) from error
    if observed != value:
        raise SigningTransformationError(
            "pre-sign application differs from its frozen manifest"
        )
    return hashlib.sha256(raw).hexdigest()


def _tree_manifest(app: Path, label: str) -> dict[str, Any]:
    try:
        value = build_manifest(app, algorithm="sha256-tree-v2")
    except (OSError, ValueError) as error:
        raise SigningTransformationError(f"cannot capture {label} tree-v2 manifest") from error
    digest = value.get("sha256")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise SigningTransformationError(f"{label} tree-v2 digest is malformed")
    return value


def _copy_exact(source: Path, destination: Path, label: str) -> dict[str, Any]:
    before = _tree_manifest(source, label)
    try:
        shutil.copytree(
            source,
            destination,
            symlinks=True,
            copy_function=shutil.copy2,
        )
    except (OSError, shutil.Error) as error:
        raise SigningTransformationError(f"cannot copy {label} into isolation") from error
    copied = _tree_manifest(destination, f"isolated {label}")
    after = _tree_manifest(source, label)
    if copied != before or after != before:
        raise SigningTransformationError(f"{label} changed while it was isolated")
    return before


def _profile_inventory(app: Path) -> tuple[str, ...]:
    discovered: list[str] = []
    try:
        for current, directories, files in os.walk(app, topdown=True, followlinks=False):
            directories.sort()
            files.sort()
            for name in (*directories, *files):
                if name == "embedded.provisionprofile":
                    discovered.append((Path(current) / name).relative_to(app).as_posix())
    except OSError as error:
        raise SigningTransformationError("cannot enumerate embedded profiles") from error
    return tuple(sorted(discovered))


def _profile_digests(root: Path, signed_app: Path) -> dict[str, str]:
    if _profile_inventory(root / PRE_SIGN_APP_RELATIVE):
        raise SigningTransformationError(
            "frozen pre-sign application unexpectedly contains an embedded profile"
        )
    observed = _profile_inventory(signed_app)
    if observed != tuple(sorted(EMBEDDED_PROFILE_PATHS)):
        raise SigningTransformationError(
            "signed application must contain exactly the three fixed embedded profiles"
        )
    digests: dict[str, str] = {}
    for role, (source_relative, embedded_relative) in PROFILE_BINDINGS.items():
        source = root / source_relative
        embedded = signed_app.joinpath(*Path(embedded_relative).parts)
        source_data = _read_regular(source, f"{role} frozen profile", MAX_PROFILE_BYTES)
        embedded_data = _read_regular(
            embedded,
            f"{role} signed embedded profile",
            MAX_PROFILE_BYTES,
        )
        if embedded_data != source_data:
            raise SigningTransformationError(
                f"{role} embedded profile differs from the frozen signing profile"
            )
        digests[role] = hashlib.sha256(source_data).hexdigest()
    return digests


def _require_code_objects(app: Path) -> None:
    for relative in CODE_OBJECTS:
        path = app if relative == "." else app.joinpath(*Path(relative).parts)
        try:
            metadata = path.lstat()
        except OSError as error:
            raise SigningTransformationError(
                f"fixed signing code object is unavailable: {relative}"
            ) from error
        if path.is_symlink() or metadata.st_uid != os.geteuid():
            raise SigningTransformationError(
                f"fixed signing code object is unsafe: {relative}"
            )
        if relative in DIRECTORY_CODE_OBJECTS:
            valid = stat.S_ISDIR(metadata.st_mode)
        else:
            valid = stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        if not valid:
            raise SigningTransformationError(
                f"fixed signing code object has the wrong type: {relative}"
            )


def _signature_directory_inventory(app: Path) -> tuple[str, ...]:
    discovered: list[str] = []
    try:
        for current, directories, files in os.walk(app, topdown=True, followlinks=False):
            directories.sort()
            files.sort()
            if "_CodeSignature" in files:
                raise SigningTransformationError(
                    "a code-signature container has the wrong file type"
                )
            if "_CodeSignature" not in directories:
                continue
            path = Path(current) / "_CodeSignature"
            metadata = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise SigningTransformationError(
                    "a code-signature container is unsafe"
                )
            discovered.append(path.relative_to(app).as_posix())
            directories.remove("_CodeSignature")
    except OSError as error:
        raise SigningTransformationError(
            "cannot enumerate fixed code-signature containers"
        ) from error
    return tuple(sorted(discovered))


def _remove_signature_directories(
    app: Path, original: tuple[str, ...]
) -> None:
    remaining = _signature_directory_inventory(app)
    if not set(remaining).issubset(original):
        raise SigningTransformationError(
            "codesign created an unexpected signature container during normalization"
        )
    for relative in remaining:
        path = app.joinpath(*Path(relative).parts)
        try:
            shutil.rmtree(path)
        except OSError as error:
            raise SigningTransformationError(
                "cannot remove one fixed signature container from the private copy"
            ) from error
    if _signature_directory_inventory(app):
        raise SigningTransformationError(
            "a fixed signature container remained after normalization"
        )


def production_codesign_runner(command: tuple[str, ...], repository: Path) -> None:
    if (
        command[:2] != ("/usr/bin/codesign", "--remove-signature")
        or len(command) != 3
        or sys.platform != "darwin"
    ):
        raise SigningTransformationError("codesign normalization command is not fixed")
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    try:
        completed = run_bounded_process(
            command,
            cwd=repository,
            environment=environment,
            timeout=120,
            output_limit=MAX_CODESIGN_OUTPUT,
        )
    except (OSError, BoundedProcessError) as error:
        raise SigningTransformationError(
            "codesign signature removal did not complete in its closed boundary"
        ) from error
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise SigningTransformationError(
            "codesign could not silently normalize one fixed signing code object"
        )


def _normalize_copy(app: Path, repository: Path, runner: CodeSignRunner) -> None:
    _require_code_objects(app)
    signature_directories = _signature_directory_inventory(app)
    if signature_directories not in (
        (),
        tuple(sorted(SIGNATURE_DIRECTORIES)),
    ):
        raise SigningTransformationError(
            "application code-signature container inventory is invalid"
        )
    for spec in CODE_OBJECT_SPECS:
        relative = spec.code_object
        executable_relative = spec.executable
        code_object = app if relative == "." else app.joinpath(*Path(relative).parts)
        executable = app.joinpath(*Path(executable_relative).parts)
        label = f"fixed Mach-O code object {executable_relative}"
        signed_layout = _inspect_signed_macho(executable, label)
        runner(("/usr/bin/codesign", "--remove-signature", str(code_object)), repository)
        _normalize_removed_signature_macho(executable, label, signed_layout)
    _remove_signature_directories(app, signature_directories)
    _require_code_objects(app)


def _remove_signed_profiles(app: Path) -> None:
    if _profile_inventory(app) != tuple(sorted(EMBEDDED_PROFILE_PATHS)):
        raise SigningTransformationError(
            "isolated signed application profile inventory changed"
        )
    for relative in EMBEDDED_PROFILE_PATHS:
        path = app.joinpath(*Path(relative).parts)
        _read_regular(path, "isolated signed embedded profile", MAX_PROFILE_BYTES)
        try:
            path.unlink()
        except OSError as error:
            raise SigningTransformationError(
                "cannot remove a fixed profile from the isolated signed application"
            ) from error
    if _profile_inventory(app):
        raise SigningTransformationError(
            "an embedded profile remained after fixed normalization"
        )


def _same_freeze(first: FrozenCandidate, second: FrozenCandidate) -> bool:
    return (
        first.root,
        first.intent_path,
        first.intent_sha256,
        first.product_version,
        first.build_number,
    ) == (
        second.root,
        second.intent_path,
        second.intent_sha256,
        second.product_version,
        second.build_number,
    )


def compose_receipt(
    repository: Path,
    *,
    signing_output: Path | None = None,
    codesign_runner: CodeSignRunner = production_codesign_runner,
    freeze_verifier: FreezeVerifier = verify_frozen_candidate,
) -> dict[str, Any]:
    """Reopen and normalize both apps without publishing release state."""

    repository = _canonical_repository(repository)
    frozen, intent = _freeze_inputs(repository, freeze_verifier)
    root = frozen.root
    output = _signing_output_path(repository, signing_output)
    pre_sign_app = root / PRE_SIGN_APP_RELATIVE
    pre_sign_manifest = root / PRE_SIGN_MANIFEST_RELATIVE
    signed_app = output / SIGNED_APP_WITHIN_OUTPUT
    with exclusive_rooted_directory_lock(repository, root):
        pre_sign_manifest_sha256 = _manifest_sha256(pre_sign_manifest, pre_sign_app)
        profiles = _profile_digests(root, signed_app)
        source_profiles = dict(profiles)
        _require_code_objects(pre_sign_app)
        _require_code_objects(signed_app)
        with tempfile.TemporaryDirectory(prefix="cfm-signing-transformation-") as temporary:
            temporary_root = Path(temporary)
            metadata = temporary_root.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise SigningTransformationError(
                    "signing-transformation temporary root is not private"
                )
            pre_copy = temporary_root / "pre-sign/Clash for Mac.app"
            signed_copy = temporary_root / "signed/Clash for Mac.app"
            pre_copy.parent.mkdir(mode=0o700)
            signed_copy.parent.mkdir(mode=0o700)
            pre_source = _copy_exact(pre_sign_app, pre_copy, "pre-sign application")
            signed_source = _copy_exact(signed_app, signed_copy, "signed application")
            _normalize_copy(pre_copy, repository, codesign_runner)
            _normalize_copy(signed_copy, repository, codesign_runner)
            _remove_signed_profiles(signed_copy)
            normalized_pre = _tree_manifest(
                pre_copy, "normalized pre-sign application"
            )
            normalized_signed = _tree_manifest(
                signed_copy, "normalized signed application"
            )
            if normalized_pre != normalized_signed:
                raise SigningTransformationError(
                    "Developer ID signing changed application bytes outside signatures and profiles"
                )
        if _tree_manifest(pre_sign_app, "pre-sign application") != pre_source:
            raise SigningTransformationError("pre-sign application changed during normalization")
        if _tree_manifest(signed_app, "signed application") != signed_source:
            raise SigningTransformationError("signed application changed during normalization")
        if _manifest_sha256(pre_sign_manifest, pre_sign_app) != pre_sign_manifest_sha256:
            raise SigningTransformationError(
                "pre-sign application manifest changed during normalization"
            )
        if _profile_digests(root, signed_app) != source_profiles:
            raise SigningTransformationError("frozen or embedded profiles changed")
        reopened, reopened_intent = _freeze_inputs(repository, freeze_verifier)
        if not _same_freeze(frozen, reopened) or reopened_intent != intent:
            raise SigningTransformationError(
                "candidate freeze changed during signing-transformation verification"
            )
    return {
        "candidate_freeze_intent_sha256": frozen.intent_sha256,
        "code_objects": list(CODE_OBJECTS),
        "document": DOCUMENT,
        "normalized_app_tree_sha256": normalized_pre["sha256"],
        "pre_sign_app_manifest_sha256": pre_sign_manifest_sha256,
        "pre_sign_app_tree_sha256": intent["pre_sign_app_tree_sha256"],
        "product": {
            "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            "version": ACTIVE_RELEASE_IDENTITY.product_version,
        },
        "profiles": profiles,
        "removed_signed_profiles": list(EMBEDDED_PROFILE_PATHS),
        "schema_version": SCHEMA_VERSION,
        "signed_app_tree_sha256": signed_source["sha256"],
    }


def _validate_receipt(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != RECEIPT_FIELDS:
        raise SigningTransformationError(
            "signing-transformation receipt has an unexpected field set"
        )
    product = value["product"]
    profiles = value["profiles"]
    if (
        value["document"] != DOCUMENT
        or type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
        or product
        != {
            "build_number": ACTIVE_RELEASE_IDENTITY.ga_build,
            "version": ACTIVE_RELEASE_IDENTITY.product_version,
        }
        or type(value["code_objects"]) is not list
        or tuple(value["code_objects"]) != CODE_OBJECTS
        or type(value["removed_signed_profiles"]) is not list
        or tuple(value["removed_signed_profiles"]) != EMBEDDED_PROFILE_PATHS
        or type(profiles) is not dict
        or set(profiles) != set(PROFILE_BINDINGS)
    ):
        raise SigningTransformationError(
            "signing-transformation receipt identity is invalid"
        )
    for field in (
        "candidate_freeze_intent_sha256",
        "normalized_app_tree_sha256",
        "pre_sign_app_manifest_sha256",
        "pre_sign_app_tree_sha256",
        "signed_app_tree_sha256",
    ):
        if not isinstance(value[field], str) or SHA256_RE.fullmatch(value[field]) is None:
            raise SigningTransformationError(
                f"signing-transformation receipt {field} is malformed"
            )
    for role, digest in profiles.items():
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise SigningTransformationError(
                f"signing-transformation receipt profile {role} is malformed"
            )
    return value


def _entry_exists(descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise SigningTransformationError(
            "cannot inspect the signing-transformation receipt"
        ) from error
    return True


def _read_receipt(
    repository: Path,
    signing_output: Path | None = None,
) -> tuple[dict[str, Any], bytes]:
    output = _signing_output_path(repository, signing_output)
    receipt = output / RECEIPT_NAME
    try:
        with exclusive_rooted_directory_lock(
            repository,
            output,
            require_private=True,
        ) as descriptor:
            raw = read_private_pending_locked(
                descriptor,
                output,
                receipt.name,
                MAX_JSON_BYTES,
            )
    except (OSError, PublicationError, RootedDirectoryChanged) as error:
        raise SigningTransformationError(
            "cannot durably reopen the signing-transformation receipt"
        ) from error
    return _validate_receipt(
        _parse_json(raw, "signing-transformation receipt", canonical=True)
    ), raw


def _write_receipt(repository: Path, signing_output: Path, data: bytes) -> None:
    output = _signing_output_path(repository, signing_output)
    receipt = output / RECEIPT_NAME
    try:
        with exclusive_rooted_directory_lock(
            repository,
            output,
            require_private=True,
        ) as descriptor:
            if _entry_exists(descriptor, receipt.name):
                raise SigningTransformationError(
                    "signing-transformation receipt already exists and cannot be replaced"
                )
            try:
                write_private_pending_locked(
                    descriptor,
                    output,
                    receipt.name,
                    data,
                )
            except PublicationError as error:
                if _entry_exists(descriptor, receipt.name):
                    raise SigningTransformationOutcomeUnknown(
                        "signing-transformation receipt write outcome is unknown; "
                        "verify it explicitly"
                    ) from error
                raise SigningTransformationError(
                    "cannot durably write the signing-transformation receipt"
                ) from error
    except SigningTransformationError:
        raise
    except (OSError, PublicationError, RootedDirectoryChanged) as error:
        if os.path.lexists(receipt):
            raise SigningTransformationOutcomeUnknown(
                "signing-transformation receipt publication outcome is unknown"
            ) from error
        raise SigningTransformationError(
            "cannot publish the signing-transformation receipt"
        ) from error


def create_attempt_receipt(
    repository: Path,
    signing_output: Path,
    *,
    codesign_runner: CodeSignRunner = production_codesign_runner,
    freeze_verifier: FreezeVerifier = verify_frozen_candidate,
) -> dict[str, Any]:
    """Prove one private attempt before its whole output is atomically published."""

    repository = _canonical_repository(repository)
    output = _signing_output_path(repository, signing_output)
    if output == ga_root(repository) / SIGNING_OUTPUT_RELATIVE:
        raise SigningTransformationError(
            "canonical signing-output must be published with its receipt atomically"
        )
    value = _validate_receipt(
        compose_receipt(
            repository,
            signing_output=output,
            codesign_runner=codesign_runner,
            freeze_verifier=freeze_verifier,
        )
    )
    encoded = canonical_json(value)
    _write_receipt(repository, output, encoded)
    # Recompute every source binding after durable publication.  Merely reopening
    # the just-written bytes would allow an input change in the compose/publish
    # window to leave an immutable but stale receipt while reporting success.
    return verify_attempt_receipt(
        repository,
        output,
        codesign_runner=codesign_runner,
        freeze_verifier=freeze_verifier,
    )


def _verify_receipt_at(
    repository: Path,
    signing_output: Path | None,
    *,
    codesign_runner: CodeSignRunner = production_codesign_runner,
    freeze_verifier: FreezeVerifier = verify_frozen_candidate,
) -> dict[str, Any]:
    """Reopen the receipt and independently recompute every transformation binding."""

    repository = _canonical_repository(repository)
    output = _signing_output_path(repository, signing_output)
    observed, raw_before = _read_receipt(repository, output)
    expected = _validate_receipt(
        compose_receipt(
            repository,
            signing_output=output,
            codesign_runner=codesign_runner,
            freeze_verifier=freeze_verifier,
        )
    )
    reopened, raw_after = _read_receipt(repository, output)
    if raw_before != raw_after or observed != reopened:
        raise SigningTransformationError(
            "signing-transformation receipt changed while it was reopened"
        )
    if observed != expected or raw_before != canonical_json(expected):
        raise SigningTransformationError(
            "signing-transformation receipt differs from the current exact GA apps"
        )
    return observed


def verify_attempt_receipt(
    repository: Path,
    signing_output: Path,
    *,
    codesign_runner: CodeSignRunner = production_codesign_runner,
    freeze_verifier: FreezeVerifier = verify_frozen_candidate,
) -> dict[str, Any]:
    """Recompute the receipt for one fixed private attempt workspace."""

    repository = _canonical_repository(repository)
    output = _signing_output_path(repository, signing_output)
    if output == ga_root(repository) / SIGNING_OUTPUT_RELATIVE:
        raise SigningTransformationError(
            "attempt verification requires a fixed private attempt workspace"
        )
    return _verify_receipt_at(
        repository,
        output,
        codesign_runner=codesign_runner,
        freeze_verifier=freeze_verifier,
    )


def verify_receipt(
    repository: Path,
    *,
    codesign_runner: CodeSignRunner = production_codesign_runner,
    freeze_verifier: FreezeVerifier = verify_frozen_candidate,
) -> dict[str, Any]:
    """Recompute the receipt in the atomically published signing-output."""

    return _verify_receipt_at(
        repository,
        None,
        codesign_runner=codesign_runner,
        freeze_verifier=freeze_verifier,
    )


def load_receipt(repository: Path) -> dict[str, Any]:
    """Reopen and validate the immutable receipt without requiring source apps.

    Fresh consumers must call :func:`verify_receipt`.  This narrower operation
    exists for notarization recovery after the signed input has already moved
    into the non-replaceable attempt.
    """

    repository = _canonical_repository(repository)
    observed, _raw = _read_receipt(repository, None)
    return observed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify",))
    arguments = parser.parse_args(argv)
    try:
        require_closed_release_runtime()
        repository = Path(__file__).resolve().parent.parent
        value = verify_receipt(repository)
    except (
        OSError,
        PublicationError,
        ReleasePythonRuntimeError,
        SigningTransformationError,
        ValueError,
    ) as error:
        raise SystemExit(f"error: GA signing transformation: {error}") from error
    receipt_sha256 = hashlib.sha256(canonical_json(value)).hexdigest()
    print(f"GA signing transformation verified: receipt_sha256={receipt_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
