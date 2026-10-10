"""Fail-closed verifier for the design-pinned libbox and toolchain inputs.

:func:`verify_source_contract` binds the pinned-input manifest
(``scripts/pinned_build_inputs.json``) to the tracked release configuration
without invoking any toolchain or the network:

* every pinned tool version and the sing-box/gomobile upstream commits in
  scripts/dependency_pins.env match the manifest exactly;
* cargo-audit and cargo-deny's CI installs consume their release pins with
  ``--locked`` and the release gate checks the exact Apple Silicon target graph;
* the XcodeGen installed-resource patch and patched source digest are bound to
    the isolated bootstrap and its installed-resource probe;
* the official Tauri CLI crate, its unchanged published lock, and the exact Cargo
  cache-normalization contract are checksum-bound to one installer entrypoint;
* the six design-pinned patch files exist as regular files and their computed
  SHA-256 digests match both the manifest and dependency_pins.env;
* the combined diff SHA-256 is pinned and is distinct from any single patch digest;
* known legacy/partial patch digests are rejected;
* the verified Go module inputs (module sums and go.mod/go.sum digests) are present
  and well formed;
* the pinned libbox Go build tag list is exactly the pinned value, is well formed,
  and contains every tag the engine start path requires — including the tags whose
  omission would make ``box.New`` fail on every start;
* the native dependency lock agrees with the pins (source-tree binding);
* the offline libbox build script references the pins with no floating versions and
  no network or recursive build actions;
* every CI job that enters the closed release gate uses exactly the pinned
  unsigned-validation Python.

Source files are not re-attested here: the exact Git commit bound by the hosted
CI receipt and the candidate freeze's release-source identity remain the
trust root for every tracked release script.

Any unavailable, missing, malformed, wrong, or partial input fails closed.
"""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path, PurePosixPath

MANIFEST_RELATIVE_PATH = "scripts/pinned_build_inputs.json"
DEPENDENCY_PINS_RELATIVE_PATH = "scripts/dependency_pins.env"
NATIVE_LOCK_RELATIVE_PATH = "native/macos/Dependencies.lock.json"
TAURI_CLI_INSTALLER_RELATIVE_PATH = "scripts/install_pinned_tauri_cli.sh"
MAX_CONTROL_FILE_BYTES = 4 * 1024 * 1024
MAX_PINNED_MANIFEST_BYTES = 512 * 1024
MAX_NATIVE_LOCK_BYTES = 256 * 1024
PINNED_MANIFEST_FIELDS = frozenset(
    {
        "buildScripts",
        "cargoDeny",
        "combinedDiffSha256",
        "combinedDiffSha256Key",
        "dependencyPinsPath",
        "description",
        "gomobileCommit",
        "gomobileCommitKey",
        "libboxBuildTags",
        "libboxModuleCacheContract",
        "nativeLockPath",
        "packetEvidenceEndpoint",
        "patches",
        "physicalCollectorModule",
        "rejectedPatchDigests",
        "schema",
        "singBoxCommit",
        "singBoxCommitKey",
        "sourceContract",
        "tauriCli",
        "tools",
        "verifiedGoModuleInputKeys",
        "xcodegen",
    }
)
NATIVE_LOCK_FIELDS = frozenset(
    {"go", "gomobile", "singBox", "singBoxForAppleReference"}
)
NATIVE_LOCK_SING_BOX_FIELDS = frozenset(
    {
        "androidReferenceCommit",
        "combinedDiffSha256",
        "commit",
        "dnsFailoverPatch",
        "endpointConflictPatch",
        "profileProbePatch",
        "socksLifecyclePatch",
        "rawPacketPatch",
        "securityPatch",
        "tag",
    }
)
NATIVE_LOCK_SECURITY_PATCH_FIELDS = frozenset(
    {"patchedDiffSha256", "patchedGoModSha256", "patchedGoSumSha256", "path", "sha256"}
)
NATIVE_LOCK_PATCH_FIELDS = frozenset({"path", "sha256"})
NATIVE_LOCK_APPLE_REFERENCE_FIELDS = frozenset({"commit"})
PATCH_ENTRY_FIELDS = frozenset({"name", "pathKey", "sha256Key", "sha256"})
LIBBOX_BUILD_TAG_FIELDS = frozenset(
    {"pinKey", "value", "required", "engineStartPathBindings"}
)
LIBBOX_REQUIRED_TAG_FIELDS = frozenset({"tag", "reason"})
LIBBOX_ENGINE_START_BINDING_FIELDS = frozenset(
    {"tag", "path", "requiredWhenContains", "triggerRequired", "reason"}
)
BUILD_SCRIPT_RULE_FIELDS = frozenset(
    {"requirePinReferences", "forbidNetworkRecursion"}
)
REQUIRED_TOOL_PIN_KEYS = frozenset(
    {
        "XCODE_BUILD_VERSION",
        "XCODE_VERSION",
        "GO_RELEASE_TOOLS_GO_SUM_SHA256",
        "GO_RELEASE_TOOLS_GO_MOD_SHA256",
        "NPM_ARCHIVE_SHA256",
        "NPM_VERSION",
        "PYTHON_VERSION",
        "RUST_VERSION",
        "RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256",
        "CARGO_AUDIT_VERSION",
        "CARGO_DENY_VERSION",
        "XCODEGEN_VERSION",
        "XCODEGEN_COMMIT",
        "XCODEGEN_SOURCE_SHA256",
        "XCODEGEN_PACKAGE_RESOLVED_SHA256",
        "XCODEGEN_UPSTREAM_PACKAGE_RESOLVED_SHA256",
        "XCODEGEN_DEPENDENCY_PATCH_PATH",
        "XCODEGEN_DEPENDENCY_PATCH_SHA256",
        "XCODEGEN_AEXML_COMMIT",
        "XCODEGEN_AEXML_UPSTREAM_MANIFEST_SHA256",
        "XCODEGEN_AEXML_PATCH_PATH",
        "XCODEGEN_AEXML_PATCH_SHA256",
        "XCODEGEN_AEXML_PATCHED_MANIFEST_SHA256",
        "NODE_VERSION",
        "GO_VERSION",
        "GOMOBILE_VERSION",
        "GOVULNCHECK_VERSION",
        "TAURI_CLI_VERSION",
        "SING_BOX_VERSION",
    }
)
REQUIRED_VERIFIED_GO_MODULE_INPUT_KEYS = frozenset(
    {
        "GOMOBILE_MODULE_SUM",
        "GOVULNCHECK_MODULE_SUM",
        "LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
        "SING_BOX_UPSTREAM_GO_MOD_SHA256",
        "SING_BOX_UPSTREAM_GO_SUM_SHA256",
        "SING_BOX_PATCHED_GO_MOD_SHA256",
        "SING_BOX_PATCHED_GO_SUM_SHA256",
    }
)
REQUIRED_PATCH_POLICIES = {
    "socksLifecyclePatch": (
        "sing-box SOCKS lifecycle patch",
        "SING_BOX_SOCKS_LIFECYCLE_PATCH_PATH",
        "SING_BOX_SOCKS_LIFECYCLE_PATCH_SHA256",
    ),
    "securityPatch": (
        "sing-box security dependencies patch",
        "SING_BOX_SECURITY_PATCH_PATH",
        "SING_BOX_SECURITY_PATCH_SHA256",
    ),
    "rawPacketPatch": (
        "sing-box raw packet tun patch",
        "SING_BOX_RAW_PACKET_PATCH_PATH",
        "SING_BOX_RAW_PACKET_PATCH_SHA256",
    ),
    "dnsFailoverPatch": (
        "sing-box DNS failover patch",
        "SING_BOX_DNS_FAILOVER_PATCH_PATH",
        "SING_BOX_DNS_FAILOVER_PATCH_SHA256",
    ),
    "profileProbePatch": (
        "sing-box profile probe patch",
        "SING_BOX_PROFILE_PROBE_PATCH_PATH",
        "SING_BOX_PROFILE_PROBE_PATCH_SHA256",
    ),
    "endpointConflictPatch": (
        "sing-box endpoint conflict patch",
        "SING_BOX_ENDPOINT_CONFLICT_PATCH_PATH",
        "SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
    ),
}
REQUIRED_REJECTED_PATCH_DIGESTS = frozenset(
    {
        "3367a387fe58b9bb374bb08a7fae9ad2fd46d609e8e9aea49a92a14ec9de4cac",
        "66128ca96ff613b0803cc92b3269b4e7822cd2532c43597e9e283acc6d9f4dde",
        "ca751c4ec4b82a60d4dd8716627dc2665b154901a988603108bb5e4e718cf439",
        "c618b69baa770e0afc3239f78acfeaaf354e3dc8105e2e61b149d4ede00a93b7",
    }
)
REQUIRED_ENGINE_START_PATH_BINDINGS = frozenset(
    {
        (
            "with_clash_api",
            "crates/cfw-singbox-config/src/controller.rs",
            '"clash_api": {',
        ),
        (
            "with_clash_api",
            "crates/cfw-singbox-config/src/projection.rs",
            'root.insert("experimental".into(), clash_api.experimental_value());',
        ),
    }
)
REQUIRED_LIBBOX_BUILD_TAGS = frozenset(
    {
        "with_wireguard",
        "with_gvisor",
        "with_quic",
        "with_utls",
        "with_clash_api",
        "badlinkname",
        "tfogo_checklinkname0",
        "grpcnotrace",
    }
)
REQUIRED_BUILD_SCRIPT_POLICIES = {
    "scripts/build_libbox.sh": frozenset(
        {
            "$GO_VERSION",
            "$GOMOBILE_VERSION",
            "$GOMOBILE_COMMIT",
            "$GOMOBILE_MODULE_SUM",
            "$SING_BOX_VERSION",
            "$SING_BOX_COMMIT",
            "$LIBBOX_BUILD_TAGS",
            "$SING_BOX_COMBINED_DIFF_SHA256",
            "$SING_BOX_SECURITY_PATCH_SHA256",
            "$SING_BOX_RAW_PACKET_PATCH_SHA256",
            "$SING_BOX_DNS_FAILOVER_PATCH_SHA256",
            "$SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
            "$SING_BOX_PROFILE_PROBE_PATCH_SHA256",
            "$SING_BOX_SOCKS_LIFECYCLE_PATCH_SHA256",
        }
    )
}
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_ENV_LINE_RE = re.compile(r"\A([A-Za-z_][A-Za-z0-9_]*)=(.*)\Z")
_NETWORK_RECURSION_RE = re.compile(
    r"git\s+clone|https?://|(?<![A-Za-z])curl(?![A-Za-z])|"
    r"(?<![A-Za-z])wget(?![A-Za-z])|go\s+get|go\s+install|GOPROXY\s*=\s*https?",
    re.IGNORECASE,
)
_PACKET_ENDPOINT_BINARY_SHA256 = (
    "f1589e0594a40df34b5062f07b6c30e6306b5753b01781f39c483fa9af7e78eb"
)
_PACKET_ENDPOINT_SYSTEMD_UNIT_SHA256 = (
    "7d485a9fe9081ebf019fcc8abc1d596358a64326e2490749d9903197262e3996"
)
_PACKET_ENDPOINT_INSTALL_SCRIPT_SHA256 = (
    "331d82561cf88af651bf9bc854946b443655d5a2e6fa498f8f2925bcc767575a"
)
_PACKET_ENDPOINT_RESOLVER_CONFIG_SHA256 = (
    "b290cc794e7f0faac9ebbd63f83aad67d23086b48206295d5d6a2767721c1e62"
)
_PACKET_ENDPOINT_SUDOERS_SHA256 = (
    "a91c2bc91a294622d44f14e2cad653b9703fcf70afa42bf91e0248ef240c3411"
)
_PACKET_ENDPOINT_KNOWN_HOSTS_SHA256 = (
    "3741384531dbd24c65a2225386beae492bf92c61fdf2d5b90b57051d57be36ba"
)
_PACKET_ENDPOINT_POLICY_SHA256 = (
    "9b7e1e8d892bc87568bbd122e502e4c0f74a2d9579e398d9d2563372772be19a"
)
_PACKET_ENDPOINT_SOURCE_PATHS = frozenset(
    {
        "tools/packet-evidence-endpoint/go.mod",
        "tools/packet-evidence-endpoint/install-endpoint.sh",
        "tools/packet-evidence-endpoint/main.go",
        "tools/packet-evidence-endpoint/main_test.go",
        "tools/packet-evidence-endpoint/packet-evidence-capture.sudoers",
        "tools/packet-evidence-endpoint/packet-evidence-endpoint.service",
        "tools/packet-evidence-endpoint/packet-evidence-resolv.conf",
        "tools/packet-evidence-endpoint/README.md",
        "scripts/physical_capture/packet_endpoints.json",
        "scripts/physical_capture/packet_known_hosts",
    }
)
_PACKET_ENDPOINT_BUILD_FRAGMENTS = (
    "GOTOOLCHAIN=local",
    "CGO_ENABLED=0",
    "GOOS=linux",
    "GOARCH=amd64",
    "target/toolchains/go-1.27.2/bin/go",
    "-C tools/packet-evidence-endpoint",
    "-buildvcs=false",
    "-trimpath",
    "-ldflags='-s -w -buildid='",
    "-o ../../target/packet-evidence-endpoint-linux-amd64",
    _PACKET_ENDPOINT_BINARY_SHA256,
)
_PHYSICAL_COLLECTOR_GO_MOD_SHA256 = (
    "15a4a62864a708fe87dc6e4624036603ad27ca82a1bcdc3b5f06d678fdde24be"
)
_PHYSICAL_COLLECTOR_GO_SUM_SHA256 = (
    "ca8994a475ecb2b18b3debe1eb422925f3f3fcdd4366b7b1aa9f5ded14cd4e9a"
)
_PHYSICAL_COLLECTOR_MODULE_FRAGMENTS = (
    "google.golang.org/grpc v1.83.2",
    "golang.org/x/text v0.42.0",
)


class PinnedInputError(RuntimeError):
    """Raised when any pinned build input cannot be proven correct."""


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _close_descriptors(
    descriptors: tuple[int, ...],
    description: str,
) -> None:
    """Close every owned descriptor and report the first cleanup failure."""

    first_error: OSError | None = None
    for descriptor in descriptors:
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None:
        raise PinnedInputError(
            f"{description} descriptor cleanup failed"
        ) from first_error


def _open_directory_beneath(
    root_descriptor: int,
    components: tuple[str, ...],
    directory_flags: int,
    description: str,
) -> tuple[int, os.stat_result]:
    """Open one repository-relative directory chain without following links."""
    try:
        descriptor = os.dup(root_descriptor)
    except OSError as error:
        raise PinnedInputError(
            f"{description} parent descriptor cannot be duplicated"
        ) from error
    try:
        try:
            opened = os.fstat(descriptor)
        except OSError as error:
            raise PinnedInputError(
                f"{description} parent descriptor cannot be inspected"
            ) from error
        for component in components:
            next_descriptor = -1
            try:
                before = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                next_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=descriptor,
                )
                next_opened = os.fstat(next_descriptor)
            except OSError as error:
                if next_descriptor >= 0:
                    _close_descriptors((next_descriptor,), description)
                if error.errno in (errno.ELOOP, errno.ENOENT, errno.ENOTDIR):
                    raise PinnedInputError(
                        f"{description} parent is missing, a symlink, or not a directory"
                    ) from error
                raise PinnedInputError(
                    f"{description} parent cannot be opened securely: {error}"
                ) from error
            try:
                if (
                    not stat.S_ISDIR(before.st_mode)
                    or not stat.S_ISDIR(next_opened.st_mode)
                    or _file_identity(before) != _file_identity(next_opened)
                ):
                    raise PinnedInputError(
                        f"{description} parent changed while it was opened"
                    )
            except BaseException:
                _close_descriptors((next_descriptor,), description)
                raise
            previous_descriptor = descriptor
            descriptor = next_descriptor
            _close_descriptors((previous_descriptor,), description)
            opened = next_opened
        if not stat.S_ISDIR(opened.st_mode):
            raise PinnedInputError(f"{description} parent is not a directory")
        return descriptor, opened
    except BaseException:
        _close_descriptors((descriptor,), description)
        raise


def read_repository_regular_file(
    repository: Path,
    relative: str,
    description: str,
    *,
    maximum_size: int,
) -> bytes:
    """Read one repository file through a root-anchored held descriptor chain."""
    if type(maximum_size) is not int or maximum_size < 1:
        raise PinnedInputError(f"{description} has no positive byte bound")
    if not repository.is_absolute():
        raise PinnedInputError(f"{description} repository root must be absolute")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise PinnedInputError(f"{description} requires O_NOFOLLOW and O_DIRECTORY")
    candidate = Path(relative)
    _safe_repository_path(repository, relative, description)
    parent_components = tuple(candidate.parts[:-1])
    filename = candidate.parts[-1]
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    directory_flags = os.O_RDONLY | nofollow | directory
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    root_descriptor = -1
    parent_descriptor = -1
    descriptor = -1
    fresh_parent_descriptor = -1
    current_descriptor = -1
    try:
        try:
            repository_before = os.stat(repository, follow_symlinks=False)
            root_descriptor = os.open(repository, directory_flags)
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOENT, errno.ENOTDIR):
                raise PinnedInputError(
                    f"{description} repository root is missing, a symlink, or not a directory"
                ) from error
            raise PinnedInputError(
                f"{description} repository root cannot be opened securely: {error}"
            ) from error
        try:
            repository_opened = os.fstat(root_descriptor)
        except OSError as error:
            raise PinnedInputError(
                f"{description} repository root cannot be inspected securely"
            ) from error
        if (
            not stat.S_ISDIR(repository_before.st_mode)
            or not stat.S_ISDIR(repository_opened.st_mode)
            or _file_identity(repository_before) != _file_identity(repository_opened)
        ):
            raise PinnedInputError(
                f"{description} repository root changed while it was opened"
            )
        parent_descriptor, parent_opened = _open_directory_beneath(
            root_descriptor,
            parent_components,
            directory_flags,
            description,
        )
        try:
            path_before = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
            descriptor = os.open(filename, flags, dir_fd=parent_descriptor)
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOENT, errno.ENOTDIR):
                raise PinnedInputError(
                    f"{description} is missing, a symlink, or has an unsafe path"
                ) from error
            raise PinnedInputError(
                f"{description} cannot be opened securely: {error}"
            ) from error
        try:
            opened = os.fstat(descriptor)
            if _file_identity(path_before) != _file_identity(opened):
                raise PinnedInputError(f"{description} changed while it was opened")
            if not stat.S_ISREG(opened.st_mode):
                raise PinnedInputError(f"{description} is not a regular file")
            if opened.st_nlink != 1:
                raise PinnedInputError(f"{description} must have exactly one hard link")
            if opened.st_uid != os.geteuid():
                raise PinnedInputError(
                    f"{description} is not owned by the effective user"
                )
            if opened.st_mode & 0o022:
                raise PinnedInputError(
                    f"{description} is writable by group or other users"
                )
            if opened.st_size > maximum_size:
                raise PinnedInputError(
                    f"{description} exceeds its {maximum_size}-byte bound"
                )

            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                try:
                    chunk = os.read(descriptor, min(1024 * 1024, remaining))
                except BlockingIOError as error:
                    raise PinnedInputError(
                        f"{description} could not be read as a regular file"
                    ) from error
                if not chunk:
                    raise PinnedInputError(
                        f"{description} ended before its observed size"
                    )
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise PinnedInputError(f"{description} exceeds its observed size")
            after = os.fstat(descriptor)
        except OSError as error:
            raise PinnedInputError(
                f"{description} cannot be read securely: {error}"
            ) from error

        try:
            path_after = os.stat(
                filename,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            parent_after = os.fstat(parent_descriptor)
        except OSError as error:
            raise PinnedInputError(
                f"{description} path changed after it was read: {error}"
            ) from error

        fresh_parent_descriptor, fresh_parent = _open_directory_beneath(
            root_descriptor,
            parent_components,
            directory_flags,
            description,
        )
        try:
            current_path_before = os.stat(
                filename,
                dir_fd=fresh_parent_descriptor,
                follow_symlinks=False,
            )
            current_descriptor = os.open(
                filename,
                flags,
                dir_fd=fresh_parent_descriptor,
            )
            current_opened = os.fstat(current_descriptor)
            current_path_after = os.stat(
                filename,
                dir_fd=fresh_parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise PinnedInputError(
                f"{description} current path cannot be rebound securely: {error}"
            ) from error

        try:
            repository_after = os.fstat(root_descriptor)
            repository_rebound = os.stat(repository, follow_symlinks=False)
        except OSError as error:
            raise PinnedInputError(
                f"{description} repository root changed after it was read: {error}"
            ) from error
        if (
            _file_identity(repository_before) != _file_identity(repository_opened)
            or _file_identity(repository_opened) != _file_identity(repository_after)
            or _file_identity(repository_after) != _file_identity(repository_rebound)
            or _file_identity(parent_opened) != _file_identity(parent_after)
            or _file_identity(parent_after) != _file_identity(fresh_parent)
            or _file_identity(opened) != _file_identity(after)
            or _file_identity(after) != _file_identity(path_after)
            or _file_identity(path_after) != _file_identity(current_path_before)
            or _file_identity(current_path_before) != _file_identity(current_opened)
            or _file_identity(current_opened) != _file_identity(current_path_after)
        ):
            raise PinnedInputError(
                f"{description} repository, parent, path, or metadata changed while it was read"
            )
        return b"".join(chunks)
    finally:
        _close_descriptors(
            (
                current_descriptor,
                fresh_parent_descriptor,
                descriptor,
                parent_descriptor,
                root_descriptor,
            ),
            description,
        )


def _read_bytes(
    repository: Path,
    relative: str,
    description: str,
    *,
    maximum_size: int = MAX_CONTROL_FILE_BYTES,
) -> bytes:
    return read_repository_regular_file(
        repository,
        relative,
        description,
        maximum_size=maximum_size,
    )


def _read_text(
    repository: Path,
    relative: str,
    description: str,
    *,
    maximum_size: int = MAX_CONTROL_FILE_BYTES,
) -> str:
    body = _read_bytes(
        repository,
        relative,
        description,
        maximum_size=maximum_size,
    )
    try:
        return body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PinnedInputError(f"{description} is not strict UTF-8") from error


def _load_strict_json(
    text: str,
    description: str,
    *,
    expected_fields: frozenset[str],
) -> dict:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise PinnedInputError(
                    f"{description} contains duplicate JSON field {key!r}"
                )
            value[key] = item
        return value

    def reject_nonfinite(value: str) -> None:
        raise PinnedInputError(
            f"{description} contains non-finite JSON number {value!r}"
        )

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            reject_nonfinite(value)
        raise PinnedInputError(
            f"{description} contains unsupported floating-point JSON number {value!r}"
        )

    def parse_bounded_int(value: str) -> int:
        digits = value.removeprefix("-")
        if len(digits) > 19:
            raise PinnedInputError(
                f"{description} contains an out-of-range JSON integer"
            )
        parsed = int(value, 10)
        if not -(2**63) <= parsed <= 2**63 - 1:
            raise PinnedInputError(
                f"{description} contains an out-of-range JSON integer"
            )
        return parsed

    try:
        document = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
            parse_float=parse_finite_float,
            parse_int=parse_bounded_int,
        )
    except PinnedInputError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        raise PinnedInputError(f"{description} is malformed: {error}") from error
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise PinnedInputError(f"{description} does not have its exact top-level shape")
    return document


def _load_manifest(repository: Path) -> dict:
    text = _read_text(
        repository,
        MANIFEST_RELATIVE_PATH,
        "pinned-input manifest",
        maximum_size=MAX_PINNED_MANIFEST_BYTES,
    )
    manifest = _load_strict_json(
        text,
        "pinned-input manifest",
        expected_fields=PINNED_MANIFEST_FIELDS,
    )
    if manifest.get("schema") != "cfw-pinned-build-inputs-v1":
        raise PinnedInputError("pinned-input manifest has an unsupported schema")
    if not isinstance(manifest.get("description"), str) or not manifest["description"]:
        raise PinnedInputError("pinned-input manifest description is empty or malformed")
    return manifest


def _parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE_RE.match(line)
        if not match:
            raise PinnedInputError(f"dependency_pins.env line {number} is malformed: {raw!r}")
        key, value = match.group(1), match.group(2)
        if key in values:
            raise PinnedInputError(f"dependency_pins.env defines {key} more than once")
        values[key] = value
    return values


def _require_env(env: dict[str, str], key: str) -> str:
    if key not in env:
        raise PinnedInputError(f"dependency_pins.env is missing required pin {key}")
    value = env[key]
    if value == "":
        raise PinnedInputError(f"dependency_pins.env pin {key} is empty")
    return value


def _require_sha256(value: str, description: str) -> str:
    if not _SHA256_RE.match(value):
        raise PinnedInputError(f"{description} is not a lowercase 64-hex SHA-256: {value!r}")
    return value


def _safe_repository_path(repository: Path, relative: str, description: str) -> Path:
    if (
        type(relative) is not str
        or not relative
        or "\0" in relative
        or "\\" in relative
    ):
        raise PinnedInputError(f"{description} path is not canonical: {relative!r}")
    candidate = PurePosixPath(relative)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or candidate.as_posix() != relative
    ):
        raise PinnedInputError(f"{description} path is not repository-relative: {relative!r}")
    if any(part in ("", ".", "..") for part in candidate.parts):
        raise PinnedInputError(f"{description} path has an unsafe component: {relative!r}")
    return repository.joinpath(*candidate.parts)


def _verify_tools(manifest: dict, env: dict[str, str]) -> None:
    tools = manifest.get("tools")
    if not isinstance(tools, dict) or set(tools) != REQUIRED_TOOL_PIN_KEYS:
        raise PinnedInputError(
            "pinned-input manifest differs from the fixed tool pin set"
        )
    for key, expected in tools.items():
        actual = _require_env(env, key)
        if actual != expected:
            raise PinnedInputError(
                f"pinned tool {key} must be {expected!r} but dependency_pins.env has {actual!r}"
            )


def _verify_packet_evidence_endpoint(
    manifest: dict, env: dict[str, str], repository: Path
) -> None:
    spec = manifest.get("packetEvidenceEndpoint")
    expected_fields = {
        "goVersionKey",
        "goVersion",
        "goos",
        "goarch",
        "cgoEnabled",
        "binarySha256",
        "transportPort",
        "dnsPort",
        "readmePath",
        "requiredBuildFragments",
        "sourceFiles",
    }
    if not isinstance(spec, dict) or set(spec) != expected_fields:
        raise PinnedInputError(
            "packet evidence endpoint pinned-input contract is missing or has unknown fields"
        )
    if (
        spec["goVersionKey"] != "GO_VERSION"
        or spec["goVersion"] != _require_env(env, "GO_VERSION")
        or spec["goos"] != "linux"
        or spec["goarch"] != "amd64"
        or spec["cgoEnabled"] != "0"
        or spec["transportPort"] != 44333
        or spec["dnsPort"] != 53
        or spec["binarySha256"] != _PACKET_ENDPOINT_BINARY_SHA256
        or spec["readmePath"] != "tools/packet-evidence-endpoint/README.md"
        or spec["requiredBuildFragments"]
        != list(_PACKET_ENDPOINT_BUILD_FRAGMENTS)
    ):
        raise PinnedInputError(
            "packet evidence endpoint build target, ports, or binary digest drifted"
        )

    source_files = spec["sourceFiles"]
    if not isinstance(source_files, list) or len(source_files) != len(
        _PACKET_ENDPOINT_SOURCE_PATHS
    ):
        raise PinnedInputError(
            "packet evidence endpoint must bind the exact source, test, service, policy, host-key, and README set"
        )
    observed: dict[str, str] = {}
    for index, entry in enumerate(source_files):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise PinnedInputError(
                f"packet evidence endpoint sourceFiles[{index}] is malformed"
            )
        relative = entry["path"]
        digest = entry["sha256"]
        if not isinstance(relative, str) or relative in observed:
            raise PinnedInputError(
                "packet evidence endpoint source paths are invalid or duplicated"
            )
        if not isinstance(digest, str):
            raise PinnedInputError(
                f"packet evidence endpoint source digest is malformed for {relative!r}"
            )
        _require_sha256(digest, f"packet evidence endpoint source digest for {relative}")
        actual = hashlib.sha256(
            _read_bytes(
                repository,
                relative,
                f"packet evidence endpoint source {relative}",
            )
        ).hexdigest()
        if actual != digest:
            raise PinnedInputError(
                f"packet evidence endpoint source digest drifted for {relative!r}"
            )
        observed[relative] = digest
    if set(observed) != _PACKET_ENDPOINT_SOURCE_PATHS:
        raise PinnedInputError(
            "packet evidence endpoint must bind the exact source, test, unit, and README set"
        )
    if (
        observed["tools/packet-evidence-endpoint/packet-evidence-endpoint.service"]
        != _PACKET_ENDPOINT_SYSTEMD_UNIT_SHA256
    ):
        raise PinnedInputError(
            "packet evidence endpoint systemd unit differs from the packet policy"
        )
    if (
        observed["tools/packet-evidence-endpoint/install-endpoint.sh"]
        != _PACKET_ENDPOINT_INSTALL_SCRIPT_SHA256
    ):
        raise PinnedInputError(
            "packet evidence endpoint installer differs from the packet policy"
        )
    if (
        observed["tools/packet-evidence-endpoint/packet-evidence-resolv.conf"]
        != _PACKET_ENDPOINT_RESOLVER_CONFIG_SHA256
    ):
        raise PinnedInputError(
            "packet evidence endpoint resolver config differs from the packet policy"
        )
    if (
        observed["tools/packet-evidence-endpoint/packet-evidence-capture.sudoers"]
        != _PACKET_ENDPOINT_SUDOERS_SHA256
    ):
        raise PinnedInputError(
            "packet evidence endpoint sudoers policy differs from the packet policy"
        )
    if (
        observed["scripts/physical_capture/packet_known_hosts"]
        != _PACKET_ENDPOINT_KNOWN_HOSTS_SHA256
    ):
        raise PinnedInputError(
            "packet evidence endpoint known-hosts bytes differ from the packet policy"
        )
    if (
        observed["scripts/physical_capture/packet_endpoints.json"]
        != _PACKET_ENDPOINT_POLICY_SHA256
    ):
        raise PinnedInputError(
            "packet evidence endpoint instance policy differs from its whole-file pin"
        )
    readme = _read_text(
        repository,
        spec["readmePath"],
        "packet evidence endpoint README",
    )
    for fragment in _PACKET_ENDPOINT_BUILD_FRAGMENTS:
        if fragment not in readme:
            raise PinnedInputError(
                f"packet evidence endpoint README lacks build binding {fragment!r}"
            )


def _verify_physical_collector_module(
    manifest: dict, env: dict[str, str], repository: Path
) -> None:
    spec = manifest.get("physicalCollectorModule")
    expected_fields = {
        "goVersionKey",
        "goVersion",
        "goModPath",
        "goModSha256",
        "goSumPath",
        "goSumSha256",
        "requiredModuleFragments",
    }
    if not isinstance(spec, dict) or set(spec) != expected_fields:
        raise PinnedInputError(
            "pinned-input manifest has no exact physical-collector module binding"
        )
    if (
        spec["goVersionKey"] != "GO_VERSION"
        or spec["goVersion"] != env.get("GO_VERSION")
        or spec["goModPath"] != "tools/physical-collector/go.mod"
        or spec["goSumPath"] != "tools/physical-collector/go.sum"
        or spec["goModSha256"] != _PHYSICAL_COLLECTOR_GO_MOD_SHA256
        or spec["goSumSha256"] != _PHYSICAL_COLLECTOR_GO_SUM_SHA256
        or spec["requiredModuleFragments"]
        != list(_PHYSICAL_COLLECTOR_MODULE_FRAGMENTS)
    ):
        raise PinnedInputError("physical-collector module pins differ from policy")
    go_mod = _read_bytes(
        repository, spec["goModPath"], "physical-collector go.mod"
    )
    go_sum = _read_bytes(
        repository, spec["goSumPath"], "physical-collector go.sum"
    )
    if hashlib.sha256(go_mod).hexdigest() != spec["goModSha256"]:
        raise PinnedInputError("physical-collector go.mod digest drifted")
    if hashlib.sha256(go_sum).hexdigest() != spec["goSumSha256"]:
        raise PinnedInputError("physical-collector go.sum digest drifted")
    try:
        go_mod_text = go_mod.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PinnedInputError("physical-collector go.mod is not UTF-8") from error
    for fragment in _PHYSICAL_COLLECTOR_MODULE_FRAGMENTS:
        if fragment not in go_mod_text:
            raise PinnedInputError(
                f"physical-collector go.mod lacks required module {fragment!r}"
            )


def _verify_cargo_deny(manifest: dict, repository: Path) -> None:
    spec = manifest.get("cargoDeny")
    if not isinstance(spec, dict):
        raise PinnedInputError("pinned-input manifest has no cargo-deny CI binding")
    workflow_relative = spec.get("ciWorkflowPath")
    fragments = spec.get("requiredCiFragments")
    if (
        not isinstance(workflow_relative, str)
        or not isinstance(fragments, list)
        or not fragments
    ):
        raise PinnedInputError("cargo-deny CI binding is incomplete")
    workflow = _read_text(
        repository,
        workflow_relative,
        "cargo-deny CI workflow",
    )
    for fragment in fragments:
        if not isinstance(fragment, str) or not fragment or fragment not in workflow:
            raise PinnedInputError(
                f"cargo-deny CI workflow lacks required pinned fragment {fragment!r}"
            )
    if re.search(
        r"cargo\s+install\s+cargo-deny\s+--version\s+['\"]?[0-9]", workflow
    ):
        raise PinnedInputError(
            "cargo-deny CI install hard-codes a version outside release pins"
        )


def _verify_xcodegen(manifest: dict, env: dict[str, str], repository: Path) -> None:
    spec = manifest.get("xcodegen")
    if not isinstance(spec, dict):
        raise PinnedInputError("pinned-input manifest has no XcodeGen patch binding")

    patch_path_key = spec.get("patchPathKey")
    patch_sha_key = spec.get("patchSha256Key")
    patched_source_sha_key = spec.get("patchedSettingsBuilderSha256Key")
    if not all(
        isinstance(value, str)
        for value in (patch_path_key, patch_sha_key, patched_source_sha_key)
    ):
        raise PinnedInputError("XcodeGen patch binding has incomplete pin keys")
    expected_patch_sha = spec.get("patchSha256")
    expected_patched_source_sha = spec.get("patchedSettingsBuilderSha256")
    if not isinstance(expected_patch_sha, str) or not isinstance(
        expected_patched_source_sha, str
    ):
        raise PinnedInputError("XcodeGen patch binding has incomplete digests")
    _require_sha256(expected_patch_sha, "manifest XcodeGen patch digest")
    _require_sha256(
        expected_patched_source_sha, "manifest patched SettingsBuilder digest"
    )
    if _require_env(env, patch_sha_key) != expected_patch_sha:
        raise PinnedInputError("XcodeGen patch digest differs from the manifest")
    if _require_env(env, patched_source_sha_key) != expected_patched_source_sha:
        raise PinnedInputError(
            "XcodeGen patched SettingsBuilder digest differs from the manifest"
        )

    patch_relative = _require_env(env, patch_path_key)
    actual_patch_sha = hashlib.sha256(
        _read_bytes(repository, patch_relative, "XcodeGen patch")
    ).hexdigest()
    if actual_patch_sha != expected_patch_sha:
        raise PinnedInputError(
            f"XcodeGen patch file digest {actual_patch_sha} differs from the pinned "
            f"{expected_patch_sha}"
        )

    bootstrap_relative = spec.get("bootstrapPath")
    fragments = spec.get("requiredBootstrapFragments")
    if (
        not isinstance(bootstrap_relative, str)
        or not isinstance(fragments, list)
        or not fragments
    ):
        raise PinnedInputError("XcodeGen bootstrap binding is incomplete")
    bootstrap = _read_text(
        repository,
        bootstrap_relative,
        "XcodeGen bootstrap",
    )
    for fragment in fragments:
        if not isinstance(fragment, str) or not fragment or fragment not in bootstrap:
            raise PinnedInputError(
                f"XcodeGen bootstrap lacks required pinned fragment {fragment!r}"
            )


def _verify_tauri_cli(manifest: dict, env: dict[str, str], repository: Path) -> None:
    spec = manifest.get("tauriCli")
    if not isinstance(spec, dict):
        raise PinnedInputError("pinned-input manifest has no Tauri CLI source binding")

    digest_pairs = (
        ("crateSha256Key", "crateSha256", "Tauri CLI crate"),
        (
            "upstreamCargoLockSha256Key",
            "upstreamCargoLockSha256",
            "Tauri CLI upstream Cargo.lock",
        ),
        ("spinCrateSha256Key", "spinCrateSha256", "Tauri CLI spin crate"),
    )
    for key_field, value_field, description in digest_pairs:
        key = spec.get(key_field)
        expected = spec.get(value_field)
        if not isinstance(key, str) or not isinstance(expected, str):
            raise PinnedInputError(f"{description} has no complete digest binding")
        _require_sha256(expected, f"manifest digest for {description}")
        actual = _require_env(env, key)
        _require_sha256(actual, f"dependency_pins.env value {key}")
        if actual != expected:
            raise PinnedInputError(
                f"{description} digest {key} is {actual} but must be {expected}"
            )

    cache_contract_relative = spec.get("cacheContractPath")
    cache_contract_key = spec.get("cacheContractSha256Key")
    cache_contract_expected = spec.get("cacheContractSha256")
    if (
        not isinstance(cache_contract_relative, str)
        or not isinstance(cache_contract_key, str)
        or not isinstance(cache_contract_expected, str)
    ):
        raise PinnedInputError("Tauri Cargo cache contract has no complete digest binding")
    _require_sha256(
        cache_contract_expected,
        "manifest digest for Tauri Cargo cache contract",
    )
    cache_contract_env = _require_env(env, cache_contract_key)
    _require_sha256(
        cache_contract_env,
        f"dependency_pins.env value {cache_contract_key}",
    )
    if cache_contract_env != cache_contract_expected:
        raise PinnedInputError(
            f"Tauri Cargo cache contract digest {cache_contract_key} is "
            f"{cache_contract_env} but must be {cache_contract_expected}"
        )
    computed_cache_contract_sha = hashlib.sha256(
        _read_bytes(
            repository,
            cache_contract_relative,
            "Tauri Cargo cache contract",
        )
    ).hexdigest()
    if computed_cache_contract_sha != cache_contract_expected:
        raise PinnedInputError(
            "Tauri Cargo cache contract file digest "
            f"{computed_cache_contract_sha} differs from the pinned "
            f"{cache_contract_expected}"
        )

    spin_version_key = spec.get("spinVersionKey")
    spin_version = spec.get("spinVersion")
    if not isinstance(spin_version_key, str) or not isinstance(spin_version, str):
        raise PinnedInputError("Tauri CLI spin input has no version binding")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", spin_version):
        raise PinnedInputError("Tauri CLI spin input version is malformed")
    if _require_env(env, spin_version_key) != spin_version:
        raise PinnedInputError("Tauri CLI spin input version differs from the manifest")

    installer_relative = spec.get("installerPath")
    fragments = spec.get("requiredInstallerFragments")
    if (
        installer_relative != TAURI_CLI_INSTALLER_RELATIVE_PATH
        or not isinstance(fragments, list)
        or not fragments
    ):
        raise PinnedInputError("Tauri CLI installer binding is incomplete")
    installer_body = _read_bytes(
        repository,
        installer_relative,
        "Tauri CLI installer",
    )
    try:
        installer = installer_body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PinnedInputError("Tauri CLI installer is not strict UTF-8") from error
    colon_path_rejection_command = '[[ "$temporary_parent" != *:* ]]'
    staging_creation_command = (
        'staging="$(/usr/bin/mktemp -d '
        '"$temporary_parent/cfw-tauri-cli.XXXXXX")"'
    )
    workspace_manifest_renderer = (
        "render_tauri_workspace_manifest() {\n"
        "  printf '[workspace]\\nmembers = [\"tauri-cli-%s\"]\\n"
        "resolver = \"2\"\\n' \\\n"
        '    "$TAURI_CLI_VERSION"\n'
        "}"
    )
    workspace_manifest_creation_command = (
        'render_tauri_workspace_manifest >"$staging_workspace_manifest"'
    )
    workspace_manifest_mode_command = (
        '/bin/chmod 0600 "$staging_workspace_manifest"'
    )
    workspace_lock_creation_command = (
        '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"'
    )
    workspace_boundary_call = "\nverify_tauri_workspace_boundary\n"
    cargo_configuration_call = "\nreject_tauri_cargo_configuration\n"
    for fragment in fragments:
        if not isinstance(fragment, str) or not fragment or fragment not in installer:
            raise PinnedInputError(
                f"Tauri CLI installer does not contain required pinned fragment {fragment!r}"
            )
    exact_counts = {
        'printf \'%s  %s\\n\' "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$source/Cargo.lock" |\n'
        '    shasum -a 256 --check >/dev/null': 1,
        'readonly cargo_cache_contract="$repo_root/scripts/tauri_cargo_cache_contract.py"': 1,
        '"$repo_root" "$cargo_cache_contract"': 2,
        'validate-preparation "$root"': 1,
        'normalize-offline "$root"': 1,
        'verify_cargo_preparation_cache "$prepared_cargo_home"': 2,
        'normalize_cargo_offline_cache "$offline_cargo_home"': 2,
        'reject_cargo_warnings "$fetch_log" "Tauri CLI dependency preparation"': 1,
        'reject_cargo_warnings "$install_log" "tauri-cli installation"': 1,
        'offline_cache_sha256_before="$(cfw_verify_release_toolchain_manifest': 1,
        'offline_cache_sha256_after="$(cfw_verify_release_toolchain_manifest': 1,
        '[[ "$offline_cache_sha256_after" == "$offline_cache_sha256_before" ]]': 1,
        colon_path_rejection_command: 1,
        staging_creation_command: 1,
        workspace_manifest_renderer: 1,
        'members = ["tauri-cli-%s"]': 1,
        'resolver = "2"': 1,
        'reject_tauri_cargo_configuration() {': 1,
        'verify_tauri_workspace_boundary() {': 1,
        '[[ -f "$boundary_file" && ! -L "$boundary_file" ]] ||': 1,
        '[[ "$(stat -f \'%l\' "$boundary_file")" == "1" ]] ||': 1,
        '[[ "$(stat -f \'%u\' "$boundary_file")" == '
        '"$(/usr/bin/id -u)" ]] ||': 1,
        'die "Tauri workspace input must be a regular file: $boundary_file"': 1,
        'die "Tauri workspace input must not have hard links: $boundary_file"': 1,
        'die "Tauri workspace input must belong to the release account: '
        '$boundary_file"': 1,
        'die "temporary Tauri workspace inputs must use mode 0600"': 1,
        '--additional-working-directory "$source_root"': 1,
        'readonly staging_workspace_manifest="$staging/Cargo.toml"': 1,
        'readonly staging_workspace_lock="$staging/Cargo.lock"': 1,
        workspace_manifest_creation_command: 1,
        workspace_manifest_mode_command: 1,
        workspace_lock_creation_command: 1,
        workspace_boundary_call: 4,
        cargo_configuration_call: 4,
        '/usr/bin/cmp -s "$cargo_lock" "$staging_workspace_lock"': 1,
    }
    for fragment, expected_count in exact_counts.items():
        actual_count = installer.count(fragment)
        if actual_count != expected_count:
            raise PinnedInputError(
                f"Tauri CLI installer requires {expected_count} exact occurrences of "
                f"{fragment!r}, found {actual_count}"
            )

    def require_exact_block(
        start_marker: str,
        end_marker: str,
        expected_sha256: str,
        description: str,
    ) -> None:
        if installer.count(start_marker) != 1:
            raise PinnedInputError(
                f"Tauri CLI installer {description} boundary is ambiguous"
            )
        start = installer.index(start_marker)
        try:
            end = installer.index(end_marker, start) + len(end_marker)
        except ValueError as error:
            raise PinnedInputError(
                f"Tauri CLI installer {description} boundary is incomplete"
            ) from error
        actual_sha256 = hashlib.sha256(
            installer[start:end].encode("utf-8")
        ).hexdigest()
        if actual_sha256 != expected_sha256:
            raise PinnedInputError(
                f"Tauri CLI installer {description} differs from release policy"
            )

    require_exact_block(
        "reject_tauri_cargo_configuration() {",
        "\n}",
        "a131e2c379b0d05f5ba5b1676ab80aefad156feb6f3fe628eea858ece4132eb1",
        "ambient Cargo configuration verifier",
    )
    require_exact_block(
        "verify_tauri_workspace_boundary() {",
        "\n}",
        "468af618535337139cfcbaf00616f00ad13eb4017d546d68d7f105c9009d6a75",
        "workspace boundary verifier",
    )
    require_exact_block(
        'staging_workspace_manifest_sha256="$(',
        "\nreadonly staging_workspace_manifest_sha256",
        "e696a052345c9b83bd83c6a2c85a536c81171448b96f824c8cc61453be3d79a9",
        "workspace manifest digest producer",
    )

    def normalized_shell_operation(operation: str) -> str:
        return " ".join(operation.replace("\\\n", " ").split())

    # Official-source mode admits no patch application. Each source/workspace
    # lock remains independently bound to the exact upstream archive bytes.
    if any(
        not line.lstrip().startswith("#") and re.search(r"\bapply\b", line)
        for line in installer.replace("\\\n", " ").splitlines()
    ):
        raise PinnedInputError("Tauri CLI official source contains a patch apply operation")

    expected_workspace_references = {
        normalized_shell_operation(value)
        for value in (
            'for boundary_file in "$cargo_manifest" "$cargo_lock" '
            '"$staging_workspace_manifest" "$staging_workspace_lock"; do',
            '[[ "$(stat -f \'%Lp\' "$staging_workspace_manifest")" == "600" && '
            '"$(stat -f \'%Lp\' "$staging_workspace_lock")" == "600" ]] ||',
            'printf \'%s  %s\\n\' "$staging_workspace_manifest_sha256" '
            '"$staging_workspace_manifest" |',
            'printf \'%s  %s\\n\' "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" '
            '"$staging_workspace_lock" |',
            '/usr/bin/cmp -s "$cargo_lock" "$staging_workspace_lock" ||',
            'readonly staging_workspace_manifest="$staging/Cargo.toml"',
            'readonly staging_workspace_lock="$staging/Cargo.lock"',
            'staging_workspace_manifest_sha256="$(',
            "readonly staging_workspace_manifest_sha256",
            '[[ ! -e "$staging_workspace_manifest" && '
            '! -L "$staging_workspace_manifest" && '
            '! -e "$staging_workspace_lock" && '
            '! -L "$staging_workspace_lock" ]] ||',
            workspace_manifest_creation_command,
            workspace_manifest_mode_command,
            workspace_lock_creation_command,
        )
    }
    workspace_reference_markers = (
        "staging_workspace_",
        '"$staging/Cargo.toml"',
        '"$staging/Cargo.lock"',
        '"${staging}/Cargo.toml"',
        '"${staging}/Cargo.lock"',
    )
    observed_workspace_references = [
        normalized_shell_operation(line)
        for line in installer.replace("\\\n", " ").splitlines()
        if any(marker in line for marker in workspace_reference_markers)
    ]
    if (
        len(observed_workspace_references) != len(expected_workspace_references)
        or set(observed_workspace_references) != expected_workspace_references
    ):
        raise PinnedInputError(
            "Tauri CLI installer contains an unexpected workspace input mutation"
        )

    # Bind the ordered, exact logical-line surface for both literal Cargo
    # control-file paths and every ordinary direct/braced reference to the two
    # source variables.  Removing line continuations mirrors shell parsing but
    # deliberately preserves all other bytes, so equal-count substitutions,
    # parameter-expansion variants, and quoted whitespace drift fail closed.
    cargo_control_file_reference_pattern = re.compile(
        r"Cargo[.](?:toml|lock)"
        r"|[$]cargo_(?:manifest|lock)(?![A-Za-z0-9_])"
        r"|[$][{]cargo_(?:manifest|lock)(?:[^}]*)[}]"
    )
    cargo_control_file_references = [
        line
        for line in installer.replace("\\\n", "").splitlines()
        if not line.lstrip().startswith("#")
        and cargo_control_file_reference_pattern.search(line)
    ]
    cargo_control_file_reference_identity = hashlib.sha256(
        json.dumps(
            cargo_control_file_references,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if cargo_control_file_reference_identity != (
        "42fab0b199f7b0bda2599a314edc45745e629207748b78d2b43972f084f79640"
    ):
        raise PinnedInputError(
            "Tauri CLI installer contains an unexpected Cargo control-file reference"
        )

    def locate(fragment: str, after: int = 0) -> int:
        try:
            return installer.index(fragment, after)
        except ValueError as error:
            raise PinnedInputError(
                f"Tauri CLI installer lacks ordered operation {fragment!r}"
            ) from error

    colon_path_rejection = locate(colon_path_rejection_command)
    staging_creation = locate(staging_creation_command, colon_path_rejection)
    preparation_before = locate(
        'verify_cargo_preparation_cache "$prepared_cargo_home"',
        staging_creation,
    )
    upstream_lock_digest = locate(
        'printf \'%s  %s\\n\' "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$cargo_lock" |\n'
        '  shasum -a 256 --check\n',
        preparation_before,
    )
    spin_semantic_check = locate(
        "official Tauri CLI lock has unexpected spin records", upstream_lock_digest
    )
    workspace_manifest_creation = locate(
        workspace_manifest_creation_command,
        spin_semantic_check,
    )
    workspace_lock_creation = locate(
        workspace_lock_creation_command,
        workspace_manifest_creation,
    )
    workspace_boundary_before_fetch = locate(
        workspace_boundary_call,
        workspace_lock_creation,
    )
    cargo_configuration_before_fetch = locate(
        cargo_configuration_call,
        workspace_boundary_before_fetch,
    )
    fetch = locate('"$cargo_bin" fetch', cargo_configuration_before_fetch)
    fetch_warning_gate = locate(
        'reject_cargo_warnings "$fetch_log" "Tauri CLI dependency preparation"',
        fetch,
    )
    workspace_boundary_after_fetch = locate(
        workspace_boundary_call,
        fetch_warning_gate,
    )
    cargo_configuration_after_fetch = locate(
        cargo_configuration_call,
        workspace_boundary_after_fetch,
    )
    preparation_after = locate(
        'verify_cargo_preparation_cache "$prepared_cargo_home"',
        cargo_configuration_after_fetch,
    )
    copied = locate(
        '/usr/bin/ditto --noqtn "$prepared_cargo_home" "$offline_cargo_home"',
        preparation_after,
    )
    normalized_before = locate(
        'normalize_cargo_offline_cache "$offline_cargo_home"',
        copied,
    )
    manifest_generation = locate(
        '"$repo_root" "$repo_root/scripts/hash_artifact.py"',
        normalized_before,
    )
    manifest_input = locate('"$offline_cargo_home"', manifest_generation)
    verified_before = locate(
        'offline_cache_sha256_before="$(cfw_verify_release_toolchain_manifest',
        manifest_input,
    )
    workspace_boundary_before_install = locate(
        workspace_boundary_call,
        verified_before,
    )
    cargo_configuration_before_install = locate(
        cargo_configuration_call,
        workspace_boundary_before_install,
    )
    install = locate('"$cargo_bin" install', cargo_configuration_before_install)
    install_warning_gate = locate(
        'reject_cargo_warnings "$install_log" "tauri-cli installation"',
        install,
    )
    workspace_boundary_after_install = locate(
        workspace_boundary_call,
        install_warning_gate,
    )
    cargo_configuration_after_install = locate(
        cargo_configuration_call,
        workspace_boundary_after_install,
    )
    normalized_after = locate(
        'normalize_cargo_offline_cache "$offline_cargo_home"',
        cargo_configuration_after_install,
    )
    verified_after = locate(
        'offline_cache_sha256_after="$(cfw_verify_release_toolchain_manifest',
        normalized_after,
    )
    locate(
        '[[ "$offline_cache_sha256_after" == "$offline_cache_sha256_before" ]]',
        verified_after,
    )
    if re.search(r"cargo\s+install\s+tauri-cli", installer):
        raise PinnedInputError(
            "Tauri CLI installer bypasses the checksum-bound local --path source"
        )

    workflow_relative = spec.get("ciWorkflowPath")
    required_ci_fragment = spec.get("requiredCiFragment")
    if not isinstance(workflow_relative, str) or not isinstance(required_ci_fragment, str):
        raise PinnedInputError("Tauri CLI CI binding is incomplete")
    workflow = _read_text(
        repository,
        workflow_relative,
        "CI workflow",
    )
    if required_ci_fragment not in workflow:
        raise PinnedInputError("CI does not use the checksum-bound Tauri CLI installer")
    if re.search(r"cargo\s+install\s+tauri-cli", workflow):
        raise PinnedInputError("CI still contains a floating direct Tauri CLI installation")


def _verify_commits(manifest: dict, env: dict[str, str]) -> None:
    for prefix, description in (
        ("singBox", "sing-box"),
        ("gomobile", "gomobile"),
    ):
        key = manifest.get(f"{prefix}CommitKey")
        expected = manifest.get(f"{prefix}Commit")
        if not isinstance(key, str) or not isinstance(expected, str):
            raise PinnedInputError(
                f"pinned-input manifest has no {description} commit binding"
            )
        if not re.fullmatch(r"[0-9a-f]{40}", expected):
            raise PinnedInputError(
                f"pinned {description} commit is not a 40-hex commit hash"
            )
        actual = _require_env(env, key)
        if actual != expected:
            raise PinnedInputError(
                f"pinned {description} commit must be {expected} but "
                f"dependency_pins.env has {actual}"
            )


def _verify_patches(manifest: dict, env: dict[str, str], repository: Path) -> list[str]:
    patches = manifest.get("patches")
    if not isinstance(patches, list) or len(patches) != 6:
        raise PinnedInputError("pinned-input manifest must pin exactly six patches")
    rejected_values = manifest.get("rejectedPatchDigests")
    if (
        not isinstance(rejected_values, list)
        or len(rejected_values) != len(REQUIRED_REJECTED_PATCH_DIGESTS)
        or any(not isinstance(digest, str) for digest in rejected_values)
        or len(rejected_values) != len(set(rejected_values))
    ):
        raise PinnedInputError(
            "pinned-input manifest must provide exactly four unique rejected patch digests"
        )
    for digest in rejected_values:
        _require_sha256(digest, "rejected patch digest")
    rejected = set(rejected_values)
    if rejected != REQUIRED_REJECTED_PATCH_DIGESTS:
        raise PinnedInputError(
            "pinned-input manifest rejected patch digests differ from release policy"
        )
    normalized_patches: list[tuple[str, str, str, str]] = []
    policy_identities: set[tuple[str, str, str]] = set()
    for patch in patches:
        if not isinstance(patch, dict) or set(patch) != PATCH_ENTRY_FIELDS:
            raise PinnedInputError("pinned-input manifest has a malformed patch entry")
        name = patch.get("name")
        path_key = patch.get("pathKey")
        sha_key = patch.get("sha256Key")
        expected = patch.get("sha256")
        if not all(
            isinstance(item, str) and item
            for item in (name, path_key, sha_key, expected)
        ):
            raise PinnedInputError(f"patch entry {name} is missing pin keys")
        identity = (name, path_key, sha_key)
        if identity in policy_identities:
            raise PinnedInputError("pinned-input manifest repeats a patch policy identity")
        policy_identities.add(identity)
        normalized_patches.append((name, path_key, sha_key, expected))

    if policy_identities != frozenset(REQUIRED_PATCH_POLICIES.values()):
        raise PinnedInputError(
            "pinned-input manifest patches differ from the fixed patch policy set"
        )

    seen: set[str] = set()
    digests: list[str] = []
    for name, path_key, sha_key, expected in normalized_patches:
        _require_sha256(expected, f"manifest digest for {name}")
        if expected in rejected:
            raise PinnedInputError(f"patch {name} pins a rejected/legacy digest: {expected}")
        if expected in seen:
            raise PinnedInputError(f"patch {name} reuses another patch digest: {expected}")
        seen.add(expected)

        env_sha = _require_env(env, sha_key)
        _require_sha256(env_sha, f"dependency_pins.env value {sha_key}")
        if env_sha != expected:
            raise PinnedInputError(
                f"patch {name} digest {sha_key} is {env_sha} but must be {expected}"
            )
        if env_sha in rejected:
            raise PinnedInputError(f"patch {name} pins a rejected/legacy digest: {env_sha}")

        relative = _require_env(env, path_key)
        computed = hashlib.sha256(
            _read_bytes(repository, relative, f"patch {name} file")
        ).hexdigest()
        if computed != expected:
            raise PinnedInputError(
                f"patch {name} file digest {computed} differs from the pinned {expected}"
            )
        digests.append(expected)
    return digests


def _verify_combined_diff(
    manifest: dict, env: dict[str, str], patch_digests: list[str]
) -> None:
    key = manifest.get("combinedDiffSha256Key")
    expected = manifest.get("combinedDiffSha256")
    if not isinstance(key, str) or not isinstance(expected, str):
        raise PinnedInputError("pinned-input manifest has no combined diff binding")
    _require_sha256(expected, "manifest combined diff digest")
    actual = _require_env(env, key)
    _require_sha256(actual, f"dependency_pins.env value {key}")
    if actual != expected:
        raise PinnedInputError(
            f"combined diff digest must be {expected} but dependency_pins.env has {actual}"
        )
    if actual in patch_digests:
        raise PinnedInputError(
            "combined diff digest equals a single patch digest; partial digest rejected"
        )
    partial = env.get("SING_BOX_PATCHED_DIFF_SHA256")
    if partial is not None and actual == partial:
        raise PinnedInputError(
            "combined diff digest equals the partial go.mod/go.sum diff digest"
        )


def _verify_source_contract(manifest: dict, env: dict[str, str]) -> None:
    contract = manifest.get("sourceContract")
    if not isinstance(contract, dict):
        raise PinnedInputError("pinned-input manifest has no source contract binding")
    for name in ("patchedDiffSha256", "patchedGoModSha256", "patchedGoSumSha256"):
        key = contract.get(f"{name}Key")
        expected = contract.get(name)
        if not isinstance(key, str) or not isinstance(expected, str):
            raise PinnedInputError(f"source contract is missing {name} binding")
        _require_sha256(expected, f"manifest source contract {name}")
        actual = _require_env(env, key)
        _require_sha256(actual, f"dependency_pins.env value {key}")
        if actual != expected:
            raise PinnedInputError(
                f"source contract {name} must be {expected} but dependency_pins.env has {actual}"
            )


def _verify_go_module_inputs(manifest: dict, env: dict[str, str]) -> None:
    keys = manifest.get("verifiedGoModuleInputKeys")
    if (
        not isinstance(keys, list)
        or len(keys) != len(REQUIRED_VERIFIED_GO_MODULE_INPUT_KEYS)
        or any(not isinstance(key, str) for key in keys)
        or len(keys) != len(set(keys))
        or set(keys) != REQUIRED_VERIFIED_GO_MODULE_INPUT_KEYS
    ):
        raise PinnedInputError(
            "pinned-input manifest differs from the fixed verified Go module input set"
        )
    for key in keys:
        value = _require_env(env, key)
        if key.endswith("_SHA256"):
            _require_sha256(value, f"dependency_pins.env value {key}")
        elif not value.startswith("h1:"):
            raise PinnedInputError(f"Go module sum {key} is not an h1: checksum: {value!r}")


def _verify_libbox_module_cache_contract(
    manifest: dict, env: dict[str, str], repository: Path
) -> None:
    spec = manifest.get("libboxModuleCacheContract")
    expected_fields = {"pathKey", "path", "sha256Key", "sha256"}
    if not isinstance(spec, dict) or set(spec) != expected_fields:
        raise PinnedInputError(
            "pinned-input manifest has no exact libbox module cache contract binding"
        )

    path_key = spec["pathKey"]
    relative = spec["path"]
    sha256_key = spec["sha256Key"]
    expected_sha256 = spec["sha256"]
    if not all(
        isinstance(value, str)
        for value in (path_key, relative, sha256_key, expected_sha256)
    ):
        raise PinnedInputError("libbox module cache contract binding is malformed")
    _require_sha256(expected_sha256, "manifest libbox module cache contract digest")

    env_relative = _require_env(env, path_key)
    if env_relative != relative:
        raise PinnedInputError(
            f"libbox module cache contract path {path_key} is {env_relative!r} "
            f"but must be {relative!r}"
        )
    env_sha256 = _require_env(env, sha256_key)
    _require_sha256(env_sha256, f"dependency_pins.env value {sha256_key}")
    if env_sha256 != expected_sha256:
        raise PinnedInputError(
            f"libbox module cache contract digest {sha256_key} is {env_sha256} "
            f"but must be {expected_sha256}"
        )

    actual_sha256 = hashlib.sha256(
        _read_bytes(repository, relative, "libbox module cache contract")
    ).hexdigest()
    if actual_sha256 != expected_sha256:
        raise PinnedInputError(
            f"libbox module cache contract file digest {actual_sha256} differs "
            f"from the pinned {expected_sha256}"
        )


def _verify_libbox_build_tags(manifest: dict, env: dict[str, str], repository: Path) -> None:
    """Bind the pinned libbox Go build tag list to the tags the engine requires.

    The tag list is a build input exactly like a version or a digest: omitting a
    tag silently removes compiled-in behaviour the runtime depends on. The
    ``with_clash_api`` omission made ``box.New`` fail on every engine start
    because the patched tree enables the clash API whenever a platform log writer
    is installed and the daemon always installs one, so the stub constructor
    returned an error instead of a server. This check therefore pins the exact
    tag list, requires each tag the start path needs, and additionally binds
    tracked source triggers (such as the application-owned
    ``experimental.clash_api`` projection block) to the tag that makes them
    reachable, so the same class of defect fails closed statically.
    """
    spec = manifest.get("libboxBuildTags")
    if not isinstance(spec, dict) or set(spec) != LIBBOX_BUILD_TAG_FIELDS:
        raise PinnedInputError("pinned-input manifest has no libbox build tag binding")
    pin_key = spec.get("pinKey")
    expected_value = spec.get("value")
    if not isinstance(pin_key, str) or not isinstance(expected_value, str):
        raise PinnedInputError("libbox build tag binding has no pin key or pinned value")
    actual_value = _require_env(env, pin_key)
    if actual_value != expected_value:
        raise PinnedInputError(
            f"pinned libbox build tags {pin_key} must be {expected_value!r} but "
            f"dependency_pins.env has {actual_value!r}"
        )

    tags: list[str] = actual_value.split(",")
    seen: set[str] = set()
    for tag in tags:
        if not re.fullmatch(r"[a-z0-9_]+", tag):
            raise PinnedInputError(f"pinned libbox build tag is malformed: {tag!r}")
        if tag in seen:
            raise PinnedInputError(f"pinned libbox build tags repeat {tag!r}")
        seen.add(tag)

    required = spec.get("required")
    if not isinstance(required, list) or not required:
        raise PinnedInputError("libbox build tag binding pins no required tags")
    required_tags: set[str] = set()
    for entry in required:
        if not isinstance(entry, dict) or set(entry) != LIBBOX_REQUIRED_TAG_FIELDS:
            raise PinnedInputError("libbox required-tag entry is malformed")
        tag = entry.get("tag")
        reason = entry.get("reason")
        if not isinstance(tag, str) or not tag:
            raise PinnedInputError("libbox required-tag entry has no tag")
        if not isinstance(reason, str) or not reason:
            raise PinnedInputError(f"libbox required tag {tag} has no recorded reason")
        if tag in required_tags:
            raise PinnedInputError(f"libbox required tags repeat {tag!r}")
        required_tags.add(tag)
        if tag not in seen:
            raise PinnedInputError(
                f"pinned libbox build tags are missing the required tag {tag!r}: {reason}"
            )

    engine_bindings = spec.get("engineStartPathBindings")
    if not isinstance(engine_bindings, list) or not engine_bindings:
        raise PinnedInputError("libbox build tag binding pins no engine-start paths")
    binding_identities: set[tuple[str, str, str]] = set()
    for binding in engine_bindings:
        if (
            not isinstance(binding, dict)
            or set(binding) != LIBBOX_ENGINE_START_BINDING_FIELDS
        ):
            raise PinnedInputError("libbox tag source binding is malformed")
        tag = binding.get("tag")
        relative = binding.get("path")
        trigger = binding.get("requiredWhenContains")
        reason = binding.get("reason")
        if not all(isinstance(item, str) and item for item in (tag, relative, trigger, reason)):
            raise PinnedInputError("libbox tag source binding is incomplete")
        if binding.get("triggerRequired") is not True:
            raise PinnedInputError("libbox tag source binding must require its trigger")
        identity = (tag, relative, trigger)
        if identity in binding_identities:
            raise PinnedInputError("libbox tag source bindings contain a duplicate")
        binding_identities.add(identity)
        text = _read_text(
            repository,
            relative,
            f"libbox tag source binding {relative}",
        )
        present = trigger in text
        if binding.get("triggerRequired") and not present:
            raise PinnedInputError(
                f"{relative} no longer contains the pinned tag trigger {trigger!r}; "
                f"re-pin the libbox build tags deliberately ({reason})"
            )
        if present and tag not in seen:
            raise PinnedInputError(
                f"{relative} requires libbox build tag {tag!r} but the pinned tag list "
                f"omits it: {reason}"
            )
    if binding_identities != REQUIRED_ENGINE_START_PATH_BINDINGS:
        raise PinnedInputError(
            "libbox tag source bindings differ from the fixed engine-start paths"
        )
    if seen != REQUIRED_LIBBOX_BUILD_TAGS:
        raise PinnedInputError("pinned libbox build tags differ from release policy")
    if required_tags != REQUIRED_LIBBOX_BUILD_TAGS:
        raise PinnedInputError("libbox required tags differ from release policy")


def _verify_native_lock(manifest: dict, env: dict[str, str], repository: Path) -> None:
    relative = manifest.get("nativeLockPath")
    if relative != NATIVE_LOCK_RELATIVE_PATH:
        raise PinnedInputError(
            "pinned-input manifest native lock path differs from release policy"
        )
    text = _read_text(
        repository,
        relative,
        "native dependency lock",
        maximum_size=MAX_NATIVE_LOCK_BYTES,
    )
    lock = _load_strict_json(
        text,
        "native dependency lock",
        expected_fields=NATIVE_LOCK_FIELDS,
    )

    def _expect(actual: object, expected: str, label: str) -> None:
        if actual != expected:
            raise PinnedInputError(
                f"native dependency lock {label} is {actual!r} but must be {expected!r}"
            )

    sing_box = lock.get("singBox")
    if not isinstance(sing_box, dict):
        raise PinnedInputError("native dependency lock has no singBox table")
    if set(sing_box) != NATIVE_LOCK_SING_BOX_FIELDS:
        raise PinnedInputError("native dependency lock singBox table has an inexact shape")
    _expect(lock.get("go"), _require_env(env, "GO_VERSION"), "go")
    _expect(lock.get("gomobile"), _require_env(env, "GOMOBILE_VERSION"), "gomobile")
    _expect(sing_box.get("tag"), _require_env(env, "SING_BOX_VERSION"), "singBox.tag")
    _expect(sing_box.get("commit"), _require_env(env, "SING_BOX_COMMIT"), "singBox.commit")
    _expect(
        sing_box.get("androidReferenceCommit"),
        _require_env(env, "SING_BOX_ANDROID_REFERENCE_COMMIT"),
        "singBox.androidReferenceCommit",
    )
    apple_reference = lock.get("singBoxForAppleReference")
    if (
        not isinstance(apple_reference, dict)
        or set(apple_reference) != NATIVE_LOCK_APPLE_REFERENCE_FIELDS
    ):
        raise PinnedInputError(
            "native dependency lock singBoxForAppleReference table has an inexact shape"
        )
    _expect(
        apple_reference.get("commit"),
        _require_env(env, "SING_BOX_APPLE_REFERENCE_COMMIT"),
        "singBoxForAppleReference.commit",
    )
    _expect(
        sing_box.get("combinedDiffSha256"),
        _require_env(env, "SING_BOX_COMBINED_DIFF_SHA256"),
        "singBox.combinedDiffSha256",
    )
    lock_patches = {
        lock_key: (path_key, sha_key)
        for lock_key, (_name, path_key, sha_key) in REQUIRED_PATCH_POLICIES.items()
    }
    for lock_key, (path_key, sha_key) in lock_patches.items():
        entry = sing_box.get(lock_key)
        expected_fields = (
            NATIVE_LOCK_SECURITY_PATCH_FIELDS
            if lock_key == "securityPatch"
            else NATIVE_LOCK_PATCH_FIELDS
        )
        if not isinstance(entry, dict) or set(entry) != expected_fields:
            raise PinnedInputError(f"native dependency lock has no {lock_key} entry")
        _expect(entry.get("path"), _require_env(env, path_key), f"singBox.{lock_key}.path")
        _expect(entry.get("sha256"), _require_env(env, sha_key), f"singBox.{lock_key}.sha256")
    security_patch = sing_box.get("securityPatch")
    assert isinstance(security_patch, dict)
    for lock_key, env_key in (
        ("patchedDiffSha256", "SING_BOX_PATCHED_DIFF_SHA256"),
        ("patchedGoModSha256", "SING_BOX_PATCHED_GO_MOD_SHA256"),
        ("patchedGoSumSha256", "SING_BOX_PATCHED_GO_SUM_SHA256"),
    ):
        _expect(
            security_patch.get(lock_key),
            _require_env(env, env_key),
            f"singBox.securityPatch.{lock_key}",
        )


def _verify_build_scripts(manifest: dict, repository: Path) -> None:
    build_scripts = manifest.get("buildScripts")
    if (
        not isinstance(build_scripts, dict)
        or set(build_scripts) != set(REQUIRED_BUILD_SCRIPT_POLICIES)
    ):
        raise PinnedInputError(
            "pinned-input manifest differs from the fixed build-script policy set"
        )
    for relative, rules in build_scripts.items():
        if (
            not isinstance(relative, str)
            or not relative
            or not isinstance(rules, dict)
            or set(rules) != BUILD_SCRIPT_RULE_FIELDS
        ):
            raise PinnedInputError("pinned-input manifest has malformed build-script policy")
        required_references = rules.get("requirePinReferences")
        if (
            not isinstance(required_references, list)
            or not required_references
            or any(
                not isinstance(reference, str) or not reference
                for reference in required_references
            )
            or len(required_references) != len(set(required_references))
        ):
            raise PinnedInputError(
                f"build script {relative} has malformed required pin references"
            )
        if set(required_references) != REQUIRED_BUILD_SCRIPT_POLICIES[relative]:
            raise PinnedInputError(
                f"build script {relative} differs from its fixed pin-reference policy"
            )
        if rules.get("forbidNetworkRecursion") is not True:
            raise PinnedInputError(
                f"build script {relative} must forbid network and recursive actions"
            )
        text = _read_text(
            repository,
            relative,
            f"build script {relative}",
        )
        for reference in required_references:
            if reference not in text:
                raise PinnedInputError(
                    f"build script {relative} does not reference pin {reference} (floating version risk)"
                )
        match = _NETWORK_RECURSION_RE.search(text)
        if match:
            raise PinnedInputError(
                f"build script {relative} contains a network or recursive action: {match.group(0)!r}"
            )


def _verify_ci_release_python(
    repository: Path, environment_pins: dict[str, str]
) -> None:
    workflow = _read_text(
        repository,
        ".github/workflows/ci.yml",
        "CI workflow",
    )
    expected_python = _require_env(environment_pins, "PYTHON_VERSION")
    lines = workflow.splitlines()
    jobs: dict[str, list[str]] = {}
    current_job: str | None = None
    in_jobs = False
    job_header = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
    for line in lines:
        if not in_jobs:
            in_jobs = line == "jobs:"
            continue
        if line and not line.startswith(" ") and not line.startswith("#"):
            break
        match = job_header.match(line)
        if match:
            current_job = match.group(1)
            jobs[current_job] = []
        elif current_job is not None:
            jobs[current_job].append(line)
    release_jobs = {
        name: "\n".join(body)
        for name, body in jobs.items()
        if "./scripts/run_release_ci_gate.sh" in "\n".join(body)
    }
    if not release_jobs:
        raise PinnedInputError(
            "CI workflow has no job using the closed release gate"
        )
    for name, body in release_jobs.items():
        configured_python_versions = re.findall(
            r'(?m)^\s+python-version:\s*"([0-9]+[.][0-9]+[.][0-9]+)"\s*$',
            body,
        )
        if configured_python_versions != [expected_python]:
            raise PinnedInputError(
                f"CI job {name!r} unsigned-validation Python version does not "
                "exactly match dependency_pins.env"
            )
        required_python_fragments = (
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "id: validation-python",
            "architecture: arm64",
            "update-environment: false",
        )
        for fragment in required_python_fragments:
            if body.count(fragment) != 1:
                raise PinnedInputError(
                    f"CI job {name!r} does not bind exactly one closed "
                    f"unsigned-validation Python through {fragment!r}"
                )
        body_lines = body.splitlines()
        gate_commands: list[str] = []
        index = 0
        while index < len(body_lines):
            line = body_lines[index]
            if "./scripts/run_release_ci_gate.sh" not in line:
                index += 1
                continue
            command = line.strip()
            while command.endswith("\\"):
                index += 1
                if index >= len(body_lines):
                    break
                command = command[:-1].rstrip() + " " + body_lines[index].strip()
            gate_commands.append(command)
            index += 1
        if not gate_commands or any(
            "--validation-python-executable" not in command
            or "steps.validation-python.outputs.python-path" not in command
            for command in gate_commands
        ):
            raise PinnedInputError(
                f"CI job {name!r} has a release gate outside its exact "
                "unsigned-validation Python boundary"
            )


def verify_source_contract(repository: Path) -> None:
    """Verify every static pinned input without invoking a toolchain."""
    manifest = _load_manifest(repository)
    dependency_pins_path = manifest.get("dependencyPinsPath")
    if dependency_pins_path != DEPENDENCY_PINS_RELATIVE_PATH:
        raise PinnedInputError(
            "pinned-input manifest dependency pins path differs from release policy"
        )
    env = _parse_env(
        _read_text(
            repository,
            dependency_pins_path,
            "dependency_pins.env",
        )
    )
    _verify_tools(manifest, env)
    _verify_packet_evidence_endpoint(manifest, env, repository)
    _verify_physical_collector_module(manifest, env, repository)
    _verify_cargo_deny(manifest, repository)
    _verify_xcodegen(manifest, env, repository)
    _verify_tauri_cli(manifest, env, repository)
    _verify_commits(manifest, env)
    patch_digests = _verify_patches(manifest, env, repository)
    _verify_combined_diff(manifest, env, patch_digests)
    _verify_source_contract(manifest, env)
    _verify_libbox_module_cache_contract(manifest, env, repository)
    _verify_go_module_inputs(manifest, env)
    _verify_libbox_build_tags(manifest, env, repository)
    _verify_native_lock(manifest, env, repository)
    _verify_build_scripts(manifest, repository)
    _verify_ci_release_python(repository, env)
