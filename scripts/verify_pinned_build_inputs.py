"""Fail-closed verifier for the pinned libbox and toolchain build inputs.

``scripts/dependency_pins.env`` is the only store of pinned values.
:func:`verify_source_contract` checks those values against the release policy in
``scripts/pinned_build_inputs.json`` without invoking any toolchain or the
network:

* the pin file defines exactly the fixed release pin keys, the policy declares a
  format for each, and every value has its declared format (SHA-256, commit,
  version, module sum, repository path, build-tag list);
* cargo-audit and cargo-deny's CI installs consume their release pins with
  ``--locked`` and the release gate checks the exact Apple Silicon target graph;
* the XcodeGen installed-resource patch hashes to its pin and the isolated
  bootstrap keeps its pinned patch, probe and metadata operations;
* the exact Cargo cache-normalization contract hashes to its pin and the
  official Tauri CLI installer keeps every checksum-bound operation;
* the six sing-box patch files exist as regular files whose computed SHA-256
  digests match their pins, are distinct, and are not known legacy digests;
* the combined diff pin is distinct from every single patch digest and from the
  dependency-only diff;
* the libbox module-cache contract hashes to its pin;
* the pinned libbox Go build tag list is well formed and is exactly the tags the
  policy requires — including the tags whose omission would make ``box.New``
  fail on every start;
* the offline libbox build script references the pins with no floating versions and
  no network or recursive build actions;
* every CI job that enters the closed release gate uses exactly the pinned
  unsigned-validation Python;
* the packet-evidence endpoint names its own Go toolchain and binary pins, not
  ``GO_VERSION`` (when both name one Go version, their archive digests agree);
  its README keeps the exact fail-closed build recipe (archive check,
  reproducible build, comparison with the binary pin); the installer and
  every endpoint identity, which run on or describe the evidence instances and
  cannot read the pin file, carry exactly that binary pin; and the endpoint's
  source, deployed and policy files hash to their recorded digests;
* the physical collector's go.mod and go.sum hash to their recorded digests and
  keep the required module versions. Nothing binds the collector to
  ``GO_VERSION``.

Release scripts are not re-attested here: the exact Git commit bound by the
hosted CI receipt and the candidate freeze's release-source identity remain the
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
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping

MANIFEST_RELATIVE_PATH = "scripts/pinned_build_inputs.json"
DEPENDENCY_PINS_RELATIVE_PATH = "scripts/dependency_pins.env"
TAURI_CLI_INSTALLER_RELATIVE_PATH = "scripts/install_pinned_tauri_cli.sh"
MANIFEST_SCHEMA = "cfw-pinned-build-inputs-v2"
MAX_CONTROL_FILE_BYTES = 4 * 1024 * 1024
MAX_PINNED_MANIFEST_BYTES = 512 * 1024
PINNED_MANIFEST_FIELDS = frozenset(
    {
        "buildScripts",
        "cargoDeny",
        "description",
        "libboxBuildTags",
        "libboxModuleCacheContract",
        "packetEvidenceEndpoint",
        "patches",
        "physicalCollectorModule",
        "pinFormats",
        "rejectedPatchDigests",
        "schema",
        "tauriCli",
        "xcodegen",
    }
)
# Every key dependency_pins.env must define: the policy's format table must name
# exactly these keys, so a pin cannot disappear from the pin file and the policy
# together. Key names only; the values live in dependency_pins.env.
REQUIRED_PIN_KEYS = frozenset(
    {
        "MACOS_DEPLOYMENT_TARGET",
        "XCODE_VERSION",
        "XCODE_BUILD_VERSION",
        "XCODEGEN_VERSION",
        "XCODEGEN_COMMIT",
        "XCODEGEN_SOURCE_SHA256",
        "XCODEGEN_UPSTREAM_PACKAGE_RESOLVED_SHA256",
        "XCODEGEN_PACKAGE_RESOLVED_SHA256",
        "XCODEGEN_DEPENDENCY_PATCH_PATH",
        "XCODEGEN_DEPENDENCY_PATCH_SHA256",
        "XCODEGEN_AEXML_COMMIT",
        "XCODEGEN_AEXML_UPSTREAM_MANIFEST_SHA256",
        "XCODEGEN_PATCH_PATH",
        "XCODEGEN_PATCH_SHA256",
        "XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256",
        "PYTHON_VERSION",
        "RUST_VERSION",
        "RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256",
        "CARGO_AUDIT_VERSION",
        "CARGO_DENY_VERSION",
        "TAURI_CLI_VERSION",
        "TAURI_CLI_CRATE_SHA256",
        "TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256",
        "TAURI_CLI_SPIN_VERSION",
        "TAURI_CLI_SPIN_CRATE_SHA256",
        "TAURI_CARGO_CACHE_CONTRACT_SHA256",
        "SHELLCHECK_VERSION",
        "SHELLCHECK_DARWIN_ARM64_SHA256",
        "NODE_VERSION",
        "NODE_DARWIN_ARM64_SHA256",
        "NPM_VERSION",
        "NPM_ARCHIVE_SHA256",
        "GO_VERSION",
        "GO_DARWIN_ARM64_SHA256",
        "GO_WINDOWS_AMD64_SHA256",
        "WINTUN_VERSION",
        "WINTUN_ARCHIVE_SHA256",
        "WINTUN_WINDOWS_AMD64_SHA256",
        "WINTUN_BINARY_LICENSE_PATH",
        "WINTUN_BINARY_LICENSE_SHA256",
        "GOMOBILE_VERSION",
        "GOMOBILE_COMMIT",
        "GOMOBILE_MODULE_SUM",
        "GOVULNCHECK_VERSION",
        "GOVULNCHECK_MODULE_SUM",
        "SING_BOX_VERSION",
        "SING_BOX_COMMIT",
        "SING_BOX_UPSTREAM_GO_MOD_SHA256",
        "SING_BOX_UPSTREAM_GO_SUM_SHA256",
        "SING_BOX_SECURITY_PATCH_PATH",
        "SING_BOX_SECURITY_PATCH_SHA256",
        "SING_BOX_RAW_PACKET_PATCH_PATH",
        "SING_BOX_RAW_PACKET_PATCH_SHA256",
        "SING_BOX_DNS_FAILOVER_PATCH_PATH",
        "SING_BOX_DNS_FAILOVER_PATCH_SHA256",
        "SING_BOX_PROFILE_PROBE_PATCH_PATH",
        "SING_BOX_PROFILE_PROBE_PATCH_SHA256",
        "SING_BOX_ENDPOINT_CONFLICT_PATCH_PATH",
        "SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
        "SING_BOX_PATCHED_DIFF_SHA256",
        "SING_BOX_COMBINED_DIFF_SHA256",
        "SING_BOX_PATCHED_GO_MOD_SHA256",
        "SING_BOX_PATCHED_GO_SUM_SHA256",
        "SING_BOX_ANDROID_REFERENCE_COMMIT",
        "SING_BOX_APPLE_REFERENCE_COMMIT",
        "LIBBOX_APPLE_PLATFORM",
        "LIBBOX_BUILD_TAGS",
        "LIBBOX_NON_MACOS_TAGS",
        "LIBBOX_MODULE_CACHE_CONTRACT_PATH",
        "LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
        "SING_BOX_SOCKS_LIFECYCLE_PATCH_PATH",
        "SING_BOX_SOCKS_LIFECYCLE_PATCH_SHA256",
        "GO_RELEASE_TOOLS_GO_MOD_SHA256",
        "GO_RELEASE_TOOLS_GO_SUM_SHA256",
        "PACKET_EVIDENCE_ENDPOINT_GO_VERSION",
        "PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256",
        "PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256",
    }
)
# Value formats a pin may declare. ``repository-path`` values must also satisfy
# the canonical repository-relative path rules of the rooted reader.
PIN_VALUE_FORMATS = MappingProxyType(
    {
        "apple-build": re.compile(r"[0-9]+[A-Z][0-9]+[a-z]?"),
        "apple-version": re.compile(r"[0-9]+[.][0-9]+(?:[.][0-9]+)?"),
        "git-commit": re.compile(r"[0-9a-f]{40}"),
        "go-build-tags": re.compile(r"[a-z0-9_]+(?:,[a-z0-9_]+)*"),
        "go-module-sum": re.compile(r"h1:[A-Za-z0-9+/]{43}="),
        "go-module-version": re.compile(r"v[0-9]+[.][0-9]+[.][0-9]+"),
        "gomobile-target": re.compile(r"[a-z]+/[a-z0-9]+"),
        "repository-path": re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*"),
        "sha256": re.compile(r"[0-9a-f]{64}"),
        "version": re.compile(r"[0-9]+[.][0-9]+[.][0-9]+"),
    }
)
# The whole-tree diff of the patched sing-box checkout and its dependency-only
# go.mod/go.sum diff; the combined diff may equal neither a patch nor that diff.
COMBINED_DIFF_PIN_KEY = "SING_BOX_COMBINED_DIFF_SHA256"
PATCHED_DIFF_PIN_KEY = "SING_BOX_PATCHED_DIFF_SHA256"
PATCH_ENTRY_FIELDS = frozenset({"name", "pathKey", "sha256Key"})
XCODEGEN_POLICY_FIELDS = frozenset(
    {"patchPathKey", "patchSha256Key", "bootstrapPath", "requiredBootstrapFragments"}
)
TAURI_CLI_POLICY_FIELDS = frozenset(
    {
        "cacheContractPath",
        "cacheContractSha256Key",
        "ciWorkflowPath",
        "requiredCiFragment",
        "installerPath",
        "requiredInstallerFragments",
    }
)
LIBBOX_MODULE_CACHE_CONTRACT_FIELDS = frozenset({"pathKey", "sha256Key"})
LIBBOX_BUILD_TAG_FIELDS = frozenset({"pinKey", "required", "engineStartPathBindings"})
LIBBOX_REQUIRED_TAG_FIELDS = frozenset({"tag", "reason"})
LIBBOX_ENGINE_START_BINDING_FIELDS = frozenset(
    {"tag", "path", "requiredWhenContains", "triggerRequired", "reason"}
)
BUILD_SCRIPT_RULE_FIELDS = frozenset(
    {"requirePinReferences", "forbidNetworkRecursion"}
)
# (name, path pin, digest pin) of every sing-box patch the policy must hash.
REQUIRED_PATCH_POLICIES = frozenset(
    {
        (
            "sing-box SOCKS lifecycle patch",
            "SING_BOX_SOCKS_LIFECYCLE_PATCH_PATH",
            "SING_BOX_SOCKS_LIFECYCLE_PATCH_SHA256",
        ),
        (
            "sing-box security dependencies patch",
            "SING_BOX_SECURITY_PATCH_PATH",
            "SING_BOX_SECURITY_PATCH_SHA256",
        ),
        (
            "sing-box raw packet tun patch",
            "SING_BOX_RAW_PACKET_PATCH_PATH",
            "SING_BOX_RAW_PACKET_PATCH_SHA256",
        ),
        (
            "sing-box DNS failover patch",
            "SING_BOX_DNS_FAILOVER_PATCH_PATH",
            "SING_BOX_DNS_FAILOVER_PATCH_SHA256",
        ),
        (
            "sing-box profile probe patch",
            "SING_BOX_PROFILE_PROBE_PATCH_PATH",
            "SING_BOX_PROFILE_PROBE_PATCH_SHA256",
        ),
        (
            "sing-box endpoint conflict patch",
            "SING_BOX_ENDPOINT_CONFLICT_PATCH_PATH",
            "SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
        ),
    }
)
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
        (
            "with_tailscale",
            "crates/cfw-singbox-config/src/profile_projection.rs",
            'base_outbound("tailscale", tag)',
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
        "with_tailscale",
        "ts_omit_logtail",
        "ts_omit_ssh",
        "ts_omit_drive",
        "ts_omit_taildrop",
        "ts_omit_webclient",
        "ts_omit_doctor",
        "ts_omit_capture",
        "ts_omit_kube",
        "ts_omit_aws",
        "ts_omit_synology",
        "ts_omit_bird",
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
# Bash splits the sourced pin file on LF only; any other line break or control
# byte would make the verified view differ from the one release scripts use.
_ENV_TEXT_RE = re.compile(r"[\x20-\x7e\n]*")
_ENV_LINE_RE = re.compile(r"\A([A-Za-z_][A-Za-z0-9_]*)=(.*)\Z")
_NETWORK_RECURSION_RE = re.compile(
    r"git\s+clone|https?://|(?<![A-Za-z])curl(?![A-Za-z])|"
    r"(?<![A-Za-z])wget(?![A-Za-z])|go\s+get|go\s+install|GOPROXY\s*=\s*https?",
    re.IGNORECASE,
)
# The packet-evidence endpoint's own Go toolchain and reviewed Linux/amd64
# output, bumped independently of the product GO_VERSION.
_PACKET_ENDPOINT_GO_VERSION_KEY = "PACKET_EVIDENCE_ENDPOINT_GO_VERSION"
_PACKET_ENDPOINT_GO_ARCHIVE_SHA256_KEY = (
    "PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256"
)
PACKET_ENDPOINT_BINARY_SHA256_KEY = "PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256"
_PACKET_ENDPOINT_README = "tools/packet-evidence-endpoint/README.md"
_PACKET_ENDPOINT_INSTALLER = "tools/packet-evidence-endpoint/install-endpoint.sh"
_PACKET_ENDPOINT_POLICY = "scripts/physical_capture/packet_endpoints.json"
# The installer runs on the evidence instances and the endpoint identities
# describe them; neither can read the pin file, so each carries the binary pin
# and is checked against it.
_PACKET_ENDPOINT_INSTALLER_BINARY_PATHS = (
    "/tmp/packet-evidence-endpoint-linux-amd64",
    "/usr/local/libexec/cfw-packet-evidence-endpoint",
)
_PACKET_ENDPOINT_INSTALLER_DIGEST_CHECK_RE = re.compile(
    r"^verify_sha256 \\\n  ([0-9a-f]{64}) \\\n  (\S+)$", re.MULTILINE
)
_PACKET_ENDPOINT_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "document",
        "identities",
        "cases",
        "unresolved_cases",
        "unresolved_controls",
    }
)
_PACKET_ENDPOINT_SYSTEMD_UNIT_SHA256 = (
    "7d485a9fe9081ebf019fcc8abc1d596358a64326e2490749d9903197262e3996"
)
_PACKET_ENDPOINT_INSTALL_SCRIPT_SHA256 = (
    "fb24d320372c327a033a839c8759fb58afe5c7ecf140d204c31bccb73de06cff"
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
    "afa5339dea0b6369f45a6dac9005ad49314e5173b2b62d68b2271d6cfa490f14"
)
_PACKET_ENDPOINT_SOURCE_PATHS = frozenset(
    {
        "tools/packet-evidence-endpoint/go.mod",
        _PACKET_ENDPOINT_INSTALLER,
        "tools/packet-evidence-endpoint/main.go",
        "tools/packet-evidence-endpoint/main_test.go",
        "tools/packet-evidence-endpoint/packet-evidence-capture.sudoers",
        "tools/packet-evidence-endpoint/packet-evidence-endpoint.service",
        "tools/packet-evidence-endpoint/packet-evidence-resolv.conf",
        _PACKET_ENDPOINT_README,
        _PACKET_ENDPOINT_POLICY,
        "scripts/physical_capture/packet_known_hosts",
    }
)
# The README recipe, required verbatim: one fail-closed bash subshell that checks
# the endpoint's own Go archive before extracting it, builds the reproducible
# Linux/amd64 artifact with no inherited Go environment, and compares the output
# with the binary pin.
_PACKET_ENDPOINT_BUILD_RECIPE = (
    "(",
    "  set -euo pipefail",
    "  source scripts/dependency_pins.env",
    '  work="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/packet-evidence-endpoint.XXXXXX")"',
    "  trap '/bin/rm -rf \"$work\"' EXIT",
    '  archive="$work/go.darwin-arm64.tar.gz"',
    "  /usr/bin/curl --fail --location --proto '=https' --tlsv1.2 \\",
    f'    "https://go.dev/dl/go${_PACKET_ENDPOINT_GO_VERSION_KEY}.darwin-arm64.tar.gz" \\',
    '    --output "$archive"',
    f"  printf '%s  %s\\n' \"${_PACKET_ENDPOINT_GO_ARCHIVE_SHA256_KEY}\" \"$archive\" |",
    "    /usr/bin/shasum -a 256 --check",
    '  /bin/mkdir "$work/go" "$work/home"',
    '  /usr/bin/tar -xzf "$archive" -C "$work/go" --strip-components 1',
    "  /bin/mkdir -p target",
    '  /usr/bin/env -i PATH=/usr/bin:/bin HOME="$work/home" GOTOOLCHAIN=local \\',
    '    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOCACHE="$work/go-build-cache" \\',
    '    "$work/go/bin/go" -C tools/packet-evidence-endpoint build \\',
    "    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \\",
    "    -o ../../target/packet-evidence-endpoint-linux-amd64 .",
    f"  printf '%s  %s\\n' \"${PACKET_ENDPOINT_BINARY_SHA256_KEY}\" \\",
    "    target/packet-evidence-endpoint-linux-amd64 | /usr/bin/shasum -a 256 --check",
    ")",
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


@dataclass(frozen=True)
class VerifiedBuildInputs:
    """The pin values that passed :func:`verify_source_contract` together.

    ``pins`` is the complete parsed ``dependency_pins.env``; the patch and
    combined diff digests are the values checked against the patch files.
    """

    pins: Mapping[str, str]
    patch_digests: tuple[str, ...]
    combined_diff_sha256: str
    rejected_patch_digests: frozenset[str]


@dataclass(frozen=True)
class _DeclaredPins:
    """Pin values whose keys and formats match the policy's format table."""

    formats: Mapping[str, str]
    values: Mapping[str, str]

    def value(self, key: object, expected_format: str, description: str) -> str:
        """Return the pin a policy rule names, requiring its declared format."""
        if not isinstance(key, str) or self.formats.get(key) != expected_format:
            raise PinnedInputError(
                f"{description} must name a declared {expected_format} pin, not {key!r}"
            )
        return self.values[key]


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
    _require_canonical_relative_path(relative, description)
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
    return _utf8(
        _read_bytes(
            repository,
            relative,
            description,
            maximum_size=maximum_size,
        ),
        description,
    )


def _utf8(body: bytes, description: str) -> str:
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
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise PinnedInputError("pinned-input manifest has an unsupported schema")
    if not isinstance(manifest.get("description"), str) or not manifest["description"]:
        raise PinnedInputError("pinned-input manifest description is empty or malformed")
    return manifest


def _parse_env(text: str) -> dict[str, str]:
    if not _ENV_TEXT_RE.fullmatch(text):
        raise PinnedInputError(
            "dependency_pins.env must hold only printable ASCII lines separated by LF"
        )
    values: dict[str, str] = {}
    for number, line in enumerate(text.split("\n"), start=1):
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE_RE.match(line)
        if not match:
            raise PinnedInputError(f"dependency_pins.env line {number} is malformed: {line!r}")
        key, value = match.group(1), match.group(2)
        if key in values:
            raise PinnedInputError(f"dependency_pins.env defines {key} more than once")
        values[key] = value
    return values


def _require_sha256(value: str, description: str) -> str:
    if not _SHA256_RE.match(value):
        raise PinnedInputError(f"{description} is not a lowercase 64-hex SHA-256: {value!r}")
    return value


def _require_canonical_relative_path(relative: object, description: str) -> None:
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


def load_dependency_pins(repository: Path) -> dict[str, str]:
    """Parse ``scripts/dependency_pins.env`` exactly as bash splits it.

    The file is read through the rooted reader; a missing, unsafe or malformed
    file raises :class:`PinnedInputError`. Pin formats are not checked here.
    """
    return _parse_env(
        _read_text(
            repository,
            DEPENDENCY_PINS_RELATIVE_PATH,
            "dependency_pins.env",
        )
    )


def _verify_pin_formats(manifest: dict, env: dict[str, str]) -> _DeclaredPins:
    """Require exactly the declared pin keys, each holding its declared format."""
    formats = manifest.get("pinFormats")
    if not isinstance(formats, dict) or not formats:
        raise PinnedInputError("pinned-input policy has no pin format table")
    if set(formats) != REQUIRED_PIN_KEYS:
        raise PinnedInputError(
            "pinned-input policy pin format table differs from the fixed release "
            "pin key set: "
            + ", ".join(sorted(set(formats) ^ REQUIRED_PIN_KEYS))
        )
    missing = sorted(set(formats) - set(env))
    if missing:
        raise PinnedInputError(
            f"dependency_pins.env is missing required pins: {', '.join(missing)}"
        )
    undeclared = sorted(set(env) - set(formats))
    if undeclared:
        raise PinnedInputError(
            "dependency_pins.env defines pins the policy does not declare: "
            + ", ".join(undeclared)
        )
    for key, format_name in formats.items():
        if not isinstance(format_name, str) or format_name not in PIN_VALUE_FORMATS:
            raise PinnedInputError(f"pin {key} declares an unknown format {format_name!r}")
        value = env[key]
        if not PIN_VALUE_FORMATS[format_name].fullmatch(value):
            raise PinnedInputError(
                f"dependency_pins.env pin {key} is not a {format_name} value: {value!r}"
            )
        if format_name == "repository-path":
            _require_canonical_relative_path(value, f"dependency_pins.env pin {key}")
    return _DeclaredPins(
        formats=MappingProxyType(dict(formats)),
        values=MappingProxyType(dict(env)),
    )


def _verify_pinned_file_digest(
    repository: Path,
    pins: _DeclaredPins,
    path_key: object,
    sha256_key: object,
    description: str,
) -> str:
    """Hash the tracked file a path pin names and require its digest pin."""
    relative = pins.value(path_key, "repository-path", f"{description} path key")
    expected = pins.value(sha256_key, "sha256", f"{description} digest key")
    actual = hashlib.sha256(_read_bytes(repository, relative, description)).hexdigest()
    if actual != expected:
        raise PinnedInputError(
            f"{description} file digest {actual} differs from the pinned "
            f"{sha256_key} {expected}"
        )
    return expected


def _verify_packet_evidence_endpoint(
    manifest: dict, pins: _DeclaredPins, repository: Path
) -> None:
    spec = manifest.get("packetEvidenceEndpoint")
    expected_fields = {
        "goVersionKey",
        "goArchiveSha256Key",
        "binarySha256Key",
        "goos",
        "goarch",
        "cgoEnabled",
        "transportPort",
        "dnsPort",
        "readmePath",
        "buildRecipe",
        "sourceFiles",
    }
    if not isinstance(spec, dict) or set(spec) != expected_fields:
        raise PinnedInputError(
            "packet evidence endpoint pinned-input contract is missing or has unknown fields"
        )
    if (
        spec["goVersionKey"] != _PACKET_ENDPOINT_GO_VERSION_KEY
        or spec["goArchiveSha256Key"] != _PACKET_ENDPOINT_GO_ARCHIVE_SHA256_KEY
        or spec["binarySha256Key"] != PACKET_ENDPOINT_BINARY_SHA256_KEY
    ):
        raise PinnedInputError(
            "packet evidence endpoint must name its own Go toolchain and binary pins"
        )
    endpoint_go = pins.value(
        spec["goVersionKey"], "version", "packet evidence endpoint Go version"
    )
    endpoint_go_archive = pins.value(
        spec["goArchiveSha256Key"], "sha256", "packet evidence endpoint Go archive"
    )
    # Independent pins may still name the same official release; one Go
    # version has one darwin-arm64 archive, so its two digests must agree.
    if endpoint_go == pins.value(
        "GO_VERSION", "version", "product Go version"
    ) and endpoint_go_archive != pins.value(
        "GO_DARWIN_ARM64_SHA256", "sha256", "product Go archive"
    ):
        raise PinnedInputError(
            "packet evidence endpoint and product pin one Go version with "
            "different archive digests"
        )
    binary_sha256 = pins.value(
        spec["binarySha256Key"], "sha256", "packet evidence endpoint binary"
    )
    if (
        spec["goos"] != "linux"
        or spec["goarch"] != "amd64"
        or spec["cgoEnabled"] != "0"
        or spec["transportPort"] != 44333
        or spec["dnsPort"] != 53
        or spec["readmePath"] != _PACKET_ENDPOINT_README
        or spec["buildRecipe"] != list(_PACKET_ENDPOINT_BUILD_RECIPE)
    ):
        raise PinnedInputError(
            "packet evidence endpoint build target, ports, or build recipe drifted"
        )

    source_files = spec["sourceFiles"]
    if not isinstance(source_files, list) or len(source_files) != len(
        _PACKET_ENDPOINT_SOURCE_PATHS
    ):
        raise PinnedInputError(
            "packet evidence endpoint must bind the exact source, test, service, policy, host-key, and README set"
        )
    contents: dict[str, bytes] = {}
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
        body = _read_bytes(
            repository,
            relative,
            f"packet evidence endpoint source {relative}",
        )
        if hashlib.sha256(body).hexdigest() != digest:
            raise PinnedInputError(
                f"packet evidence endpoint source digest drifted for {relative!r}"
            )
        contents[relative] = body
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
    if observed[_PACKET_ENDPOINT_INSTALLER] != _PACKET_ENDPOINT_INSTALL_SCRIPT_SHA256:
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
    if observed[_PACKET_ENDPOINT_POLICY] != _PACKET_ENDPOINT_POLICY_SHA256:
        raise PinnedInputError(
            "packet evidence endpoint instance policy differs from its whole-file pin"
        )
    readme = _utf8(contents[_PACKET_ENDPOINT_README], "packet evidence endpoint README")
    if "\n".join(("```sh", *_PACKET_ENDPOINT_BUILD_RECIPE, "```")) not in readme:
        raise PinnedInputError(
            "packet evidence endpoint README lacks the exact build recipe"
        )
    _verify_packet_endpoint_binary_copies(
        _utf8(contents[_PACKET_ENDPOINT_INSTALLER], "packet evidence endpoint installer"),
        _utf8(contents[_PACKET_ENDPOINT_POLICY], "packet evidence endpoint policy"),
        binary_sha256,
    )


def _verify_packet_endpoint_binary_copies(
    installer: str, policy_text: str, binary_sha256: str
) -> None:
    """Require the installer and every instance identity to carry the binary pin."""
    checks = _PACKET_ENDPOINT_INSTALLER_DIGEST_CHECK_RE.findall(installer)
    for path in _PACKET_ENDPOINT_INSTALLER_BINARY_PATHS:
        if [digest for digest, checked in checks if checked == path] != [binary_sha256]:
            raise PinnedInputError(
                f"packet evidence endpoint installer must verify {path} exactly once "
                f"against {PACKET_ENDPOINT_BINARY_SHA256_KEY}"
            )
    policy = _load_strict_json(
        policy_text,
        "packet evidence endpoint policy",
        expected_fields=_PACKET_ENDPOINT_POLICY_FIELDS,
    )
    identities = policy["identities"]
    if not isinstance(identities, list) or not identities:
        raise PinnedInputError(
            "packet evidence endpoint policy binds no instance identity"
        )
    for index, entry in enumerate(identities):
        identity = entry.get("identity") if isinstance(entry, dict) else None
        if (
            not isinstance(identity, dict)
            or identity.get("endpoint_binary_sha256") != binary_sha256
        ):
            raise PinnedInputError(
                f"packet evidence endpoint identities[{index}] does not carry "
                f"{PACKET_ENDPOINT_BINARY_SHA256_KEY}"
            )


def _verify_physical_collector_module(manifest: dict, repository: Path) -> None:
    spec = manifest.get("physicalCollectorModule")
    expected_fields = {
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
        spec["goModPath"] != "tools/physical-collector/go.mod"
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
    go_mod_text = _utf8(go_mod, "physical-collector go.mod")
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


def _verify_xcodegen(manifest: dict, pins: _DeclaredPins, repository: Path) -> None:
    spec = manifest.get("xcodegen")
    if not isinstance(spec, dict) or set(spec) != XCODEGEN_POLICY_FIELDS:
        raise PinnedInputError("pinned-input policy has no exact XcodeGen patch binding")
    _verify_pinned_file_digest(
        repository,
        pins,
        spec["patchPathKey"],
        spec["patchSha256Key"],
        "XcodeGen patch",
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


def _verify_tauri_cli(manifest: dict, pins: _DeclaredPins, repository: Path) -> None:
    spec = manifest.get("tauriCli")
    if not isinstance(spec, dict) or set(spec) != TAURI_CLI_POLICY_FIELDS:
        raise PinnedInputError("pinned-input policy has no exact Tauri CLI source binding")

    cache_contract_relative = spec["cacheContractPath"]
    if not isinstance(cache_contract_relative, str):
        raise PinnedInputError("Tauri Cargo cache contract path is malformed")
    cache_contract_expected = pins.value(
        spec["cacheContractSha256Key"],
        "sha256",
        "Tauri Cargo cache contract digest key",
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


def _rejected_patch_digests(manifest: dict) -> frozenset[str]:
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
    rejected = frozenset(rejected_values)
    if rejected != REQUIRED_REJECTED_PATCH_DIGESTS:
        raise PinnedInputError(
            "pinned-input manifest rejected patch digests differ from release policy"
        )
    return rejected


def _verify_patches(
    manifest: dict,
    pins: _DeclaredPins,
    repository: Path,
    rejected: frozenset[str],
) -> tuple[str, ...]:
    patches = manifest.get("patches")
    if not isinstance(patches, list) or len(patches) != len(REQUIRED_PATCH_POLICIES):
        raise PinnedInputError("pinned-input policy must name exactly six patches")
    policy_identities: list[tuple[str, str, str]] = []
    for patch in patches:
        if not isinstance(patch, dict) or set(patch) != PATCH_ENTRY_FIELDS:
            raise PinnedInputError("pinned-input policy has a malformed patch entry")
        identity = (patch["name"], patch["pathKey"], patch["sha256Key"])
        if not all(isinstance(item, str) and item for item in identity):
            raise PinnedInputError(f"patch entry {identity[0]!r} is missing pin keys")
        if identity in policy_identities:
            raise PinnedInputError("pinned-input policy repeats a patch policy identity")
        policy_identities.append(identity)
    if frozenset(policy_identities) != REQUIRED_PATCH_POLICIES:
        raise PinnedInputError(
            "pinned-input policy patches differ from the fixed patch policy set"
        )

    digests: list[str] = []
    for name, path_key, sha_key in policy_identities:
        digest = _verify_pinned_file_digest(
            repository, pins, path_key, sha_key, f"patch {name}"
        )
        if digest in rejected:
            raise PinnedInputError(f"patch {name} pins a rejected/legacy digest: {digest}")
        if digest in digests:
            raise PinnedInputError(f"patch {name} reuses another patch digest: {digest}")
        digests.append(digest)
    return tuple(digests)


def _verify_combined_diff(pins: _DeclaredPins, patch_digests: tuple[str, ...]) -> str:
    combined = pins.value(COMBINED_DIFF_PIN_KEY, "sha256", "combined diff")
    if combined in patch_digests:
        raise PinnedInputError(
            "combined diff digest equals a single patch digest; partial digest rejected"
        )
    if combined == pins.value(PATCHED_DIFF_PIN_KEY, "sha256", "dependency-only diff"):
        raise PinnedInputError(
            "combined diff digest equals the partial go.mod/go.sum diff digest"
        )
    return combined


def _verify_libbox_module_cache_contract(
    manifest: dict, pins: _DeclaredPins, repository: Path
) -> None:
    spec = manifest.get("libboxModuleCacheContract")
    if not isinstance(spec, dict) or set(spec) != LIBBOX_MODULE_CACHE_CONTRACT_FIELDS:
        raise PinnedInputError(
            "pinned-input policy has no exact libbox module cache contract binding"
        )
    _verify_pinned_file_digest(
        repository,
        pins,
        spec["pathKey"],
        spec["sha256Key"],
        "libbox module cache contract",
    )


def _verify_libbox_build_tags(
    manifest: dict, pins: _DeclaredPins, repository: Path
) -> None:
    """Bind the pinned libbox Go build tag list to the tags the engine requires.

    The tag list is a build input exactly like a version or a digest: omitting a
    tag silently removes compiled-in behaviour the runtime depends on. The
    ``with_clash_api`` omission made ``box.New`` fail on every engine start
    because the patched tree enables the clash API whenever a platform log writer
    is installed and the daemon always installs one, so the stub constructor
    returned an error instead of a server. This check therefore requires the
    pinned tag list to be exactly the policy's required tags, each with its
    recorded reason, and additionally binds tracked source triggers (such as the
    application-owned ``experimental.clash_api`` projection block) to the tag
    that makes them reachable, so the same class of defect fails closed
    statically.
    """
    spec = manifest.get("libboxBuildTags")
    if not isinstance(spec, dict) or set(spec) != LIBBOX_BUILD_TAG_FIELDS:
        raise PinnedInputError("pinned-input manifest has no libbox build tag binding")
    pin_key = spec["pinKey"]
    actual_value = pins.value(pin_key, "go-build-tags", "libbox build tag pin key")

    tags: list[str] = actual_value.split(",")
    seen: set[str] = set()
    for tag in tags:
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


def _verify_ci_release_python(repository: Path, pins: _DeclaredPins) -> None:
    workflow = _read_text(
        repository,
        ".github/workflows/ci.yml",
        "CI workflow",
    )
    expected_python = pins.value("PYTHON_VERSION", "version", "release Python pin")
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


def verify_source_contract(repository: Path) -> VerifiedBuildInputs:
    """Verify every static pinned input without invoking a toolchain.

    Returns the pin values exactly as verified so callers bind the same values
    instead of re-reading the pin file.
    """
    manifest = _load_manifest(repository)
    env = load_dependency_pins(repository)
    pins = _verify_pin_formats(manifest, env)
    _verify_packet_evidence_endpoint(manifest, pins, repository)
    _verify_physical_collector_module(manifest, repository)
    _verify_cargo_deny(manifest, repository)
    _verify_xcodegen(manifest, pins, repository)
    _verify_tauri_cli(manifest, pins, repository)
    rejected = _rejected_patch_digests(manifest)
    patch_digests = _verify_patches(manifest, pins, repository, rejected)
    combined = _verify_combined_diff(pins, patch_digests)
    _verify_libbox_module_cache_contract(manifest, pins, repository)
    _verify_libbox_build_tags(manifest, pins, repository)
    _verify_build_scripts(manifest, repository)
    _verify_ci_release_python(repository, pins)
    return VerifiedBuildInputs(
        pins=pins.values,
        patch_digests=patch_digests,
        combined_diff_sha256=combined,
        rejected_patch_digests=rejected,
    )
