#!/usr/bin/env python3
"""Fail-closed verifier for the design-pinned libbox and toolchain inputs.

The source-contract layer binds the pinned-input manifest
(``scripts/pinned_build_inputs.json``) to the tracked release configuration
without invoking any toolchain or the network. The default :func:`verify`
entrypoint additionally requires the generated packet LAN peer artifact, while
:func:`verify_source_contract` intentionally stops at its pinned identity:

* every pinned tool version and the sing-box/gomobile upstream commits in
  scripts/dependency_pins.env match the manifest exactly;
* cargo-audit and cargo-deny's CI installs consume their release pins with
  ``--locked`` and the release gate checks the exact Apple Silicon target graph;
* the XcodeGen installed-resource patch and patched source digest are bound to
    the isolated bootstrap and its installed-resource probe;
* the official Tauri CLI crate, its published lock, the narrow yanked-spin lock
  update, the resulting lock, and the exact Cargo cache-normalization contract
  are checksum-bound to one installer entrypoint;
* the four design-pinned patch files exist as regular files and their computed
  SHA-256 digests match both the manifest and dependency_pins.env;
* the combined diff SHA-256 is pinned and is distinct from any single patch digest;
* known legacy/partial patch digests are rejected;
* the verified Go module inputs (module sums and go.mod/go.sum digests) are present
  and well formed;
* the Android packet LAN peer's complete source tree, reproducible Linux/arm64
  build and verification scripts, bounded TCP contract, generated artifact
  identity, and fixed shell-owned deployment layout are independently pinned;
* the ADB runtime path, version, and executable digest are pinned independently
  and match the Android admission source constants exactly;
* the pinned libbox Go build tag list is exactly the pinned value, is well formed,
  and contains every tag the engine start path requires — including the tags whose
  omission would make ``box.New`` fail on every start;
* the native dependency lock agrees with the pins (source-tree binding);
* the offline libbox build script references the pins with no floating versions and
  no network or recursive build actions;
* the build scripts bind the pinned commit, patch, and combined-diff hashes into the
  produced artifact manifests (artifact-hash bindings);
* every artifact-bound source except this self-referential verifier has an exact
  release-freeze SHA-256 whose complete mapping has a code-owned Level 1 identity.

Any unavailable, missing, malformed, wrong, or partial input fails closed.
"""

from __future__ import annotations

import ast
import copy
import errno
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
import tokenize
from pathlib import Path, PurePosixPath

if __package__:
    from .hash_artifact import build_manifest
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from hash_artifact import build_manifest

MANIFEST_RELATIVE_PATH = "scripts/pinned_build_inputs.json"
DEPENDENCY_PINS_RELATIVE_PATH = "scripts/dependency_pins.env"
NATIVE_LOCK_RELATIVE_PATH = "native/macos/Dependencies.lock.json"
TAURI_CLI_INSTALLER_RELATIVE_PATH = "scripts/install_pinned_tauri_cli.sh"
# Level 1 source identity: detect accidental or unreviewed installer drift.
# Exact Git/hosted-CI identity remains the trust root; this is not authentication.
REQUIRED_TAURI_CLI_INSTALLER_SHA256 = (
    "7bc439d444cb7dc00c6c60fd7ee9003124ae635d331d71df7c528f75d6158ce7"
)
MAX_CONTROL_FILE_BYTES = 4 * 1024 * 1024
MAX_PINNED_MANIFEST_BYTES = 512 * 1024
MAX_NATIVE_LOCK_BYTES = 256 * 1024
PINNED_MANIFEST_FIELDS = frozenset(
    {
        "artifactBindings",
        "artifactSourceSha256",
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
        "packetLanPeer",
        "patches",
        "physicalCollectorModule",
        "rejectedPatchDigests",
        "runtimeTools",
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
# This Level 1 identity detects accidental or unreviewed policy drift in the
# complete path-to-fragment mapping. It is an exact policy checksum, not an
# authentication mechanism or a claim that the repository resists its owner.
REQUIRED_ARTIFACT_BINDINGS_SHA256 = (
    "8022aff8052e54fbb68476d99d801b8cbf1d248fe300e71d7dff9da27c741e1b"
)
# Level 1 identity of the complete path-to-source-digest release-freeze map.
# It detects accidental or unreviewed drift; it is not authentication and does
# not claim to protect the repository from its owner. The verifier itself is
# excluded to avoid a recursive self-hash.
ARTIFACT_SOURCE_DIGEST_SELF_EXCLUSION = "scripts/verify_pinned_build_inputs.py"
REQUIRED_ARTIFACT_SOURCE_DIGESTS_SHA256 = (
    "d80b4675fb0ce324c98a7f45018af11c1165f38005a9f2eedd228dbbc868198b"
)
# Level 1 structural identities for the fixed release-policy functions.  AST
# identities deliberately omit source locations so formatting cannot alter the
# result.  They detect reviewed-function drift; exact Git/hosted-CI identity is
# still the external trust root and these checks are not authentication.
GA_RELEASE_POLICY_GUARD_FUNCTION_AST_SHA256 = {
    "_publish_and_confirm_stage": "f8647aa681a7e02ca7e38be3f18cfd903fdc2c9cfedf938d0f8313f407dc1c93",
    "_require_hosted_ci_source_binding": "63a05e630f3622bbcd4d5b418ebe8174487d8690ea60b383147bd24e87696f0a",
    "_verified_prepackage_inputs": "dc428b342b9d2f7818ef9b129c244057f9a91e5c29fe7f9f30caa0517e7264ac",
    "_verified_package_sets": "03322fad12344a0f9dbf70acaf152a78a6fa09778794c52202bc6c804110791d",
    "_verified_migration_journals": "aae37ebedddaa00d345475f26ed45e28d69d1097bee7a9a9997b6dd63b7bcc28",
    "_expected_candidate_from_prepackage": "6157ac3c2f944787433c9db2ed8bdc95e80d88866729b5a2351fd7c15975e42e",
    "_require_migration_matches_prepackage": "ec7e739571f12b1204412b2ad1d4ea721855b1442047f20eaa275cab4c7eb93a",
    "_verified_acceptance_inputs": "6a326b17cf90c28e4410a5b883676d4c64d79c18c9d87e7b9e6a1717d561e702",
    "_verified_runtime_acceptance_adapter": "093b48c0a98761e5b8287281c032850ccc8aaeea6f71cac04c6c5030e1c55e16",
    "_ga_acceptance_files": "d4530d6ef4c092df45eab0dd91f0751872ad82f69c0a8d011f5a0382e3cb9023",
    "_prepackage_files": "6f93a995b7aa3a8efcee95c6b423e259d153a26b3d0cc7b7c7d33f5c317f5d8c",
    "build_expected_stage_files": "48ccccf9fffbad3948ac662cffd812856ad39863be5410c15e6d521a2f7fabda",
    "verify_stage": "9b60090cc53552fe01d9891ec634678b9faa6df7cb5bd40b7ced755b9d8c0dd8",
    "verify_prepackage_authorization": "0b9ae7f3ec556847e8f65af5a4760c25eb359552d42de8e3cba26cf09629f29a",
    "verify_publication_authorization": "cdc26323dba3a714add18e1e30394717e3a98eafef0e87adfa460f7a0b67ae61",
    "derive_runtime_expectation": "8c6916b576a732aea4ad533c64549a1835b68d78410cae6614435f9420826624",
    "seal_prepackage": "3d63970071f5c47783136635b7091ce7f352f91f9cba15019f37f16dd9a5b223",
    "seal_ga_acceptance": "3474c8516cc7190c5f3b5164dd4a4c54288709fbc58a58c3f87e0fce0d40cecd",
    "seal_publication": "808fbaaea13245bb940eecaf1abc047f472211f8e1e95192a34f47e4a71e1f89",
    "_compose_stage_files": "284e186baba2f7dbb21d02b3fc3fb2380e86ada30464b4ceb81a5df9d459ce8f",
    "_current_stage_executor": "4640733086dffe90fffdef7b33fc52163268546e16d404200ee6b18eb9517b55",
    "_verify_stage": "8f6f61fd8a69a137b8bb5cce99fd6a7f1104f7ee5558162d92072213cdfc594f"
}
GA_RELEASE_CLI_FUNCTION_AST_SHA256 = {
    "scripts/ga_runtime_acceptance_cli.py": {
        "_existing_runtime_outputs": "d37a6c6a3011b0acfa634f7a9f6ff2aadb24eb0750b0f762a182f469d1e74063",
        "_run_runtime_command": "84b2acfa2fd1f5858b14f688e78d928784ec82713b999dafb30fa7f0df21e3fc",
        "main": "e5b7736ffa5a8d72160b18c08cb16678f50b78a4d5d1d718498aa27ee096fa68"
    },
    "scripts/release_artifact_set_cli.py": {
        "_run_verification_command": "679c3827128d6ec7fbcbf3e2b3c1bd938a54470efe304a32540bc5cad64fa862",
        "main": "7144daa7b40662a231b907a366ea1798b234f9306c672cce77258cf5aa26631b"
    }
}
PINNED_VERIFIER_GUARD_FUNCTION_AST_SHA256 = {
    "_artifact_binding_surface": "fae882ae2244166f36c3a5376b9a3e8777ce2aefc41c0cf852b5fe5bbc2f3e77",
    "_verify_build_scripts": "a8cf93cc988322f742d31a3914338d53eb4e805ceb87422b164ca25da8933910",
    "_verify_pinned_verifier_structure": "3ad60e2d9ef3f43529da3b95b1401fb209502f700ba4c35267d54c43689426da"
}
PINNED_VERIFIER_MODULE_AST_SHA256 = (
    "33dddc6234702108048c69eb6b058e005ce28f16290e18c00d140c20201f5bb5"
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
        "PYTHON_VERSION",
        "RUST_VERSION",
        "RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256",
        "CARGO_AUDIT_VERSION",
        "CARGO_DENY_VERSION",
        "XCODEGEN_VERSION",
        "XCODEGEN_COMMIT",
        "XCODEGEN_SOURCE_SHA256",
        "XCODEGEN_PACKAGE_RESOLVED_SHA256",
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
    "c63c202b22823197ad12cb2d5f484c95be25904260ed266083dcca6fc766db6c"
)
_PACKET_ENDPOINT_SYSTEMD_UNIT_SHA256 = (
    "7d485a9fe9081ebf019fcc8abc1d596358a64326e2490749d9903197262e3996"
)
_PACKET_ENDPOINT_INSTALL_SCRIPT_SHA256 = (
    "14b45b1705f762057ac38d836f2ac5c7d3721e72ec0ec45b72505b354f0d05c8"
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
    "35f1e9bfc73baae302f7b26e24adf86df57a01c61f3c71133ae7cba23e64a5cb"
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
    "target/toolchains/go-1.26.6/bin/go",
    "-C tools/packet-evidence-endpoint",
    "-trimpath",
    "-ldflags='-s -w -buildid='",
    "-o ../../target/packet-evidence-endpoint-linux-amd64",
    _PACKET_ENDPOINT_BINARY_SHA256,
)
_PACKET_LAN_PEER_ARTIFACT_SHA256 = (
    "268699e59caff2ea3ddf73e2a22b556364724a6bae985d012f1df7e2b089085c"
)
_PACKET_LAN_PEER_ARTIFACT_SIZE = 2359422
_ADB_RUNTIME_TOOL_PATH = "/Users/bill/Library/Android/sdk/platform-tools/adb"
_ADB_RUNTIME_TOOL_VERSION = "37.0.0-14910828"
_ADB_RUNTIME_TOOL_SHA256 = (
    "5759ea07285e5a5b66d84f489c118a3fa3998e69cd37725e5a3dc7cbe0597278"
)
_ANDROID_LAN_PEER_SOURCE_PATH = "scripts/physical_capture/android_lan_peer.py"
_ANDROID_LAN_PEER_SOURCE_SHA256 = (
    "bed9e81cd7e11eb4251a3324acee88e8e9195d0f8ac33f59f9c755fff25148b2"
)
_ANDROID_LAN_PEER_SOURCE_SIZE = 137417
_PACKET_LAN_PEER_SOURCE_TREE_SHA256 = (
    "8437dce5e85780a49e882dd1594b188ce0f5188c44b7a020fe7a42d7efaa08a4"
)
_PACKET_LAN_PEER_BUILD_SCRIPT_SHA256 = (
    "c3fb49c83d98a710a15874afe83a3606b3f50f1f65b01c76dbb03edfcc9b43d8"
)
_PACKET_LAN_PEER_VERIFY_SCRIPT_SHA256 = (
    "eb7c518d3209ccf6486847e9f9042f58796b2192d5fdd733f3b991f640d7309e"
)
_PACKET_LAN_PEER_SOURCE_FILES = (
    (
        "README.md",
        "b84a4528927d8b7ceb707203a35d8052579717fb19a9b380a4828147b38b3547",
        2035,
        "0644",
    ),
    (
        "go.mod",
        "af5ff7973354844d111edb9d303d6543d8aa6dc0afc6ecf439225acc15e1d1fd",
        70,
        "0644",
    ),
    (
        "main.go",
        "fb6dd50acaa306f9664ef1e89929041459bf68b3ec13feee8166dcc8bf588b4b",
        7757,
        "0644",
    ),
    (
        "main_test.go",
        "ef4b6eff3f31f4d17345bf0da67726f1c2f6b776c15ab2691bbb3710487ca87e",
        10813,
        "0644",
    ),
)
_PACKET_LAN_PEER_BUILD_FRAGMENTS = (
    'source "$repo_root/scripts/dependency_pins.env"',
    'source "$repo_root/scripts/release_toolchain_contract.sh"',
    'cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"',
    'source_root="$repo_root/tools/packet-lan-peer"',
    'artifact="$repo_root/target/packet-lan-peer-linux-arm64"',
    "GOTOOLCHAIN=local",
    "GOFLAGS=-mod=readonly",
    "GOPROXY=off",
    "GOSUMDB=sum.golang.org",
    "GOVCS='*:off'",
    "CGO_ENABLED=0",
    "GOOS=linux",
    "GOARCH=arm64",
    "-buildvcs=false",
    "-trimpath",
    "-ldflags='-s -w -buildid='",
    '/usr/bin/cmp -s "$first" "$second"',
    '/bin/chmod 0555 "$artifact_staging"',
    '/bin/mv -fh "$artifact_staging" "$artifact"',
)
_PACKET_LAN_PEER_VERIFY_FRAGMENTS = (
    'source "$repo_root/scripts/dependency_pins.env"',
    'source "$repo_root/scripts/release_toolchain_contract.sh"',
    'cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"',
    'source_root="$repo_root/tools/packet-lan-peer"',
    'artifact="$repo_root/target/packet-lan-peer-linux-arm64"',
    "expected_artifact_sha256=268699e59caff2ea3ddf73e2a22b556364724a6bae985d012f1df7e2b089085c",
    "expected_artifact_size=2359422",
    "expected_artifact_mode=555",
    "module_path=github.com/billziss-gh/cfw-rs/tools/packet-lan-peer",
    "GOTOOLCHAIN=local",
    "GOFLAGS=-mod=readonly",
    "GOPROXY=off",
    "GOSUMDB=sum.golang.org",
    "GOVCS='*:off'",
    "CGO_ENABLED=0 GOOS=linux GOARCH=arm64",
    'expected_imports="$(printf',
    "net\\.(ListenPacket|ListenUDP)",
    '"$go_bin" -C "$source_root" test -count=1 ./...',
    '"$go_bin" -C "$source_root" vet ./...',
    '"$go_bin" -C "$source_root" test -race -count=1 ./...',
    '"$repo_root/scripts/build_packet_lan_peer.sh"',
    '"$go_bin" version -m "$artifact"',
    '"$go_bin" tool buildid "$artifact"',
    'artifact_sha256="$(/usr/bin/shasum -a 256 "$artifact"',
    '"$artifact_mode" != "$expected_artifact_mode"',
    '"$artifact_size" != "$expected_artifact_size"',
    '"$artifact_sha256" != "$expected_artifact_sha256"',
)
_PHYSICAL_COLLECTOR_GO_MOD_SHA256 = (
    "24b0294d6fe42b5baab92bc58ed47a69275323bb02ca75b087605a5aabf2b2d0"
)
_PHYSICAL_COLLECTOR_GO_SUM_SHA256 = (
    "5c71b0dca9d0be45b65ab07b1a7386475f72d454c9638d60c36494a75fbc35ec"
)
_PHYSICAL_COLLECTOR_MODULE_FRAGMENTS = (
    "google.golang.org/grpc v1.82.1",
    "golang.org/x/text v0.39.0",
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
    expected_uid: int | None = None,
    expected_mode: int | None = None,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    """Read one repository file through a root-anchored held descriptor chain."""
    if type(maximum_size) is not int or maximum_size < 1:
        raise PinnedInputError(f"{description} has no positive byte bound")
    if expected_uid is None:
        expected_uid = os.geteuid()
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
            if opened.st_uid != expected_uid:
                raise PinnedInputError(
                    f"{description} is not owned by the effective user"
                )
            if expected_mode is None and opened.st_mode & 0o022:
                raise PinnedInputError(
                    f"{description} is writable by group or other users"
                )
            if (
                expected_mode is not None
                and stat.S_IMODE(opened.st_mode) != expected_mode
            ):
                raise PinnedInputError(
                    f"{description} mode is not {expected_mode:04o}"
                )
            if expected_size is not None and opened.st_size != expected_size:
                raise PinnedInputError(
                    f"{description} size is {opened.st_size}, expected {expected_size}"
                )
            if opened.st_size > maximum_size:
                raise PinnedInputError(
                    f"{description} exceeds its {maximum_size}-byte bound"
                )

            digest = hashlib.sha256()
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
                digest.update(chunk)
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
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise PinnedInputError(f"{description} SHA-256 differs from its pin")
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


def _python_binding_surface(source: str, relative: str) -> tuple[str, ast.Module]:
    """Return Python source with comments and docstrings removed from policy use."""

    try:
        module = ast.parse(source, filename=relative)
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (SyntaxError, tokenize.TokenError, IndentationError) as error:
        raise PinnedInputError(
            f"artifact-bound Python source is malformed: {relative}: {error}"
        ) from error

    for node in ast.walk(module):
        if (
            isinstance(node, (ast.If, ast.While))
            and isinstance(node.test, ast.Constant)
            and not bool(node.test.value)
        ):
            raise PinnedInputError(
                f"artifact-bound Python source contains a statically unreachable block: {relative}"
            )

    docstring_starts: set[tuple[int, int]] = set()
    for owner in (module, *(
        node
        for node in ast.walk(module)
        if isinstance(
            node,
            (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        )
    )):
        body = owner.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            docstring_starts.add(
                (body[0].value.lineno, body[0].value.col_offset)
            )

    lines = [list(line) for line in source.splitlines(keepends=True)]

    def blank(start: tuple[int, int], end: tuple[int, int]) -> None:
        start_line, start_column = start
        end_line, end_column = end
        for line_number in range(start_line, end_line + 1):
            line = lines[line_number - 1]
            first = start_column if line_number == start_line else 0
            last = end_column if line_number == end_line else len(line)
            for index in range(first, min(last, len(line))):
                if line[index] not in {"\n", "\r"}:
                    line[index] = " "

    for token in tokens:
        if token.type == tokenize.COMMENT or (
            token.type == tokenize.STRING and token.start in docstring_starts
        ):
            blank(token.start, token.end)
    return "".join("".join(line) for line in lines), module


def _direct_call_positions(
    function: ast.FunctionDef,
    call_names: frozenset[str],
    *,
    require_unconditional: bool = False,
    verified_alias_targets: tuple[ast.Name, ...] = (),
    protected_provider_names: frozenset[str] = frozenset(),
) -> dict[str, list[int]]:
    positions = {name: [] for name in call_names}

    def call_identifier(node: ast.Call) -> str | None:
        parts: list[str] = []
        target: ast.expr = node.func
        while isinstance(target, ast.Attribute):
            parts.append(target.attr)
            target = target.value
        if not isinstance(target, ast.Name):
            return None
        parts.append(target.id)
        return ".".join(reversed(parts))

    protected_names = {name for name in call_names if "." not in name}
    protected_names.update(protected_provider_names)
    forbidden_control_calls = frozenset(
        {
            "builtins.eval",
            "builtins.exec",
            "builtins.exit",
            "builtins.quit",
            "builtins.SystemExit",
            "eval",
            "exec",
            "exit",
            "GeneratorExit",
            "KeyboardInterrupt",
            "os._exit",
            "quit",
            "SystemExit",
            "sys.exit",
        }
    )
    for node in ast.walk(function):
        if isinstance(node, (ast.Assert, ast.ClassDef, ast.TryStar, ast.Yield, ast.YieldFrom)):
            raise PinnedInputError(
                f"release guard function {function.name} contains forbidden "
                f"{type(node).__name__} control flow"
            )
        if (
            isinstance(node, ast.Call)
            and (identifier := call_identifier(node)) in forbidden_control_calls
        ):
            raise PinnedInputError(
                f"release guard function {function.name} contains a forbidden "
                f"control call {identifier}"
            )
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id in protected_names
            and node not in verified_alias_targets
        ) or (
            isinstance(node, ast.arg)
            and node.arg in protected_names
        ) or (
            isinstance(node, (ast.Global, ast.Nonlocal))
            and protected_names.intersection(node.names)
        ):
            raise PinnedInputError(
                f"release guard function {function.name} rebinds a policy validator"
            )
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            raise PinnedInputError(
                f"release guard function {function.name} mutates a dotted policy binding"
            )

    for index, statement in enumerate(function.body):
        if any(
            isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            )
            for node in ast.walk(statement)
            if node is not statement
        ):
            raise PinnedInputError(
                f"release guard function {function.name} contains a nested callable"
            )
        parents = {
            child: parent
            for parent in ast.walk(statement)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(statement):
            call_name = call_identifier(node) if isinstance(node, ast.Call) else None
            if (
                call_name is not None
                and call_name in positions
            ):
                if require_unconditional:
                    ancestor = parents.get(node)
                    while ancestor is not None:
                        if isinstance(
                            ancestor,
                            (
                                ast.If,
                                ast.IfExp,
                                ast.For,
                                ast.AsyncFor,
                                ast.While,
                                ast.Match,
                                ast.comprehension,
                                ast.BoolOp,
                                ast.ExceptHandler,
                                ast.With,
                                ast.AsyncWith,
                            ),
                        ):
                            raise PinnedInputError(
                                f"production orchestrator {function.name} critical "
                                "guard is conditional"
                            )
                        if isinstance(ancestor, ast.Try) and (
                            ancestor.orelse
                            or ancestor.finalbody
                            or not ancestor.handlers
                            or any(
                                len(handler.body) != 1
                                or not isinstance(handler.body[0], ast.Raise)
                                for handler in ancestor.handlers
                            )
                        ):
                            raise PinnedInputError(
                                f"production orchestrator {function.name} critical "
                                "guard exception path is not fail closed"
                            )
                        ancestor = parents.get(ancestor)
                positions[call_name].append(index)

    required_positions = [
        position for observed in positions.values() for position in observed
    ]
    if required_positions:
        last_required_position = max(required_positions)
        for index, statement in enumerate(function.body[: last_required_position + 1]):
            returns = [node for node in ast.walk(statement) if isinstance(node, ast.Return)]
            if returns and (
                index < last_required_position or index != len(function.body) - 1
            ):
                raise PinnedInputError(
                    f"release guard function {function.name} returns before a "
                    "required policy validator"
                )
            if index < last_required_position and isinstance(statement, ast.Raise):
                raise PinnedInputError(
                    f"release guard function {function.name} raises before a "
                    "required policy validator"
                )
    return positions


def _verify_orchestrator_release_guard(module: ast.Module, relative: str) -> None:
    orchestrator_relative = "scripts/publication/orchestrator.py"
    contract_relative = "scripts/publication/ga_release_contract.py"
    if relative not in {orchestrator_relative, contract_relative}:
        raise PinnedInputError("GA release guard was applied to an unexpected module")

    imported_guards = frozenset(
        {
            "ACCEPTANCE_ROOT_RELATIVE",
            "ENVIRONMENT_RELATIVE",
            "INSTALL_RELATIVE",
            "MIGRATION_RELATIVE",
            "SERVICE_RELATIVE",
            "build_manifest",
            "capture_executor_source",
            "identity_at_commit",
            "live_verify_hosted_ci_receipt",
            "require_executor_unchanged",
            "require_historical_executor",
            "validate_source_identity",
            "validate_candidate_app_manifest",
            "validate_ci_lane_document",
            "validate_gatekeeper_evidence",
            "validate_hosted_ci_receipt_offline",
            "validate_notary_files",
            "validate_published_transaction_receipt",
            "verify_ga_acceptance_journal_export",
            "verify_ga_workspace_path_preconditions",
            "verify_frozen_candidate",
            "verify_signing_transformation_receipt",
            "validate_ga_runtime_acceptance",
        }
    )
    expected_imports = {
        "ACCEPTANCE_ROOT_RELATIVE": (
            "scripts.ga_acceptance_journal_export",
            0,
            "ACCEPTANCE_ROOT_RELATIVE",
            None,
        ),
        "ENVIRONMENT_RELATIVE": (
            "scripts.ga_acceptance_journal_export",
            0,
            "ENVIRONMENT_RELATIVE",
            None,
        ),
        "INSTALL_RELATIVE": (
            "scripts.ga_acceptance_journal_export",
            0,
            "INSTALL_RELATIVE",
            None,
        ),
        "MIGRATION_RELATIVE": (
            "scripts.ga_acceptance_journal_export",
            0,
            "MIGRATION_RELATIVE",
            None,
        ),
        "SERVICE_RELATIVE": (
            "scripts.ga_acceptance_journal_export",
            0,
            "SERVICE_RELATIVE",
            None,
        ),
        "build_manifest": ("scripts.hash_artifact", 0, "build_manifest", None),
        "capture_executor_source": (
            "scripts.release_executor_source", 0, "capture_executor_source", None
        ),
        "identity_at_commit": (
            "scripts.repository_source_identity", 0, "identity_at_commit", None
        ),
        "require_executor_unchanged": (
            "scripts.release_executor_source", 0, "require_executor_unchanged", None
        ),
        "require_historical_executor": (
            "scripts.release_executor_source", 0, "require_historical_executor", None
        ),
        "validate_source_identity": (
            "scripts.release_executor_source", 0, "validate_source_identity", None
        ),
        "live_verify_hosted_ci_receipt": (
            "scripts.github_hosted_ci_receipt",
            0,
            "verify_receipt",
            "live_verify_hosted_ci_receipt",
        ),
        "validate_candidate_app_manifest": (
            "scripts.candidate_artifact_binding",
            0,
            "validate_candidate_app_manifest",
            None,
        ),
        "validate_ci_lane_document": (
            "sealed_manifest",
            1,
            "validate_ci_lane_document",
            None,
        ),
        "validate_ga_runtime_acceptance": (
            "scripts.ga_runtime_acceptance",
            0,
            "validate_ga_runtime_acceptance",
            None,
        ),
        "validate_gatekeeper_evidence": (
            "scripts.gatekeeper_assessment",
            0,
            "validate_evidence",
            "validate_gatekeeper_evidence",
        ),
        "verify_ga_acceptance_journal_export": (
            "scripts.ga_acceptance_journal_export",
            0,
            "verify_ga_acceptance_journal_export",
            None,
        ),
        "verify_ga_workspace_path_preconditions": (
            "scripts.release_build_identity",
            0,
            "verify_ga_workspace_path_preconditions",
            None,
        ),
        "validate_hosted_ci_receipt_offline": (
            "scripts.github_hosted_ci_receipt",
            0,
            "validate_receipt_offline",
            "validate_hosted_ci_receipt_offline",
        ),
        "validate_notary_files": (
            "scripts.verify_notary_log",
            0,
            "validate_files",
            "validate_notary_files",
        ),
        "validate_published_transaction_receipt": (
            "scripts.notarization_transaction",
            0,
            "validate_published_transaction_receipt",
            None,
        ),
        "verify_frozen_candidate": (
            "scripts.candidate_freeze",
            0,
            "verify_frozen_candidate",
            None,
        ),
        "verify_signing_transformation_receipt": (
            "scripts.verify_signing_transformation",
            0,
            "verify_retained_receipt",
            "verify_signing_transformation_receipt",
        ),
    }
    orchestrator_functions = (
        "_publish_and_confirm_stage",
        "seal_prepackage",
        "seal_ga_acceptance",
        "seal_publication",
    )
    contract_functions = (
        "_require_hosted_ci_source_binding",
        "_verified_prepackage_inputs",
        "_verified_package_sets",
        "_verified_migration_journals",
        "_expected_candidate_from_prepackage",
        "_require_migration_matches_prepackage",
        "_verified_acceptance_inputs",
        "_verified_runtime_acceptance_adapter",
        "_ga_acceptance_files",
        "_prepackage_files",
        "_compose_stage_files",
        "_current_stage_executor",
        "build_expected_stage_files",
        "_verify_stage",
        "verify_stage",
        "verify_prepackage_authorization",
        "verify_publication_authorization",
        "derive_runtime_expectation",
    )
    expected_function_names = (
        orchestrator_functions
        if relative == orchestrator_relative
        else contract_functions
    )
    if set(GA_RELEASE_POLICY_GUARD_FUNCTION_AST_SHA256) != set(
        orchestrator_functions + contract_functions
    ):
        raise PinnedInputError("GA release guarded function policy is incomplete")

    if relative == orchestrator_relative:
        observed_contract_imports: list[tuple[str | None, int, str, str | None]] = []
        for node in ast.walk(module):
            if not isinstance(node, ast.ImportFrom):
                continue
            for alias in node.names:
                if (alias.asname or alias.name) == "contract":
                    observed_contract_imports.append(
                        (node.module, node.level, alias.name, alias.asname)
                    )
        if observed_contract_imports != [(None, 1, "ga_release_contract", "contract")]:
            raise PinnedInputError(
                "production orchestrator contract import differs from policy"
            )
    else:
        observed_imports = {name: [] for name in expected_imports}
        for node in ast.walk(module):
            if not isinstance(node, ast.ImportFrom):
                continue
            for alias in node.names:
                target = alias.asname or alias.name
                if target in observed_imports:
                    observed_imports[target].append(
                        (node.module, node.level, alias.name, alias.asname)
                    )
        if any(
            observed_imports[name] != [expected]
            for name, expected in expected_imports.items()
        ):
            raise PinnedInputError(
                "production GA contract policy validator imports differ from policy"
            )

    functions: dict[str, ast.FunctionDef] = {}
    for name in expected_function_names:
        matches = [
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        if len(matches) != 1:
            raise PinnedInputError(
                "production GA release entrypoints differ from policy"
            )
        if matches[0].decorator_list:
            raise PinnedInputError(
                "production GA release guard entrypoints cannot be decorated"
            )
        functions[name] = matches[0]
    stage_assignments = [
        node
        for node in module.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == "STAGES"
            for target in (
                node.targets if isinstance(node, ast.Assign) else (node.target,)
            )
        )
    ]
    schema_assignments = [
        node
        for node in module.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == "STAGE_SCHEMA_VERSIONS"
            for target in (
                node.targets if isinstance(node, ast.Assign) else (node.target,)
            )
        )
    ]
    if relative == contract_relative:
        if len(stage_assignments) != 1:
            raise PinnedInputError("production GA contract stage order is not unique")
        stage_value = stage_assignments[0].value
        if (
            not isinstance(stage_value, ast.Tuple)
            or tuple(
                item.value if isinstance(item, ast.Constant) else None
                for item in stage_value.elts
            )
            != ("prepackage", "ga-acceptance", "publication")
        ):
            raise PinnedInputError(
                "production GA contract stage order differs from policy"
            )
        try:
            stage_schema_versions = (
                ast.literal_eval(schema_assignments[0].value)
                if len(schema_assignments) == 1
                else None
            )
        except (ValueError, TypeError):
            stage_schema_versions = None
        if stage_schema_versions != {
            "prepackage": 2,
            "ga-acceptance": 3,
            "publication": 3,
        }:
            raise PinnedInputError(
                "production GA contract stage schemas differ from policy"
            )
    elif stage_assignments or schema_assignments:
        raise PinnedInputError(
            "production orchestrator must not own stage order or schemas"
        )

    imported_bindings = imported_guards if relative == contract_relative else {"contract"}
    protected_module_names = (
        frozenset(imported_bindings)
        | frozenset(functions)
        | {"STAGES", "STAGE_SCHEMA_VERSIONS"}
    )
    allowed_statement_ids = {id(function) for function in functions.values()}
    allowed_statement_ids.update(id(statement) for statement in stage_assignments)
    allowed_statement_ids.update(id(statement) for statement in schema_assignments)
    dynamic_mutators = {
        "delattr",
        "eval",
        "exec",
        "globals",
        "locals",
        "setattr",
    }
    for statement in module.body:
        if id(statement) in allowed_statement_ids:
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            aliases = {
                alias.asname or alias.name.split(".", 1)[0]
                for alias in statement.names
            }
            if aliases.intersection(
                frozenset(functions) | {"STAGES", "STAGE_SCHEMA_VERSIONS"}
            ):
                raise PinnedInputError(
                    "production GA release module imports over a protected binding"
                )
            continue
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if statement.name in protected_module_names:
                raise PinnedInputError(
                    "production GA release module redefines a protected binding"
                )
            continue
        for node in ast.walk(statement):
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and node.id in protected_module_names
            ):
                raise PinnedInputError(
                    "production GA release module rebinds a protected binding"
                )
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                raise PinnedInputError(
                    "production GA release module performs a dynamic binding mutation"
                )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in dynamic_mutators
            ):
                raise PinnedInputError(
                    "production GA release module invokes a dynamic binding mutator"
                )

    def require_calls(
        function_name: str,
        expected: dict[str, list[int]],
        *,
        require_unconditional: bool = True,
    ) -> None:
        calls = _direct_call_positions(
            functions[function_name],
            frozenset(expected),
            require_unconditional=require_unconditional,
        )
        if calls != expected:
            raise PinnedInputError(
                f"production GA release {function_name} guard calls differ from policy"
            )
    if relative == orchestrator_relative:
        require_calls(
            "_publish_and_confirm_stage",
            {"_publish_stage": [0], "contract.verify_stage": [1]},
        )
        for function_name in (
            "seal_prepackage",
            "seal_ga_acceptance",
            "seal_publication",
        ):
            require_calls(
                function_name,
                {
                    "contract.build_expected_stage_files": [1],
                    "_publish_and_confirm_stage": [2],
                },
            )
    else:
        require_calls(
            "verify_stage",
            {
                "_canonical_repository": [1],
                "_current_stage_executor": [2],
                "_verify_stage": [3],
                "require_executor_unchanged": [4],
            },
        )
        require_calls(
            "_verify_stage",
            {
                "_read_stage_files": [1, 9],
                "_manifest_from_files": [2],
                "_path": [2],
                "identity_at_commit": [4],
                "validate_source_identity": [5],
                "_compose_stage_files": [7],
            },
        )

    verified_alias_targets: dict[str, tuple[ast.Name, ...]] = {}
    if relative == contract_relative:
        freeze_function = functions["_verified_prepackage_inputs"]
        alias_assignments = [
            node
            for node in freeze_function.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "selected_freeze_verifier"
                for target in node.targets
            )
        ]
        expected_alias = ast.parse(
            "selected_freeze_verifier = "
            "verify_frozen_candidate if freeze_verifier is None else freeze_verifier"
        ).body[0]
        if (
            len(alias_assignments) != 1
            or ast.dump(alias_assignments[0], include_attributes=False)
            != ast.dump(expected_alias, include_attributes=False)
        ):
            raise PinnedInputError("GA frozen verifier provider selection differs from policy")
        # Admit only this exact, unconditional provider selection. Any later
        # assignment, deletion, argument shadow or global rebind still fails.
        target = alias_assignments[0].targets[0]
        if not isinstance(target, ast.Name):
            raise PinnedInputError("GA frozen verifier provider target is invalid")
        verified_alias_targets[freeze_function.name] = (target,)

    critical_calls = {
        "_verified_prepackage_inputs": frozenset(
            {
                "selected_freeze_verifier",
                "validate_ci_lane_document",
                "validate_hosted_ci_receipt_offline",
                "_require_hosted_ci_source_binding",
                "validate_candidate_app_manifest",
                "_validate_release_application",
                "verify_signing_transformation_receipt",
                "validate_published_transaction_receipt",
                "_validate_signing_notarization_binding",
                "validate_notary_files",
                "validate_gatekeeper_evidence",
                "verify_ga_workspace_path_preconditions",
                "_verified_legal_source_closure",
                "build_manifest",
            }
        ),
        "_verified_package_sets": frozenset(
            {"artifact_set.verify_dmg_set", "artifact_set.verify_updater_set"}
        ),
        "_verified_migration_journals": frozenset(
            {"verify_ga_acceptance_journal_export"}
        ),
        "_require_migration_matches_prepackage": frozenset(
            {"_expected_candidate_from_prepackage"}
        ),
        "_verified_acceptance_inputs": frozenset(
            {
                "_verified_migration_journals",
                "_require_migration_matches_prepackage",
                "_verified_runtime_acceptance_adapter",
            }
        ),
        "_verified_runtime_acceptance_adapter": frozenset(
            {"validate_ga_runtime_acceptance"}
        ),
        "_ga_acceptance_files": frozenset(
            {"_verified_package_sets", "_verified_acceptance_inputs"}
        ),
        "_prepackage_files": frozenset(
            {"_verified_prepackage_inputs", "_stage_manifest"}
        ),
        "_current_stage_executor": frozenset(
            {"capture_executor_source", "require_historical_executor"}
        ),
        "build_expected_stage_files": frozenset(
            {
                "_canonical_repository",
                "_current_stage_executor",
                "_compose_stage_files",
                "require_executor_unchanged",
            }
        ),
        "verify_prepackage_authorization": frozenset(
            {
                "_canonical_repository",
                "_require_artifact_set_adapter",
                "verify_stage",
                "artifact_set._validate_prepackage_binding",
            }
        ),
        "verify_publication_authorization": frozenset(
            {
                "_canonical_repository",
                "_require_artifact_set_adapter",
            }
        ),
        "derive_runtime_expectation": frozenset(
            {
                "_canonical_repository",
                "verify_stage",
                "_verified_package_sets",
                "_verified_migration_journals",
                "_require_migration_matches_prepackage",
            }
        ),
    }
    for function_name, expected_calls in critical_calls.items():
        if function_name not in functions:
            continue
        positions = _direct_call_positions(
            functions[function_name],
            expected_calls,
            require_unconditional=function_name != "build_expected_stage_files",
            verified_alias_targets=verified_alias_targets.get(function_name, ()),
            protected_provider_names=(
                frozenset({"verify_frozen_candidate"})
                if function_name == "_verified_prepackage_inputs"
                else frozenset()
            ),
        )
        if any(len(observed) != 1 for observed in positions.values()):
            raise PinnedInputError(
                f"production GA release {function_name} critical guards differ from policy"
            )
    if relative == contract_relative:
        acceptance_positions = _direct_call_positions(
            functions["_ga_acceptance_files"],
            frozenset({"_verified_package_sets", "_verified_acceptance_inputs"}),
            require_unconditional=True,
        )
        if not (
            acceptance_positions["_verified_package_sets"][0]
            < acceptance_positions["_verified_acceptance_inputs"][0]
        ):
            raise PinnedInputError(
                "GA package verification must precede runtime acceptance"
            )
        migration_positions = _direct_call_positions(
            functions["_verified_acceptance_inputs"],
            frozenset(
                {
                    "_verified_migration_journals",
                    "_require_migration_matches_prepackage",
                    "_verified_runtime_acceptance_adapter",
                }
            ),
            require_unconditional=True,
        )
        if not (
            migration_positions["_verified_migration_journals"][0]
            < migration_positions["_require_migration_matches_prepackage"][0]
            < migration_positions["_verified_runtime_acceptance_adapter"][0]
        ):
            raise PinnedInputError(
                "GA migration export and candidate verification must precede runtime acceptance"
            )
        derivation_positions = _direct_call_positions(
            functions["derive_runtime_expectation"],
            frozenset(
                {
                    "verify_stage",
                    "_verified_package_sets",
                    "_verified_migration_journals",
                    "_require_migration_matches_prepackage",
                }
            ),
            require_unconditional=True,
        )
        if not (
            derivation_positions["verify_stage"][0]
            < derivation_positions["_verified_package_sets"][0]
            < derivation_positions["_verified_migration_journals"][0]
            < derivation_positions["_require_migration_matches_prepackage"][0]
        ):
            raise PinnedInputError(
                "GA runtime derivation order differs from release policy"
            )

    expected_stage_calls = (
        {
            "_compose_stage_files": (
                "prepackage",
                "prepackage",
                "ga-acceptance",
            ),
            "verify_prepackage_authorization": ("prepackage",),
            "verify_publication_authorization": ("prepackage", "publication"),
            "derive_runtime_expectation": ("prepackage",),
        }
        if relative == contract_relative
        else {}
    )
    for function_name, expected_stages in expected_stage_calls.items():
        observed: list[tuple[int, str | None]] = []
        for node in ast.walk(functions[function_name]):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id
                == ("_verify_stage" if function_name == "_compose_stage_files" else "verify_stage")
            ):
                stage = (
                    node.args[1].value
                    if len(node.args) == 2
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id == "repository"
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                    and len(node.keywords) == 1
                    and node.keywords[0].arg == "freeze_verifier"
                    and isinstance(node.keywords[0].value, ast.Name)
                    and node.keywords[0].value.id == "freeze_verifier"
                    else None
                )
                observed.append((node.lineno, stage))
        if tuple(stage for _line, stage in sorted(observed)) != expected_stages:
            raise PinnedInputError(
                f"production GA contract {function_name} predecessor order differs from policy"
            )
    function_ast_sha256 = {
        name: hashlib.sha256(
            ast.dump(
                function,
                annotate_fields=True,
                include_attributes=False,
            ).encode("utf-8")
        ).hexdigest()
        for name, function in functions.items()
    }
    expected_ast_sha256 = {
        name: GA_RELEASE_POLICY_GUARD_FUNCTION_AST_SHA256[name]
        for name in expected_function_names
    }
    if function_ast_sha256 != expected_ast_sha256:
        raise PinnedInputError(
            "production GA release guarded function AST differs from release policy"
        )


def _verify_ga_release_cli_guard(module: ast.Module, relative: str) -> None:
    expected_functions = GA_RELEASE_CLI_FUNCTION_AST_SHA256.get(relative)
    if expected_functions is None:
        raise PinnedInputError("GA release CLI guard was applied to an unexpected module")
    functions = [
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef)
    ]
    if (
        {node.name for node in functions} != set(expected_functions)
        or len(functions) != len(expected_functions)
        or any(node.decorator_list for node in functions)
        or "main" not in expected_functions
    ):
        raise PinnedInputError("GA release CLI main entrypoint differs from policy")
    observed_functions = {
        node.name: hashlib.sha256(
            ast.dump(
                node,
                annotate_fields=True,
                include_attributes=False,
            ).encode("utf-8")
        ).hexdigest()
        for node in functions
    }
    if observed_functions != expected_functions:
        raise PinnedInputError("GA release CLI injection AST differs from policy")
    dispatches = [
        statement
        for statement in module.body
        if isinstance(statement, ast.If)
        and isinstance(statement.test, ast.Compare)
        and isinstance(statement.test.left, ast.Name)
        and statement.test.left.id == "__name__"
        and len(statement.test.ops) == 1
        and isinstance(statement.test.ops[0], ast.Eq)
        and len(statement.test.comparators) == 1
        and isinstance(statement.test.comparators[0], ast.Constant)
        and statement.test.comparators[0].value == "__main__"
    ]
    dispatch = dispatches[0] if len(dispatches) == 1 else None
    if not (
        dispatch is not None
        and module.body[-1] is dispatch
        and len(dispatch.body) == 1
        and not dispatch.orelse
        and isinstance(dispatch.body[0], ast.Expr)
        and isinstance(dispatch.body[0].value, ast.Call)
        and isinstance(dispatch.body[0].value.func, ast.Name)
        and dispatch.body[0].value.func.id == "main"
        and not dispatch.body[0].value.args
        and not dispatch.body[0].value.keywords
    ):
        raise PinnedInputError("GA release CLI module dispatch differs from policy")


def _verify_pinned_verifier_structure(module: ast.Module) -> None:
    functions = {
        name: [
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        for name in (
            "_artifact_binding_surface",
            "_verify",
            "_verify_build_scripts",
            "_verify_pinned_verifier_structure",
            "verify_source_contract",
            "verify",
            "main",
        )
    }
    if any(len(matches) != 1 for matches in functions.values()):
        raise PinnedInputError(
            "pinned-input verifier entrypoint structure differs from release policy"
        )
    if any(matches[0].decorator_list for matches in functions.values()):
        raise PinnedInputError(
            "pinned-input verifier validation functions cannot be decorated"
        )
    assignments = {
        target.id
        for node in module.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in (
            node.targets if isinstance(node, ast.Assign) else (node.target,)
        )
        if isinstance(target, ast.Name)
    }
    required_constants = {
        "DEPENDENCY_PINS_RELATIVE_PATH",
        "NATIVE_LOCK_RELATIVE_PATH",
        "REQUIRED_ARTIFACT_BINDINGS_SHA256",
        "ARTIFACT_SOURCE_DIGEST_SELF_EXCLUSION",
        "REQUIRED_ARTIFACT_SOURCE_DIGESTS_SHA256",
        "GA_RELEASE_POLICY_GUARD_FUNCTION_AST_SHA256",
        "GA_RELEASE_CLI_FUNCTION_AST_SHA256",
        "PINNED_VERIFIER_GUARD_FUNCTION_AST_SHA256",
        "PINNED_VERIFIER_MODULE_AST_SHA256",
        "TAURI_CLI_INSTALLER_RELATIVE_PATH",
        "REQUIRED_TAURI_CLI_INSTALLER_SHA256",
        "REQUIRED_TOOL_PIN_KEYS",
        "REQUIRED_VERIFIED_GO_MODULE_INPUT_KEYS",
        "REQUIRED_PATCH_POLICIES",
        "REQUIRED_REJECTED_PATCH_DIGESTS",
        "REQUIRED_ENGINE_START_PATH_BINDINGS",
        "REQUIRED_LIBBOX_BUILD_TAGS",
        "REQUIRED_BUILD_SCRIPT_POLICIES",
    }
    if not required_constants.issubset(assignments):
        raise PinnedInputError(
            "pinned-input verifier constants differ from release policy"
        )

    self_exclusion_assignments = [
        node
        for node in module.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name)
            and target.id == "ARTIFACT_SOURCE_DIGEST_SELF_EXCLUSION"
            for target in (
                node.targets if isinstance(node, ast.Assign) else (node.target,)
            )
        )
    ]
    if (
        len(self_exclusion_assignments) != 1
        or not isinstance(self_exclusion_assignments[0].value, ast.Constant)
        or self_exclusion_assignments[0].value.value
        != "scripts/verify_pinned_build_inputs.py"
    ):
        raise PinnedInputError(
            "pinned-input verifier self-exclusion differs from release policy"
        )

    def executable_body(function: ast.FunctionDef) -> list[ast.stmt]:
        body = list(function.body)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body.pop(0)
        return body

    for function_name, expected_value in (
        ("verify_source_contract", False),
        ("verify", True),
    ):
        function = functions[function_name][0]
        body = executable_body(function)
        call = body[0].value if len(body) == 1 and isinstance(body[0], ast.Expr) else None
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "_verify"
            and len(call.args) == 1
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == "repository"
            and len(call.keywords) == 1
            and call.keywords[0].arg == "require_packet_lan_peer_artifact"
            and isinstance(call.keywords[0].value, ast.Constant)
            and call.keywords[0].value.value is expected_value
        ):
            raise PinnedInputError(
                f"pinned-input verifier entrypoint {function_name} differs from policy"
            )

    validation_chain = functions["_verify"][0]
    if any(
        isinstance(node, (ast.Return, ast.Assert))
        for node in ast.walk(validation_chain)
    ):
        raise PinnedInputError(
            "pinned-input verifier validation chain has an early exit"
        )
    guarded_validation_functions = (
        validation_chain,
        functions["_verify_build_scripts"][0],
    )
    forbidden_validation_calls = {
        "eval",
        "exec",
        "exit",
        "quit",
        "sys.exit",
        "os._exit",
        "builtins.eval",
        "builtins.exec",
        "builtins.exit",
        "builtins.quit",
    }
    for function in guarded_validation_functions:
        for node in ast.walk(function):
            if isinstance(node, ast.Raise) and not (
                isinstance(node.exc, ast.Call)
                and isinstance(node.exc.func, ast.Name)
                and node.exc.func.id == "PinnedInputError"
            ):
                raise PinnedInputError(
                    f"pinned-input verifier {function.name} has a non-policy exit"
                )
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    identifier = node.func.id
                elif (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                ):
                    identifier = f"{node.func.value.id}.{node.func.attr}"
                else:
                    identifier = None
                if identifier in forbidden_validation_calls:
                    raise PinnedInputError(
                        f"pinned-input verifier {function.name} has a forbidden "
                        f"control call {identifier}"
                    )
    expected_chain = (
        "_load_manifest",
        "_parse_env",
        "_verify_tools",
        "_verify_runtime_tools",
        "_verify_packet_evidence_endpoint",
        "_verify_packet_lan_peer_source_contract",
        "_verify_packet_lan_peer_artifact",
        "_verify_physical_collector_module",
        "_verify_cargo_deny",
        "_verify_xcodegen",
        "_verify_tauri_cli",
        "_verify_commits",
        "_verify_patches",
        "_verify_combined_diff",
        "_verify_source_contract",
        "_verify_libbox_module_cache_contract",
        "_verify_go_module_inputs",
        "_verify_libbox_build_tags",
        "_verify_native_lock",
        "_verify_build_scripts",
    )
    observed_chain = tuple(
        node.func.id
        for node in sorted(
            (
                node
                for node in ast.walk(validation_chain)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in expected_chain
            ),
            key=lambda node: (node.lineno, node.col_offset),
        )
    )
    if observed_chain != expected_chain:
        raise PinnedInputError(
            "pinned-input verifier validation call order differs from release policy"
        )
    chain_parents = {
        child: parent
        for parent in ast.walk(validation_chain)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(validation_chain):
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Name)
            or node.func.id not in expected_chain
        ):
            continue
        conditional_ancestors: list[ast.AST] = []
        ancestor = chain_parents.get(node)
        while ancestor is not None and ancestor is not validation_chain:
            if isinstance(
                ancestor,
                (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.Try,
                 ast.Match, ast.comprehension, ast.BoolOp, ast.With, ast.AsyncWith),
            ):
                conditional_ancestors.append(ancestor)
            ancestor = chain_parents.get(ancestor)
        if node.func.id == "_verify_packet_lan_peer_artifact":
            if (
                len(conditional_ancestors) != 1
                or not isinstance(conditional_ancestors[0], ast.If)
                or not isinstance(conditional_ancestors[0].test, ast.Name)
                or conditional_ancestors[0].test.id
                != "require_packet_lan_peer_artifact"
            ):
                raise PinnedInputError(
                    "pinned-input verifier generated-artifact branch differs from policy"
                )
        elif conditional_ancestors:
            raise PinnedInputError(
                "pinned-input verifier validation call became conditional"
            )

    build_script_verifier = functions["_verify_build_scripts"][0]
    if any(isinstance(node, ast.Return) for node in ast.walk(build_script_verifier)):
        raise PinnedInputError(
            "pinned-input artifact-source verifier has an early return"
        )
    required_identity_comparisons = {
        (
            "artifact_binding_identity",
            "REQUIRED_ARTIFACT_BINDINGS_SHA256",
        ),
        (
            "artifact_source_identity",
            "REQUIRED_ARTIFACT_SOURCE_DIGESTS_SHA256",
        ),
    }
    observed_identity_comparisons = {
        (node.left.id, node.comparators[0].id)
        for node in ast.walk(build_script_verifier)
        if isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.NotEq)
        and isinstance(node.left, ast.Name)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Name)
    }
    if not required_identity_comparisons.issubset(observed_identity_comparisons):
        raise PinnedInputError(
            "pinned-input artifact-source identity checks differ from release policy"
        )

    main_function = functions["main"][0]
    main_body = executable_body(main_function)
    if (
        len(main_body) != 4
        or not isinstance(main_body[0], ast.Assign)
        or not isinstance(main_body[1], ast.Try)
        or len(main_body[1].body) != 1
        or not isinstance(main_body[1].body[0], ast.Expr)
        or not isinstance(main_body[1].body[0].value, ast.Call)
        or not isinstance(main_body[1].body[0].value.func, ast.Name)
        or main_body[1].body[0].value.func.id != "verify"
        or main_body[1].orelse
        or main_body[1].finalbody
        or len(main_body[1].handlers) != 1
        or len(main_body[1].handlers[0].body) != 2
        or not isinstance(main_body[1].handlers[0].body[-1], ast.Return)
        or not isinstance(main_body[1].handlers[0].body[-1].value, ast.Constant)
        or main_body[1].handlers[0].body[-1].value.value != 1
        or not isinstance(main_body[2], ast.Expr)
        or not isinstance(main_body[3], ast.Return)
        or not isinstance(main_body[3].value, ast.Constant)
        or main_body[3].value.value != 0
    ):
        raise PinnedInputError(
            "pinned-input verifier main failure propagation differs from policy"
        )
    main_dispatches = [
        statement
        for statement in module.body
        if isinstance(statement, ast.If)
        and isinstance(statement.test, ast.Compare)
        and isinstance(statement.test.left, ast.Name)
        and statement.test.left.id == "__name__"
        and len(statement.test.ops) == 1
        and isinstance(statement.test.ops[0], ast.Eq)
        and len(statement.test.comparators) == 1
        and isinstance(statement.test.comparators[0], ast.Constant)
        and statement.test.comparators[0].value == "__main__"
    ]
    dispatch = main_dispatches[0] if len(main_dispatches) == 1 else None
    dispatch_raise = (
        dispatch.body[0]
        if dispatch is not None
        and module.body[-1] is dispatch
        and len(dispatch.body) == 1
        and not dispatch.orelse
        and isinstance(dispatch.body[0], ast.Raise)
        else None
    )
    dispatch_exit = (
        dispatch_raise.exc
        if dispatch_raise is not None and dispatch_raise.cause is None
        else None
    )
    dispatch_main = (
        dispatch_exit.args[0]
        if isinstance(dispatch_exit, ast.Call)
        and isinstance(dispatch_exit.func, ast.Name)
        and dispatch_exit.func.id == "SystemExit"
        and len(dispatch_exit.args) == 1
        and not dispatch_exit.keywords
        else None
    )
    if not (
        isinstance(dispatch_main, ast.Call)
        and isinstance(dispatch_main.func, ast.Name)
        and dispatch_main.func.id == "main"
        and not dispatch_main.args
        and not dispatch_main.keywords
    ):
        raise PinnedInputError(
            "pinned-input verifier module dispatch differs from release policy"
        )
    verifier_function_ast_sha256 = {
        name: hashlib.sha256(
            ast.dump(
                functions[name][0],
                annotate_fields=True,
                include_attributes=False,
            ).encode("utf-8")
        ).hexdigest()
        for name in PINNED_VERIFIER_GUARD_FUNCTION_AST_SHA256
    }
    if verifier_function_ast_sha256 != PINNED_VERIFIER_GUARD_FUNCTION_AST_SHA256:
        raise PinnedInputError(
            "pinned-input verifier guarded function AST differs from release policy"
        )
    normalized_module = copy.deepcopy(module)
    recursive_identity_names = {
        "PINNED_VERIFIER_MODULE_AST_SHA256",
        "REQUIRED_ARTIFACT_BINDINGS_SHA256",
        "REQUIRED_ARTIFACT_SOURCE_DIGESTS_SHA256",
    }
    for statement in normalized_module.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else (statement.target,)
        )
        if any(
            isinstance(target, ast.Name)
            and target.id in recursive_identity_names
            for target in targets
        ):
            statement.value = ast.Constant(value="<normalized-release-identity>")
    module_ast_sha256 = hashlib.sha256(
        ast.dump(
            normalized_module,
            annotate_fields=True,
            include_attributes=False,
        ).encode("utf-8")
    ).hexdigest()
    if module_ast_sha256 != PINNED_VERIFIER_MODULE_AST_SHA256:
        raise PinnedInputError(
            "pinned-input verifier module AST differs from release policy"
        )


def _shell_binding_surface(source: str) -> str:
    """Remove shell comments without treating quoted ``#`` bytes as comments."""

    result: list[str] = []
    for line_number, line in enumerate(source.splitlines(keepends=True), start=1):
        if line_number == 1 and line.startswith("#!"):
            result.append(line)
            continue
        single_quoted = False
        double_quoted = False
        escaped = False
        comment_at: int | None = None
        for index, character in enumerate(line):
            if escaped:
                escaped = False
                continue
            if character == "\\" and not single_quoted:
                escaped = True
                continue
            if character == "'" and not double_quoted:
                single_quoted = not single_quoted
                continue
            if character == '"' and not single_quoted:
                double_quoted = not double_quoted
                continue
            if (
                character == "#"
                and not single_quoted
                and not double_quoted
                and (
                    index == 0
                    or line[index - 1].isspace()
                    or line[index - 1] in ";|&()<>{}"
                )
            ):
                comment_at = index
                break
        if comment_at is None:
            result.append(line)
            continue
        ending = "\n" if line.endswith("\n") else ""
        result.append(line[:comment_at] + ending)
    return "".join(result)


def _artifact_binding_surface(source: str, relative: str) -> str:
    if relative.endswith(".py"):
        surface, module = _python_binding_surface(source, relative)
        if relative in {
            "scripts/publication/orchestrator.py",
            "scripts/publication/ga_release_contract.py",
        }:
            _verify_orchestrator_release_guard(module, relative)
        elif relative in GA_RELEASE_CLI_FUNCTION_AST_SHA256:
            _verify_ga_release_cli_guard(module, relative)
        elif relative == ARTIFACT_SOURCE_DIGEST_SELF_EXCLUSION:
            _verify_pinned_verifier_structure(module)
        return surface
    if relative.endswith(".sh"):
        return _shell_binding_surface(source)
    return source


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


def _json_values_identical(actual: object, expected: object) -> bool:
    """Compare JSON values without accepting bool/int or int/float aliases."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _json_values_identical(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _json_values_identical(actual_item, expected_item)
            for actual_item, expected_item in zip(actual, expected)
        )
    return actual == expected


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


def _is_loaded_name(node: ast.AST, name: str) -> bool:
    return isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == name


def _is_str_call_for(node: ast.AST, name: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "str"
        and len(node.args) == 1
        and not node.keywords
        and _is_loaded_name(node.args[0], name)
    )


def _verify_android_admission_adb_uses(module: ast.Module) -> None:
    functions = {
        name: [
            node
            for node in module.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ]
        for name in ("_fixed_spec", "_validate_host_inputs")
    }
    if any(len(matches) != 1 for matches in functions.values()) or any(
        isinstance(matches[0], ast.AsyncFunctionDef) for matches in functions.values()
    ):
        raise PinnedInputError(
            "Android LAN peer admission must retain unique synchronous ADB boundary functions"
        )

    fixed_spec = functions["_fixed_spec"][0]
    assert isinstance(fixed_spec, ast.FunctionDef)
    prefix_assignments = [
        node
        for node in ast.walk(fixed_spec)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "prefix"
    ]
    prefix_bindings = [
        node
        for node in ast.walk(fixed_spec)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id == "prefix"
    ]
    if len(prefix_assignments) != 3 or len(prefix_bindings) != 3:
        raise PinnedInputError(
            "Android LAN peer fixed command constructor must retain three exact prefix branches"
        )

    branches: set[str] = set()
    for assignment in prefix_assignments:
        value = assignment.value
        if not isinstance(value, ast.Tuple) or not value.elts:
            raise PinnedInputError(
                "Android LAN peer fixed command prefixes must be exact tuples"
            )
        first = value.elts[0]
        if not (
            _is_str_call_for(first, "ADB")
            or _is_loaded_name(first, "adb_path")
        ):
            raise PinnedInputError(
                "Android LAN peer fixed command prefixes must use the pinned or private ADB client"
            )
        tail = value.elts[1:]
        if (
            len(tail) == 3
            and isinstance(tail[0], ast.Constant)
            and tail[0].value == "-L"
            and isinstance(tail[1], ast.JoinedStr)
            and isinstance(tail[2], ast.Constant)
            and tail[2].value == "-d"
        ):
            branches.add("inventory")
        elif (
            len(tail) == 4
            and isinstance(tail[0], ast.Constant)
            and tail[0].value == "-L"
            and isinstance(tail[1], ast.JoinedStr)
            and isinstance(tail[2], ast.Constant)
            and tail[2].value == "-t"
            and isinstance(tail[3], ast.Call)
            and isinstance(tail[3].func, ast.Name)
            and tail[3].func.id == "str"
            and len(tail[3].args) == 1
            and not tail[3].keywords
            and isinstance(tail[3].args[0], ast.Attribute)
            and tail[3].args[0].attr == "transport_id"
            and _is_loaded_name(tail[3].args[0].value, "selector")
        ):
            branches.add("transport")
        elif (
            len(tail) == 2
            and isinstance(tail[0], ast.Constant)
            and tail[0].value == "-L"
            and isinstance(tail[1], ast.JoinedStr)
        ):
            branches.add("default")
        else:
            raise PinnedInputError(
                "Android LAN peer fixed command prefix arguments differ from policy"
            )
    if branches != {"inventory", "transport", "default"}:
        raise PinnedInputError(
            "Android LAN peer fixed command prefix branches are duplicated or incomplete"
        )

    returns = [node for node in ast.walk(fixed_spec) if isinstance(node, ast.Return)]
    if (
        len(returns) != 1
        or not isinstance(returns[0].value, ast.Call)
        or not isinstance(returns[0].value.func, ast.Name)
        or returns[0].value.func.id != "CommandSpec"
    ):
        raise PinnedInputError(
            "Android LAN peer fixed command constructor must return one CommandSpec"
        )
    argv_keywords = [
        keyword
        for keyword in returns[0].value.keywords
        if keyword.arg == "argv"
    ]
    if len(argv_keywords) != 1:
        raise PinnedInputError(
            "Android LAN peer fixed command constructor must set one argv tuple"
        )
    argv = argv_keywords[0].value
    if not (
        isinstance(argv, ast.Tuple)
        and len(argv.elts) == 2
        and isinstance(argv.elts[0], ast.Starred)
        and _is_loaded_name(argv.elts[0].value, "prefix")
        and isinstance(argv.elts[1], ast.Starred)
        and _is_loaded_name(argv.elts[1].value, "arguments")
    ):
        raise PinnedInputError(
            "Android LAN peer CommandSpec argv must consume only the fixed prefix and arguments"
        )

    validate_inputs = functions["_validate_host_inputs"][0]
    assert isinstance(validate_inputs, ast.FunctionDef)
    adb_reads = []
    for node in ast.walk(validate_inputs):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_read_pinned_file"
            and node.args
            and _is_loaded_name(node.args[0], "ADB")
        ):
            continue
        expected_digests = [
            keyword.value
            for keyword in node.keywords
            if keyword.arg == "expected_sha256"
        ]
        if len(expected_digests) == 1 and _is_loaded_name(
            expected_digests[0], "ADB_SHA256"
        ):
            adb_reads.append(node)
    if len(adb_reads) != 1:
        raise PinnedInputError(
            "Android LAN peer host validation must hash the pinned ADB path with ADB_SHA256"
        )


def _extract_android_admission_constants(source: str) -> dict[str, str]:
    try:
        module = ast.parse(source)
    except SyntaxError as error:
        raise PinnedInputError(
            f"Android LAN peer admission source is malformed: {error}"
        ) from error

    wanted = {"ADB", "ADB_VERSION", "ADB_SHA256"}
    assignments: dict[str, ast.AST] = {}
    for node in module.body:
        if isinstance(node, ast.Assign):
            rebound = {
                target.id
                for target in node.targets
                if isinstance(target, ast.Name) and target.id in wanted
            }
            if rebound:
                raise PinnedInputError(
                    "Android LAN peer admission constants have a non-Final reassignment"
                )
            continue
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id in wanted:
                raise PinnedInputError(
                    "Android LAN peer admission constants have a non-Final reassignment"
                )
            continue
        if not isinstance(node, ast.AnnAssign) or not isinstance(
            node.target, ast.Name
        ):
            continue
        name = node.target.id
        if name not in wanted:
            continue
        if (
            name in assignments
            or node.value is None
            or not isinstance(node.annotation, ast.Name)
            or node.annotation.id != "Final"
        ):
            raise PinnedInputError(
                f"Android LAN peer admission constant {name} is duplicated, empty, or not Final"
            )
        assignments[name] = node.value
    if set(assignments) != wanted:
        missing = ", ".join(sorted(wanted - set(assignments)))
        raise PinnedInputError(
            f"Android LAN peer admission constants are incomplete: {missing}"
        )
    binding_counts = {name: 0 for name in wanted}
    for node in ast.walk(module):
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id in wanted
        ):
            binding_counts[node.id] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in wanted:
                binding_counts[node.name] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                if bound_name in wanted:
                    binding_counts[bound_name] += 1
        elif isinstance(node, ast.ExceptHandler) and node.name in wanted:
            binding_counts[node.name] += 1
        elif isinstance(node, ast.arg) and node.arg in wanted:
            binding_counts[node.arg] += 1
        elif (
            type(node).__name__ in {"MatchAs", "MatchStar"}
            and getattr(node, "name", None) in wanted
        ):
            binding_counts[node.name] += 1
    rebound = sorted(name for name, count in binding_counts.items() if count != 1)
    if rebound:
        raise PinnedInputError(
            "Android LAN peer admission constants must each have exactly one "
            f"source binding: {', '.join(rebound)}"
        )

    _verify_android_admission_adb_uses(module)

    adb_value = assignments["ADB"]
    if not (
        isinstance(adb_value, ast.Call)
        and isinstance(adb_value.func, ast.Name)
        and adb_value.func.id == "Path"
        and len(adb_value.args) == 1
        and not adb_value.keywords
        and isinstance(adb_value.args[0], ast.Constant)
        and type(adb_value.args[0].value) is str
    ):
        raise PinnedInputError(
            "Android LAN peer ADB constant must be a literal Path"
        )

    extracted = {"path": adb_value.args[0].value}
    for constant_name, field_name in (
        ("ADB_VERSION", "version"),
        ("ADB_SHA256", "sha256"),
    ):
        value = assignments[constant_name]
        if not (
            isinstance(value, ast.Constant) and type(value.value) is str
        ):
            raise PinnedInputError(
                f"Android LAN peer {constant_name} must be a string literal"
            )
        extracted[field_name] = value.value
    return extracted


def _verify_runtime_tools(manifest: dict, repository: Path) -> None:
    expected = {
        "adb": {
            "schema": "cfw-runtime-tool-pin-v1",
            "path": _ADB_RUNTIME_TOOL_PATH,
            "version": _ADB_RUNTIME_TOOL_VERSION,
            "sha256": _ADB_RUNTIME_TOOL_SHA256,
            "verificationPhase": "android-lan-peer-admission",
            "sourceBinding": {
                "path": _ANDROID_LAN_PEER_SOURCE_PATH,
                "sha256": _ANDROID_LAN_PEER_SOURCE_SHA256,
                "size": _ANDROID_LAN_PEER_SOURCE_SIZE,
                "mode": "0644",
                "pathConstant": "ADB",
                "versionConstant": "ADB_VERSION",
                "sha256Constant": "ADB_SHA256",
            },
        }
    }
    runtime_tools = manifest.get("runtimeTools")
    if not _json_values_identical(runtime_tools, expected):
        raise PinnedInputError(
            "runtime-tool pin contract is missing, malformed, or differs from policy"
        )

    source_bytes = read_repository_regular_file(
        repository,
        _ANDROID_LAN_PEER_SOURCE_PATH,
        "Android LAN peer admission source",
        maximum_size=_ANDROID_LAN_PEER_SOURCE_SIZE,
        expected_uid=os.geteuid(),
        expected_mode=0o644,
        expected_size=_ANDROID_LAN_PEER_SOURCE_SIZE,
        expected_sha256=_ANDROID_LAN_PEER_SOURCE_SHA256,
    )
    try:
        source = source_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PinnedInputError(
            "Android LAN peer admission source is not canonical UTF-8"
        ) from error
    observed = _extract_android_admission_constants(source)
    pinned = expected["adb"]
    if observed != {
        "path": pinned["path"],
        "version": pinned["version"],
        "sha256": pinned["sha256"],
    }:
        raise PinnedInputError(
            "Android LAN peer admission ADB constants differ from the runtime-tool pin"
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


def _packet_lan_peer_script_contract(
    path: str,
    sha256: str,
    size: int,
    fragments: tuple[str, ...],
) -> dict[str, object]:
    return {
        "path": path,
        "sha256": sha256,
        "size": size,
        "mode": "0755",
        "requiredFragments": list(fragments),
    }


def _verify_packet_lan_peer_script(
    repository: Path,
    contract: dict[str, object],
    description: str,
) -> None:
    relative = contract["path"]
    assert isinstance(relative, str)
    size = contract["size"]
    digest = contract["sha256"]
    mode = contract["mode"]
    if (
        type(size) is not int
        or size < 1
        or not isinstance(digest, str)
        or not isinstance(mode, str)
        or not re.fullmatch(r"0[0-7]{3}", mode)
    ):
        raise PinnedInputError(f"{description} has malformed file identity")
    _require_sha256(digest, f"{description} digest")
    body = read_repository_regular_file(
        repository,
        relative,
        description,
        maximum_size=size,
        expected_mode=int(mode, 8),
        expected_size=size,
        expected_sha256=digest,
    )
    try:
        script = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PinnedInputError(f"{description} is not strict UTF-8") from error
    for fragment in contract["requiredFragments"]:
        assert isinstance(fragment, str)
        if fragment not in script:
            raise PinnedInputError(
                f"{description} lacks required pinned fragment {fragment!r}"
            )


def _verify_packet_lan_peer_source_contract(
    manifest: dict, env: dict[str, str], repository: Path
) -> dict[str, object]:
    source_files = [
        {"path": path, "sha256": sha256, "size": size, "mode": mode}
        for path, sha256, size, mode in _PACKET_LAN_PEER_SOURCE_FILES
    ]
    expected = {
        "schema": "cfw-packet-lan-peer-build-input-v1",
        "goToolchain": {
            "versionKey": "GO_VERSION",
            "version": _require_env(env, "GO_VERSION"),
            "goos": "linux",
            "goarch": "arm64",
            "cgoEnabled": "0",
        },
        "source": {
            "root": "tools/packet-lan-peer",
            "treeAlgorithm": "sha256-tree-v2",
            "treeSha256": _PACKET_LAN_PEER_SOURCE_TREE_SHA256,
            "rootMode": "0755",
            "files": source_files,
        },
        "artifact": {
            "path": "target/packet-lan-peer-linux-arm64",
            "sha256": _PACKET_LAN_PEER_ARTIFACT_SHA256,
            "size": _PACKET_LAN_PEER_ARTIFACT_SIZE,
            "fileType": "regular",
            "linkCount": 1,
            "hostOwner": "effective-uid",
            "hostMode": "0555",
        },
        "protocol": {
            "network": "tcp4",
            "listenAddress": ":44333",
            "port": 44333,
            "maximumConnections": 8,
            "maximumRequestBytes": 64,
            "readDeadlineSeconds": 5,
            "responseBytes": 0,
        },
        "androidDeployment": {
            "directory": "/data/local/tmp/cfw-release-evidence-v040",
            "directoryMode": "0700",
            "binaryPath": (
                "/data/local/tmp/cfw-release-evidence-v040/"
                "packet-lan-peer-linux-arm64"
            ),
            "binaryMode": "0500",
            "uid": 2000,
            "gid": 2000,
        },
        "buildScript": _packet_lan_peer_script_contract(
            "scripts/build_packet_lan_peer.sh",
            _PACKET_LAN_PEER_BUILD_SCRIPT_SHA256,
            4933,
            _PACKET_LAN_PEER_BUILD_FRAGMENTS,
        ),
        "verifyScript": _packet_lan_peer_script_contract(
            "scripts/verify_packet_lan_peer.sh",
            _PACKET_LAN_PEER_VERIFY_SCRIPT_SHA256,
            7357,
            _PACKET_LAN_PEER_VERIFY_FRAGMENTS,
        ),
    }
    spec = manifest.get("packetLanPeer")
    if not _json_values_identical(spec, expected):
        raise PinnedInputError(
            "packet LAN peer build-input contract is missing, malformed, or differs from policy"
        )

    source = expected["source"]
    assert isinstance(source, dict)
    source_root_relative = source["root"]
    assert isinstance(source_root_relative, str)
    source_root = _safe_repository_path(
        repository, source_root_relative, "packet LAN peer source root"
    )
    try:
        source_manifest = build_manifest(source_root, algorithm="sha256-tree-v2")
    except (OSError, ValueError) as error:
        raise PinnedInputError(
            f"packet LAN peer source tree cannot be securely hashed: {error}"
        ) from error
    expected_tree = {
        "algorithm": "sha256-tree-v2",
        "root": "packet-lan-peer",
        "rootMode": "0755",
        "sha256": _PACKET_LAN_PEER_SOURCE_TREE_SHA256,
        "entries": [
            {
                "path": entry["path"],
                "type": "file",
                "size": entry["size"],
                "sha256": entry["sha256"],
                "mode": entry["mode"],
            }
            for entry in source_files
        ],
    }
    if not _json_values_identical(source_manifest, expected_tree):
        raise PinnedInputError(
            "packet LAN peer source tree digest, file set, size, type, or mode drifted"
        )

    _verify_packet_lan_peer_script(
        repository, expected["buildScript"], "packet LAN peer build script"
    )
    _verify_packet_lan_peer_script(
        repository, expected["verifyScript"], "packet LAN peer verification script"
    )

    artifact = expected["artifact"]
    assert isinstance(artifact, dict)
    return artifact


def _verify_packet_lan_peer_artifact(
    repository: Path, artifact: dict[str, object]
) -> None:
    """Verify the generated packet-peer artifact without weakening its source pin.

    The static source contract deliberately remains usable in a clean checkout
    before this artifact exists. The default :func:`verify` entrypoint calls
    this function as a second layer and therefore retains the historical,
    complete source-plus-artifact check.
    """
    artifact_relative = artifact["path"]
    assert isinstance(artifact_relative, str)
    read_repository_regular_file(
        repository,
        artifact_relative,
        "packet LAN peer artifact",
        maximum_size=_PACKET_LAN_PEER_ARTIFACT_SIZE,
        expected_uid=os.geteuid(),
        expected_mode=0o555,
        expected_size=_PACKET_LAN_PEER_ARTIFACT_SIZE,
        expected_sha256=_PACKET_LAN_PEER_ARTIFACT_SHA256,
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
        ("lockPatchSha256Key", "lockPatchSha256", "Tauri CLI lock patch"),
        (
            "patchedCargoLockSha256Key",
            "patchedCargoLockSha256",
            "Tauri CLI patched Cargo.lock",
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
        raise PinnedInputError("Tauri CLI spin replacement has no version binding")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", spin_version):
        raise PinnedInputError("Tauri CLI spin replacement version is malformed")
    if _require_env(env, spin_version_key) != spin_version:
        raise PinnedInputError("Tauri CLI spin replacement version differs from the manifest")

    patch_path_key = spec.get("lockPatchPathKey")
    if not isinstance(patch_path_key, str):
        raise PinnedInputError("Tauri CLI lock patch has no path binding")
    patch_relative = _require_env(env, patch_path_key)
    computed_patch_sha = hashlib.sha256(
        _read_bytes(repository, patch_relative, "Tauri CLI lock patch")
    ).hexdigest()
    if computed_patch_sha != spec["lockPatchSha256"]:
        raise PinnedInputError(
            f"Tauri CLI lock patch digest {computed_patch_sha} differs from the pinned "
            f"{spec['lockPatchSha256']}"
        )

    installer_relative = spec.get("installerPath")
    installer_expected_sha256 = spec.get("installerSha256")
    fragments = spec.get("requiredInstallerFragments")
    if (
        installer_relative != TAURI_CLI_INSTALLER_RELATIVE_PATH
        or not isinstance(installer_expected_sha256, str)
        or not isinstance(fragments, list)
        or not fragments
    ):
        raise PinnedInputError("Tauri CLI installer binding is incomplete")
    _require_sha256(
        installer_expected_sha256,
        "manifest digest for Tauri CLI installer",
    )
    if installer_expected_sha256 != REQUIRED_TAURI_CLI_INSTALLER_SHA256:
        raise PinnedInputError(
            "Tauri CLI installer digest differs from the fixed release policy"
        )
    installer_body = _read_bytes(
        repository,
        installer_relative,
        "Tauri CLI installer",
    )
    computed_installer_sha256 = hashlib.sha256(installer_body).hexdigest()
    try:
        installer = installer_body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PinnedInputError("Tauri CLI installer is not strict UTF-8") from error
    lock_patch_command_prefix = (
        'GIT_CEILING_DIRECTORIES="$staging" ' + "\\" + "\n  "
    )
    lock_patch_check_command = (
        lock_patch_command_prefix
        + '/usr/bin/git -C "$source_root" apply --unidiff-zero --check "$lock_patch"'
    )
    lock_patch_apply_command = (
        lock_patch_command_prefix
        + '/usr/bin/git -C "$source_root" apply --unidiff-zero "$lock_patch"'
    )
    lock_patch_reverse_check_command = (
        lock_patch_command_prefix
        + '/usr/bin/git -C "$source_root" apply --unidiff-zero --reverse --check "$lock_patch"'
    )
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
        lock_patch_check_command: 1,
        lock_patch_apply_command: 1,
        lock_patch_reverse_check_command: 1,
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
        "79ff796bee6ec01ab2530da6112847aad1a2bf9df786103dbb6e3d2c780fd992",
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

    expected_lock_patch_operations = {
        normalized_shell_operation(lock_patch_check_command),
        normalized_shell_operation(lock_patch_apply_command),
        normalized_shell_operation(lock_patch_reverse_check_command),
    }
    observed_lock_patch_operations = [
        normalized_shell_operation(line)
        for line in installer.replace("\\\n", " ").splitlines()
        if not line.lstrip().startswith("#") and re.search(r"\bapply\b", line)
    ]
    if (
        len(observed_lock_patch_operations) != len(expected_lock_patch_operations)
        or set(observed_lock_patch_operations) != expected_lock_patch_operations
    ):
        raise PinnedInputError(
            "Tauri CLI installer contains an unexpected lock patch apply operation"
        )

    expected_workspace_references = {
        normalized_shell_operation(value)
        for value in (
            'for boundary_file in "$cargo_manifest" "$cargo_lock" '
            '"$staging_workspace_manifest" "$staging_workspace_lock"; do',
            '[[ "$(stat -f \'%Lp\' "$staging_workspace_manifest")" == "600" && '
            '"$(stat -f \'%Lp\' "$staging_workspace_lock")" == "600" ]] ||',
            'printf \'%s  %s\\n\' "$staging_workspace_manifest_sha256" '
            '"$staging_workspace_manifest" |',
            'printf \'%s  %s\\n\' "$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256" '
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
        "c2004832a51b0ea20561ee649c58fa5d2be3c5594e47d58bfd02ee8a48bd6e2b"
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
        'printf \'%s  %s\\n\' "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$cargo_lock"',
        preparation_before,
    )
    lock_patch_check = locate(lock_patch_check_command, upstream_lock_digest)
    lock_patch_apply = locate(lock_patch_apply_command, lock_patch_check)
    patched_lock_digest = locate(
        'printf \'%s  %s\\n\' "$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256" "$cargo_lock"',
        lock_patch_apply,
    )
    lock_patch_reverse_check = locate(
        lock_patch_reverse_check_command, patched_lock_digest
    )
    spin_semantic_check = locate(
        "patched Tauri CLI lock has unexpected spin records",
        lock_patch_reverse_check,
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
    if computed_installer_sha256 != installer_expected_sha256:
        raise PinnedInputError(
            "Tauri CLI installer source digest differs from the pinned release policy"
        )


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
    if not isinstance(patches, list) or len(patches) != 4:
        raise PinnedInputError("pinned-input manifest must pin exactly four patches")
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


def _verify_build_scripts(
    manifest: dict, repository: Path, environment_pins: dict[str, str]
) -> None:
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

    artifact_bindings = manifest.get("artifactBindings")
    if not isinstance(artifact_bindings, dict) or not artifact_bindings:
        raise PinnedInputError("pinned-input manifest has no artifact bindings")
    for relative, bindings in artifact_bindings.items():
        if (
            not isinstance(relative, str)
            or not relative
            or not isinstance(bindings, list)
            or not bindings
            or any(not isinstance(binding, str) or not binding for binding in bindings)
            or len(bindings) != len(set(bindings))
        ):
            raise PinnedInputError(
                "pinned-input manifest has a malformed artifact binding"
            )
    artifact_binding_identity = hashlib.sha256(
        json.dumps(
            artifact_bindings,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if artifact_binding_identity != REQUIRED_ARTIFACT_BINDINGS_SHA256:
        raise PinnedInputError(
            "pinned-input manifest artifact bindings differ from release policy"
        )
    artifact_source_digests = manifest.get("artifactSourceSha256")
    expected_source_paths = set(artifact_bindings) - {
        ARTIFACT_SOURCE_DIGEST_SELF_EXCLUSION
    }
    if (
        not isinstance(artifact_source_digests, dict)
        or set(artifact_source_digests) != expected_source_paths
        or any(
            type(relative) is not str
            or type(digest) is not str
            or not _SHA256_RE.fullmatch(digest)
            for relative, digest in artifact_source_digests.items()
        )
    ):
        raise PinnedInputError(
            "artifact source digest map differs from the complete release policy"
        )
    artifact_source_identity = hashlib.sha256(
        json.dumps(
            artifact_source_digests,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if artifact_source_identity != REQUIRED_ARTIFACT_SOURCE_DIGESTS_SHA256:
        raise PinnedInputError(
            "artifact source digest map identity differs from release policy"
        )
    for relative, bindings in artifact_bindings.items():
        text = _read_text(
            repository,
            relative,
            f"build script {relative}",
        )
        if relative != ARTIFACT_SOURCE_DIGEST_SELF_EXCLUSION and (
            hashlib.sha256(text.encode("utf-8")).hexdigest()
            != artifact_source_digests[relative]
        ):
            raise PinnedInputError(
                f"artifact source digest differs from release policy: {relative}"
            )
        if relative == ARTIFACT_SOURCE_DIGEST_SELF_EXCLUSION:
            binding_surface, verifier_module = _python_binding_surface(text, relative)
            _verify_pinned_verifier_structure(verifier_module)
        else:
            binding_surface = _artifact_binding_surface(text, relative)
        for binding in bindings:
            if binding not in binding_surface:
                raise PinnedInputError(
                    f"build script {relative} is missing executable artifact-hash binding "
                    f"{binding!r}"
                )

    workflow_relative = ".github/workflows/ci.yml"
    if workflow_relative in artifact_bindings:
        workflow = _read_text(
            repository,
            workflow_relative,
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
                "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405",
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


def _verify(
    repository: Path, *, require_packet_lan_peer_artifact: bool
) -> None:
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
    _verify_runtime_tools(manifest, repository)
    _verify_packet_evidence_endpoint(manifest, env, repository)
    packet_lan_peer_artifact = _verify_packet_lan_peer_source_contract(
        manifest, env, repository
    )
    if require_packet_lan_peer_artifact:
        _verify_packet_lan_peer_artifact(repository, packet_lan_peer_artifact)
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
    _verify_build_scripts(manifest, repository, env)


def verify_source_contract(repository: Path) -> None:
    """Verify static pinned inputs without requiring generated packet output."""
    _verify(repository, require_packet_lan_peer_artifact=False)


def verify(repository: Path) -> None:
    """Verify all pinned inputs, including the generated packet-peer artifact."""
    _verify(repository, require_packet_lan_peer_artifact=True)


def main() -> int:
    repository = Path(__file__).resolve().parent.parent
    try:
        verify(repository)
    except PinnedInputError as error:
        print(f"error: pinned build inputs failed: {error}", file=sys.stderr)
        return 1
    print(
        "pinned build inputs verified: Python/Rust/cargo-audit/cargo-deny/Node/Go/"
        "gomobile/govulncheck/"
        "Tauri CLI/sing-box versions, checksum-bound Tauri CLI local-source installation, "
        "packet evidence endpoint source/service/sudoers/identity/known-hosts and "
        "reproducible Linux artifact binding, Android packet LAN peer source/tree/"
        "script/protocol/deployment/held-artifact binding, ADB runtime-tool source "
        "binding, physical-collector module graph, "
        "XcodeGen patch/source binding, sing-box and gomobile commits, four libbox patch "
        "digests, combined diff, Go module inputs and module-cache closure contract, "
        "libbox build tags required by the engine start path, native lock binding, "
        "offline artifact-hash build-script references, and the exact artifact-source "
        "release-freeze map"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
