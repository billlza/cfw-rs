from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from scripts import verify_pinned_build_inputs as pinned_verifier
from scripts.verify_pinned_build_inputs import (
    MANIFEST_RELATIVE_PATH,
    MAX_NATIVE_LOCK_BYTES,
    MAX_PINNED_MANIFEST_BYTES,
    PinnedInputError,
    REQUIRED_REJECTED_PATCH_DIGESTS,
    verify,
    verify_source_contract,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPED_PINNED_MANIFEST = json.loads(
    (REPO_ROOT / MANIFEST_RELATIVE_PATH).read_text(encoding="utf-8")
)
SHIPPED_ARTIFACT_BINDINGS = SHIPPED_PINNED_MANIFEST["artifactBindings"]
SHIPPED_ARTIFACT_SOURCE_SHA256 = SHIPPED_PINNED_MANIFEST[
    "artifactSourceSha256"
]
PACKET_ENDPOINT_BINARY_SHA = (
    "c63c202b22823197ad12cb2d5f484c95be25904260ed266083dcca6fc766db6c"
)
PACKET_ENDPOINT_PATHS = (
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
)
PACKET_ENDPOINT_BUILD_FRAGMENTS = [
    "GOTOOLCHAIN=local",
    "CGO_ENABLED=0",
    "GOOS=linux",
    "GOARCH=amd64",
    "target/toolchains/go-1.26.6/bin/go",
    "-C tools/packet-evidence-endpoint",
    "-trimpath",
    "-ldflags='-s -w -buildid='",
    "-o ../../target/packet-evidence-endpoint-linux-amd64",
    PACKET_ENDPOINT_BINARY_SHA,
]
PACKET_LAN_PEER_ARTIFACT_SHA = (
    "268699e59caff2ea3ddf73e2a22b556364724a6bae985d012f1df7e2b089085c"
)
ADB_RUNTIME_TOOL_PATH = "/Users/bill/Library/Android/sdk/platform-tools/adb"
ADB_RUNTIME_TOOL_VERSION = "37.0.0-14910828"
ADB_RUNTIME_TOOL_SHA256 = (
    "5759ea07285e5a5b66d84f489c118a3fa3998e69cd37725e5a3dc7cbe0597278"
)
ANDROID_LAN_PEER_SOURCE_PATH = "scripts/physical_capture/android_lan_peer.py"
SYNTHETIC_PACKET_LAN_PEER_ARTIFACT = b"synthetic packet LAN peer binary\n"
SYNTHETIC_ANDROID_ADMISSION_SOURCE = (
    REPO_ROOT / ANDROID_LAN_PEER_SOURCE_PATH
).read_bytes()
PACKET_LAN_PEER_SOURCE_TREE_SHA = (
    "8437dce5e85780a49e882dd1594b188ce0f5188c44b7a020fe7a42d7efaa08a4"
)
PACKET_LAN_PEER_SOURCE_ENTRIES = (
    (
        "README.md",
        "b84a4528927d8b7ceb707203a35d8052579717fb19a9b380a4828147b38b3547",
        2035,
    ),
    (
        "go.mod",
        "af5ff7973354844d111edb9d303d6543d8aa6dc0afc6ecf439225acc15e1d1fd",
        70,
    ),
    (
        "main.go",
        "fb6dd50acaa306f9664ef1e89929041459bf68b3ec13feee8166dcc8bf588b4b",
        7757,
    ),
    (
        "main_test.go",
        "ef4b6eff3f31f4d17345bf0da67726f1c2f6b776c15ab2691bbb3710487ca87e",
        10813,
    ),
)
PACKET_LAN_PEER_BUILD_FRAGMENTS = [
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
]
PACKET_LAN_PEER_VERIFY_FRAGMENTS = [
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
]
PHYSICAL_COLLECTOR_PATHS = (
    "tools/physical-collector/go.mod",
    "tools/physical-collector/go.sum",
)
PHYSICAL_COLLECTOR_MODULE_FRAGMENTS = [
    "google.golang.org/grpc v1.82.1",
    "golang.org/x/text v0.39.0",
]


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


# Synthetic, self-consistent patch bodies. Their real SHA-256 digests drive the
# generated manifest, env, and lock so the verifier logic can be exercised without
# needing SHA-256 preimages of the shipped design pins.
PATCH_BODIES = {
    "security": b"synthetic security dependencies patch body\n",
    "raw": b"synthetic raw packet tun patch body\n",
    "dns": b"synthetic dns failover patch body\n",
    "endpoint": b"synthetic endpoint conflict patch body\n",
}
TAURI_LOCK_PATCH_BODY = b"synthetic tauri-cli spin lock patch body\n"
TAURI_CACHE_CONTRACT_BODY = b"synthetic Tauri Cargo cache contract\n"
LIBBOX_MODULE_CACHE_CONTRACT_BODY = b"""\
LIBBOX_MODULE_BUILD_PACKAGES=("./experimental/libbox")
LIBBOX_GOMOBILE_BIND_PACKAGES=("github.com/sagernet/gomobile/bind")
LIBBOX_RACE_TEST_PACKAGES=("./dns")
LIBBOX_TEST_PACKAGES=(".")
LIBBOX_COMPILE_TEST_PACKAGES=("./route")
LIBBOX_VET_PACKAGES=(".")
"""
XCODEGEN_PATCH_BODY = b"synthetic XcodeGen installed-resource patch body\n"

SECURITY_SHA = _sha(PATCH_BODIES["security"])
RAW_SHA = _sha(PATCH_BODIES["raw"])
DNS_SHA = _sha(PATCH_BODIES["dns"])
ENDPOINT_SHA = _sha(PATCH_BODIES["endpoint"])
COMBINED_SHA = _sha(b"synthetic combined diff body\n")
REJECTED_PATCH_DIGESTS = sorted(REQUIRED_REJECTED_PATCH_DIGESTS)
TAURI_CRATE_SHA = _sha(b"synthetic official tauri-cli crate archive")
TAURI_UPSTREAM_LOCK_SHA = _sha(b"synthetic upstream tauri-cli Cargo.lock")
TAURI_LOCK_PATCH_SHA = _sha(TAURI_LOCK_PATCH_BODY)
TAURI_PATCHED_LOCK_SHA = _sha(b"synthetic patched tauri-cli Cargo.lock")
TAURI_SPIN_SHA = _sha(b"synthetic spin crate")
TAURI_CACHE_CONTRACT_SHA = _sha(TAURI_CACHE_CONTRACT_BODY)
LIBBOX_MODULE_CACHE_CONTRACT_SHA = _sha(LIBBOX_MODULE_CACHE_CONTRACT_BODY)
XCODEGEN_PATCH_SHA = _sha(XCODEGEN_PATCH_BODY)
XCODEGEN_PATCHED_SETTINGS_SHA = _sha(b"synthetic patched SettingsBuilder.swift")
COMMIT = "3708fa18766cda1f11b77f6ed9c7bd61688f17df"
ANDROID_REFERENCE_COMMIT = "124a7c13038fcc389e3efbe61504fe6ab14724d9"
APPLE_REFERENCE_COMMIT = "afb1ac6fd63aeb4660f39b21bde4a3f52cdee9fa"
GOMOBILE_COMMIT = "9f03b8f25789099c5c8abef4a02085da783ba923"
TAURI_PATCH_PATH = "scripts/tauri-cli-spin.patch"
TAURI_CACHE_CONTRACT_PATH = "scripts/tauri_cargo_cache_contract.py"
LIBBOX_MODULE_CACHE_CONTRACT_PATH = "scripts/libbox_module_cache_contract.sh"
XCODEGEN_PATCH_PATH = "scripts/xcodegen-installed-resources.patch"

PATCH_PATHS = {
    "security": "native/macos/patches/security.patch",
    "raw": "native/macos/patches/raw-packet.patch",
    "dns": "native/macos/patches/dns-failover.patch",
    "endpoint": "native/macos/patches/endpoint-conflict.patch",
}

BUILD_LIBBOX = """\
#!/usr/bin/env bash
set -euo pipefail
echo "$GO_VERSION $GOMOBILE_VERSION $GOMOBILE_COMMIT $GOMOBILE_MODULE_SUM $SING_BOX_VERSION $SING_BOX_COMMIT $LIBBOX_BUILD_TAGS"
python3 hash_artifact.py "$out" \\
  --metadata "sourceCommit=$SING_BOX_COMMIT" \\
  --metadata "gomobileCommit=$GOMOBILE_COMMIT" \\
  --metadata "gomobileModuleSum=$GOMOBILE_MODULE_SUM" \\
  --metadata "securityPatchSha256=$SING_BOX_SECURITY_PATCH_SHA256" \\
  --metadata "rawPacketPatchSha256=$SING_BOX_RAW_PACKET_PATCH_SHA256" \\
  --metadata "dnsFailoverPatchSha256=$SING_BOX_DNS_FAILOVER_PATCH_SHA256" \\
  --metadata "endpointConflictPatchSha256=$SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256" \\
  --metadata "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256"
"""
LIBBOX_ARTIFACT_BINDINGS = [
    "sourceTag=$SING_BOX_VERSION",
    "sourceCommit=$SING_BOX_COMMIT",
    "goVersion=$GO_VERSION",
    "goToolchainTreeSha256=$go_toolchain_tree_sha256",
    "goToolsTreeSha256=$go_tools_tree_sha256",
    "goModuleCacheTreeSha256=$go_module_cache_tree_sha256",
    "gomobileVersion=$GOMOBILE_VERSION",
    "gomobileCommit=$GOMOBILE_COMMIT",
    "gomobileModuleSum=$GOMOBILE_MODULE_SUM",
    "headerNormalization=angleBracketFrameworkImports-v1",
    "platform=$LIBBOX_APPLE_PLATFORM",
    "buildTags=$LIBBOX_BUILD_TAGS",
    "nonMacOsTags=$LIBBOX_NON_MACOS_TAGS",
    "upstreamGoModSha256=$SING_BOX_UPSTREAM_GO_MOD_SHA256",
    "upstreamGoSumSha256=$SING_BOX_UPSTREAM_GO_SUM_SHA256",
    "securityPatchSha256=$SING_BOX_SECURITY_PATCH_SHA256",
    "rawPacketPatchSha256=$SING_BOX_RAW_PACKET_PATCH_SHA256",
    "dnsFailoverPatchSha256=$SING_BOX_DNS_FAILOVER_PATCH_SHA256",
    "endpointConflictPatchSha256=$SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
    "patchedDiffSha256=$SING_BOX_PATCHED_DIFF_SHA256",
    "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256",
    "patchedGoModSha256=$SING_BOX_PATCHED_GO_MOD_SHA256",
    "patchedGoSumSha256=$SING_BOX_PATCHED_GO_SUM_SHA256",
]
LIBBOX_CONTRACT = "#!/usr/bin/env bash\n" + "\n".join(LIBBOX_ARTIFACT_BINDINGS) + "\n"
BUILD_NATIVE = (
    '#!/usr/bin/env bash\necho "--metadata singBoxCommit=$SING_BOX_COMMIT"\n'
    "libbox_verify_xcframework_artifact\n"
)
BUILD_TAGS = (
    "with_quic,with_utls,with_clash_api,badlinkname,"
    "tfogo_checklinkname0,grpcnotrace"
)
CONTROLLER_RELATIVE_PATH = "crates/cfw-singbox-config/src/controller.rs"
CONTROLLER_TRIGGER = '"clash_api": {'
CONTROLLER_SOURCE = (
    "fn experimental_value(&self) -> Value {\n"
    "    json!({\n"
    f"        {CONTROLLER_TRIGGER}\n"
    '            "external_controller": self.external_controller(),\n'
    "    })\n"
    "}\n"
)
PROJECTION_RELATIVE_PATH = "crates/cfw-singbox-config/src/projection.rs"
PROJECTION_TRIGGER = (
    'root.insert("experimental".into(), clash_api.experimental_value());'
)
PROJECTION_SOURCE = f"fn project() {{\n    {PROJECTION_TRIGGER}\n}}\n"
BUILD_UNSIGNED = (
    "#!/usr/bin/env bash\n"
    "libbox_verify_xcframework_artifact\n"
)
TAURI_INSTALLER = """\
#!/usr/bin/env bash
echo "https://static.crates.io/crates/tauri-cli/tauri-cli-$TAURI_CLI_VERSION.crate"
echo "$TAURI_CLI_CRATE_SHA256"
echo "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256"
echo "$TAURI_CLI_LOCK_PATCH_SHA256"
echo "$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256"
echo "$TAURI_CLI_SPIN_VERSION"
echo "$TAURI_CLI_SPIN_CRATE_SHA256"
echo "$TAURI_CARGO_CACHE_CONTRACT_SHA256"
readonly cargo_cache_contract="$repo_root/scripts/tauri_cargo_cache_contract.py"
verify_cargo_preparation_cache() {
  local root="$1"
  cfw_run_release_python_script "$repo_root" "$cargo_cache_contract" \
    validate-preparation "$root"
}
normalize_cargo_offline_cache() {
  local root="$1"
  cfw_run_release_python_script "$repo_root" "$cargo_cache_contract" \
    normalize-offline "$root"
}
git apply --unidiff-zero "$TAURI_CLI_LOCK_PATCH_PATH"
cargo_bin="$CFW_RELEASE_CARGO_EXECUTABLE"
rustc_bin="$CFW_RELEASE_RUSTC_EXECUTABLE"
verify_cargo_preparation_cache "$prepared_cargo_home"
/usr/bin/env -i CARGO_HOME="$prepared_cargo_home" \
  CARGO_HTTP_LOW_SPEED_LIMIT=1 CARGO_HTTP_MULTIPLEXING=true \
  CARGO_HTTP_TIMEOUT=600 CARGO_NET_RETRY=3 \
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse CARGO_TERM_COLOR=never RUSTC="$rustc_bin" \
  "$cargo_bin" fetch --manifest-path "$cargo_manifest" --locked \
  --target aarch64-apple-darwin
reject_cargo_warnings "$fetch_log" "Tauri CLI dependency preparation"
verify_cargo_preparation_cache "$prepared_cargo_home"
/usr/bin/ditto --noqtn "$prepared_cargo_home" "$offline_cargo_home"
normalize_cargo_offline_cache "$offline_cargo_home"
cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/hash_artifact.py" \
  "$offline_cargo_home"
offline_cache_sha256_before="$(cfw_verify_release_toolchain_manifest)"
/usr/bin/env -i PATH="$cargo_install_root/bin:$(dirname "$cargo_bin"):/usr/bin:/bin:/usr/sbin:/sbin" \
  CARGO_HOME="$offline_cargo_home" CARGO_TARGET_DIR="$cargo_target" \
  CARGO_NET_OFFLINE=true CARGO_NET_RETRY=0 \
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse RUSTC="$rustc_bin" \
  "$cargo_bin" install --path "$source_root" --offline --locked \
  --target aarch64-apple-darwin
reject_cargo_warnings "$install_log" "tauri-cli installation"
normalize_cargo_offline_cache "$offline_cargo_home"
offline_cache_sha256_after="$(cfw_verify_release_toolchain_manifest)"
[[ "$offline_cache_sha256_after" == "$offline_cache_sha256_before" ]]
echo "tauri-cli-$TAURI_CLI_VERSION"
readonly payload="$staging/payload/tauri-cli-$TAURI_CLI_VERSION"
/bin/mv "$source_root" "$payload/source"
/usr/bin/lipo -archs "$payload/bin/cargo-tauri"
echo "--algorithm sha256-tree-v2"
echo "artifactKind=pinned-tauri-cli-v2"
echo "cacheContractSha256=$TAURI_CARGO_CACHE_CONTRACT_SHA256"
echo "cacheNormalization=cargo-runtime-metadata-v1"
echo "dependencyMode=isolated-fetch-offline-locked-v1"
echo "macosDeploymentTarget=$MACOS_DEPLOYMENT_TARGET"
echo "payloadLayout=bin-and-patched-source-v1"
echo "xcodeBuild=$XCODE_BUILD_VERSION"
echo "xcodeVersion=$XCODE_VERSION"
echo "cfw_verify_tauri_toolchain_tree"
"""
CI_WORKFLOW = """\
jobs:
  release:
    runs-on: macos-26
    timeout-minutes: 60
    steps:
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405
        id: validation-python
        with:
          python-version: "3.14.6"
          architecture: arm64
          update-environment: false
      - run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' bootstrap-policy-tools
      - run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' cargo-deny
      - run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' install-tauri-cli
"""
XCODEGEN_BOOTSTRAP = """\
#!/usr/bin/env bash
xcodegen_patch="$repo_root/$XCODEGEN_PATCH_PATH"
echo "$XCODEGEN_PATCH_SHA256"
echo "$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256"
GIT_CEILING_DIRECTORIES="$toolchain_root"
/usr/bin/git -C "$payload/source" apply --check "$xcodegen_patch"
/usr/bin/git -C "$payload/source" apply --reverse --check "$xcodegen_patch"
USER=cfw-release
LOGNAME=cfw-release
/usr/bin/strip -S "$build_root/release/xcodegen"
echo "patchSha256=$XCODEGEN_PATCH_SHA256"
echo "patchedSettingsBuilderSha256=$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256"
echo "XcodeGenResourceProbe.xcodeproj/project.pbxproj"
"""


class Fixture:
    """A self-consistent, mutable pinned-input repository fixture."""

    def __init__(self) -> None:
        self.env: dict[str, str] = {
            "PYTHON_VERSION": "3.14.6",
            "RUST_VERSION": "1.97.1",
            "RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256": (
                "472d78d9340576ca15b8f17f2eb4fe5fb709c0aae3a428e8c4dfd2cd65e5b6ae"
            ),
            "CARGO_AUDIT_VERSION": "0.22.2",
            "CARGO_DENY_VERSION": "0.20.2",
            "XCODEGEN_VERSION": "2.46.0",
            "XCODEGEN_COMMIT": "8445e778451c7e44237b90281bde622d764b0084",
            "XCODEGEN_SOURCE_SHA256": "a3270d0e5fce8f4dc2aa1801b0d932f6561cd24c0735e718d2455896b2359142",
            "XCODEGEN_PACKAGE_RESOLVED_SHA256": "2f0b0265e33ab55bbc6cab8ad209afa85821064a2cb6fe4a1df07b642f7cebcd",
            "XCODEGEN_PATCH_PATH": XCODEGEN_PATCH_PATH,
            "XCODEGEN_PATCH_SHA256": XCODEGEN_PATCH_SHA,
            "XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256": XCODEGEN_PATCHED_SETTINGS_SHA,
            "NODE_VERSION": "24.18.0",
            "GO_VERSION": "1.26.6",
            "TAURI_CLI_VERSION": "2.11.4",
            "TAURI_CLI_CRATE_SHA256": TAURI_CRATE_SHA,
            "TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256": TAURI_UPSTREAM_LOCK_SHA,
            "TAURI_CLI_LOCK_PATCH_PATH": TAURI_PATCH_PATH,
            "TAURI_CLI_LOCK_PATCH_SHA256": TAURI_LOCK_PATCH_SHA,
            "TAURI_CLI_PATCHED_CARGO_LOCK_SHA256": TAURI_PATCHED_LOCK_SHA,
            "TAURI_CLI_SPIN_VERSION": "0.9.9",
            "TAURI_CLI_SPIN_CRATE_SHA256": TAURI_SPIN_SHA,
            "TAURI_CARGO_CACHE_CONTRACT_SHA256": TAURI_CACHE_CONTRACT_SHA,
            "GOMOBILE_VERSION": "v0.1.13",
            "GOMOBILE_COMMIT": GOMOBILE_COMMIT,
            "GOMOBILE_MODULE_SUM": "h1:foTOGKJetah9VwaJl1XJx5TswIAVg8NfYmHOhrOc95I=",
            "GOVULNCHECK_VERSION": "v1.6.0",
            "GOVULNCHECK_MODULE_SUM": "h1:FeMO9Rm/HwyduOztbvKcOw+zvDEPr4I4aQNSfevFcKY=",
            "SING_BOX_VERSION": "v1.13.15",
            "SING_BOX_COMMIT": COMMIT,
            "SING_BOX_ANDROID_REFERENCE_COMMIT": ANDROID_REFERENCE_COMMIT,
            "SING_BOX_APPLE_REFERENCE_COMMIT": APPLE_REFERENCE_COMMIT,
            "SING_BOX_UPSTREAM_GO_MOD_SHA256": _sha(b"upstream go.mod"),
            "SING_BOX_UPSTREAM_GO_SUM_SHA256": _sha(b"upstream go.sum"),
            "SING_BOX_SECURITY_PATCH_PATH": PATCH_PATHS["security"],
            "SING_BOX_SECURITY_PATCH_SHA256": SECURITY_SHA,
            "SING_BOX_RAW_PACKET_PATCH_PATH": PATCH_PATHS["raw"],
            "SING_BOX_RAW_PACKET_PATCH_SHA256": RAW_SHA,
            "SING_BOX_DNS_FAILOVER_PATCH_PATH": PATCH_PATHS["dns"],
            "SING_BOX_DNS_FAILOVER_PATCH_SHA256": DNS_SHA,
            "SING_BOX_ENDPOINT_CONFLICT_PATCH_PATH": PATCH_PATHS["endpoint"],
            "SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256": ENDPOINT_SHA,
            "SING_BOX_PATCHED_DIFF_SHA256": SECURITY_SHA,
            "SING_BOX_COMBINED_DIFF_SHA256": COMBINED_SHA,
            "SING_BOX_PATCHED_GO_MOD_SHA256": _sha(b"patched go.mod"),
            "SING_BOX_PATCHED_GO_SUM_SHA256": _sha(b"patched go.sum"),
            "LIBBOX_BUILD_TAGS": BUILD_TAGS,
            "LIBBOX_MODULE_CACHE_CONTRACT_PATH": LIBBOX_MODULE_CACHE_CONTRACT_PATH,
            "LIBBOX_MODULE_CACHE_CONTRACT_SHA256": LIBBOX_MODULE_CACHE_CONTRACT_SHA,
        }
        self.patch_bodies = dict(PATCH_BODIES)
        self.packet_endpoint_files = {
            relative: (REPO_ROOT / relative).read_bytes()
            for relative in PACKET_ENDPOINT_PATHS
        }
        self.packet_lan_peer_files = {
            f"tools/packet-lan-peer/{relative}": (
                REPO_ROOT / "tools/packet-lan-peer" / relative
            ).read_bytes()
            for relative, _, _ in PACKET_LAN_PEER_SOURCE_ENTRIES
        }
        self.packet_lan_peer_modes = {
            relative: 0o644 for relative in self.packet_lan_peer_files
        }
        self.packet_lan_peer_build_script = (
            REPO_ROOT / "scripts/build_packet_lan_peer.sh"
        ).read_bytes()
        self.packet_lan_peer_verify_script = (
            REPO_ROOT / "scripts/verify_packet_lan_peer.sh"
        ).read_bytes()
        self.packet_lan_peer_build_script_mode = 0o755
        self.packet_lan_peer_verify_script_mode = 0o755
        self.packet_lan_peer_artifact = SYNTHETIC_PACKET_LAN_PEER_ARTIFACT
        self.packet_lan_peer_artifact_mode = 0o555
        self.android_admission_source = SYNTHETIC_ANDROID_ADMISSION_SOURCE
        self.physical_collector_files = {
            relative: (REPO_ROOT / relative).read_bytes()
            for relative in PHYSICAL_COLLECTOR_PATHS
        }
        self.controller_source = CONTROLLER_SOURCE
        self.projection_source = PROJECTION_SOURCE
        self.manifest = {
            "schema": "cfw-pinned-build-inputs-v1",
            "description": "synthetic pinned build inputs",
            "dependencyPinsPath": "scripts/dependency_pins.env",
            "nativeLockPath": "native/macos/Dependencies.lock.json",
            "tools": {
                "PYTHON_VERSION": "3.14.6",
                "RUST_VERSION": "1.97.1",
                "RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256": (
                    "472d78d9340576ca15b8f17f2eb4fe5fb709c0aae3a428e8c4dfd2cd65e5b6ae"
                ),
                "CARGO_AUDIT_VERSION": "0.22.2",
                "CARGO_DENY_VERSION": "0.20.2",
                "XCODEGEN_VERSION": "2.46.0",
                "XCODEGEN_COMMIT": "8445e778451c7e44237b90281bde622d764b0084",
                "XCODEGEN_SOURCE_SHA256": "a3270d0e5fce8f4dc2aa1801b0d932f6561cd24c0735e718d2455896b2359142",
                "XCODEGEN_PACKAGE_RESOLVED_SHA256": "2f0b0265e33ab55bbc6cab8ad209afa85821064a2cb6fe4a1df07b642f7cebcd",
                "NODE_VERSION": "24.18.0",
                "GO_VERSION": "1.26.6",
                "GOMOBILE_VERSION": "v0.1.13",
                "GOVULNCHECK_VERSION": "v1.6.0",
                "TAURI_CLI_VERSION": "2.11.4",
                "SING_BOX_VERSION": "v1.13.15",
            },
            "runtimeTools": {
                "adb": {
                    "schema": "cfw-runtime-tool-pin-v1",
                    "path": ADB_RUNTIME_TOOL_PATH,
                    "version": ADB_RUNTIME_TOOL_VERSION,
                    "sha256": ADB_RUNTIME_TOOL_SHA256,
                    "verificationPhase": "android-lan-peer-admission",
                    "sourceBinding": {
                        "path": ANDROID_LAN_PEER_SOURCE_PATH,
                        "sha256": _sha(self.android_admission_source),
                        "size": len(self.android_admission_source),
                        "mode": "0644",
                        "pathConstant": "ADB",
                        "versionConstant": "ADB_VERSION",
                        "sha256Constant": "ADB_SHA256",
                    },
                }
            },
            "packetEvidenceEndpoint": {
                "goVersionKey": "GO_VERSION",
                "goVersion": "1.26.6",
                "goos": "linux",
                "goarch": "amd64",
                "cgoEnabled": "0",
                "binarySha256": PACKET_ENDPOINT_BINARY_SHA,
                "transportPort": 44333,
                "dnsPort": 53,
                "readmePath": "tools/packet-evidence-endpoint/README.md",
                "requiredBuildFragments": list(PACKET_ENDPOINT_BUILD_FRAGMENTS),
                "sourceFiles": [
                    {"path": path, "sha256": _sha(body)}
                    for path, body in self.packet_endpoint_files.items()
                ],
            },
            "packetLanPeer": {
                "schema": "cfw-packet-lan-peer-build-input-v1",
                "goToolchain": {
                    "versionKey": "GO_VERSION",
                    "version": "1.26.6",
                    "goos": "linux",
                    "goarch": "arm64",
                    "cgoEnabled": "0",
                },
                "source": {
                    "root": "tools/packet-lan-peer",
                    "treeAlgorithm": "sha256-tree-v2",
                    "treeSha256": PACKET_LAN_PEER_SOURCE_TREE_SHA,
                    "rootMode": "0755",
                    "files": [
                        {
                            "path": path,
                            "sha256": sha256,
                            "size": size,
                            "mode": "0644",
                        }
                        for path, sha256, size in PACKET_LAN_PEER_SOURCE_ENTRIES
                    ],
                },
                "artifact": {
                    "path": "target/packet-lan-peer-linux-arm64",
                    "sha256": _sha(self.packet_lan_peer_artifact),
                    "size": len(self.packet_lan_peer_artifact),
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
                "buildScript": {
                    "path": "scripts/build_packet_lan_peer.sh",
                    "sha256": (
                        "c3fb49c83d98a710a15874afe83a3606b3f50f1f65b01c76dbb03edfcc9b43d8"
                    ),
                    "size": 4933,
                    "mode": "0755",
                    "requiredFragments": list(PACKET_LAN_PEER_BUILD_FRAGMENTS),
                },
                "verifyScript": {
                    "path": "scripts/verify_packet_lan_peer.sh",
                    "sha256": (
                        "eb7c518d3209ccf6486847e9f9042f58796b2192d5fdd733f3b991f640d7309e"
                    ),
                    "size": 7357,
                    "mode": "0755",
                    "requiredFragments": list(PACKET_LAN_PEER_VERIFY_FRAGMENTS),
                },
            },
            "physicalCollectorModule": {
                "goVersionKey": "GO_VERSION",
                "goVersion": "1.26.6",
                "goModPath": "tools/physical-collector/go.mod",
                "goModSha256": _sha(
                    self.physical_collector_files["tools/physical-collector/go.mod"]
                ),
                "goSumPath": "tools/physical-collector/go.sum",
                "goSumSha256": _sha(
                    self.physical_collector_files["tools/physical-collector/go.sum"]
                ),
                "requiredModuleFragments": list(
                    PHYSICAL_COLLECTOR_MODULE_FRAGMENTS
                ),
            },
            "xcodegen": {
                "patchPathKey": "XCODEGEN_PATCH_PATH",
                "patchSha256Key": "XCODEGEN_PATCH_SHA256",
                "patchSha256": XCODEGEN_PATCH_SHA,
                "patchedSettingsBuilderSha256Key": "XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256",
                "patchedSettingsBuilderSha256": XCODEGEN_PATCHED_SETTINGS_SHA,
                "bootstrapPath": "scripts/bootstrap_release_toolchain.sh",
                "requiredBootstrapFragments": [
                    "$XCODEGEN_PATCH_PATH",
                    "$XCODEGEN_PATCH_SHA256",
                    "$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256",
                    'GIT_CEILING_DIRECTORIES="$toolchain_root"',
                    '/usr/bin/git -C "$payload/source" apply --check "$xcodegen_patch"',
                    '/usr/bin/git -C "$payload/source" apply --reverse --check "$xcodegen_patch"',
                    "USER=cfw-release",
                    "LOGNAME=cfw-release",
                    '/usr/bin/strip -S "$build_root/release/xcodegen"',
                    "patchSha256=$XCODEGEN_PATCH_SHA256",
                    "patchedSettingsBuilderSha256=$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256",
                    "XcodeGenResourceProbe.xcodeproj/project.pbxproj",
                ],
            },
            "gomobileCommitKey": "GOMOBILE_COMMIT",
            "gomobileCommit": GOMOBILE_COMMIT,
            "cargoDeny": {
                "ciWorkflowPath": ".github/workflows/ci.yml",
                "requiredCiFragments": [
                    "run_release_ci_gate.sh",
                    "bootstrap-policy-tools",
                    "cargo-deny",
                ],
            },
            "tauriCli": {
                "crateSha256Key": "TAURI_CLI_CRATE_SHA256",
                "crateSha256": TAURI_CRATE_SHA,
                "upstreamCargoLockSha256Key": "TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256",
                "upstreamCargoLockSha256": TAURI_UPSTREAM_LOCK_SHA,
                "lockPatchPathKey": "TAURI_CLI_LOCK_PATCH_PATH",
                "lockPatchSha256Key": "TAURI_CLI_LOCK_PATCH_SHA256",
                "lockPatchSha256": TAURI_LOCK_PATCH_SHA,
                "patchedCargoLockSha256Key": "TAURI_CLI_PATCHED_CARGO_LOCK_SHA256",
                "patchedCargoLockSha256": TAURI_PATCHED_LOCK_SHA,
                "spinVersionKey": "TAURI_CLI_SPIN_VERSION",
                "spinVersion": "0.9.9",
                "spinCrateSha256Key": "TAURI_CLI_SPIN_CRATE_SHA256",
                "spinCrateSha256": TAURI_SPIN_SHA,
                "cacheContractPath": TAURI_CACHE_CONTRACT_PATH,
                "cacheContractSha256Key": "TAURI_CARGO_CACHE_CONTRACT_SHA256",
                "cacheContractSha256": TAURI_CACHE_CONTRACT_SHA,
                "ciWorkflowPath": ".github/workflows/ci.yml",
                "requiredCiFragment": "install-tauri-cli",
                "installerPath": "scripts/install_pinned_tauri_cli.sh",
                "requiredInstallerFragments": [
                    "https://static.crates.io/crates/tauri-cli/tauri-cli-$TAURI_CLI_VERSION.crate",
                    "$TAURI_CLI_CRATE_SHA256",
                    "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256",
                    "$TAURI_CLI_LOCK_PATCH_SHA256",
                    "$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256",
                    "$TAURI_CLI_SPIN_VERSION",
                    "$TAURI_CLI_SPIN_CRATE_SHA256",
                    "$TAURI_CARGO_CACHE_CONTRACT_SHA256",
                    'readonly cargo_cache_contract="$repo_root/scripts/tauri_cargo_cache_contract.py"',
                    "cfw_run_release_python_script",
                    '"$repo_root" "$cargo_cache_contract"',
                    'validate-preparation "$root"',
                    'normalize-offline "$root"',
                    'cargo_bin="$CFW_RELEASE_CARGO_EXECUTABLE"',
                    'rustc_bin="$CFW_RELEASE_RUSTC_EXECUTABLE"',
                    "/usr/bin/env -i",
                    'CARGO_HOME="$prepared_cargo_home"',
                    'CARGO_HOME="$offline_cargo_home"',
                    'CARGO_TARGET_DIR="$cargo_target"',
                    "CARGO_HTTP_LOW_SPEED_LIMIT=1",
                    "CARGO_HTTP_MULTIPLEXING=true",
                    "CARGO_HTTP_TIMEOUT=600",
                    "CARGO_NET_RETRY=3",
                    "CARGO_NET_RETRY=0",
                    "CARGO_NET_OFFLINE=true",
                    "CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse",
                    "CARGO_TERM_COLOR=never",
                    'RUSTC="$rustc_bin"',
                    "--unidiff-zero",
                    "fetch",
                    "--manifest-path",
                    "install",
                    "--path",
                    "--offline",
                    "--locked",
                    "--target aarch64-apple-darwin",
                    "tauri-cli-$TAURI_CLI_VERSION",
                    'payload="$staging/payload/tauri-cli-$TAURI_CLI_VERSION"',
                    '/usr/bin/ditto --noqtn "$prepared_cargo_home" "$offline_cargo_home"',
                    'normalize_cargo_offline_cache "$offline_cargo_home"',
                    'reject_cargo_warnings "$fetch_log" "Tauri CLI dependency preparation"',
                    'reject_cargo_warnings "$install_log" "tauri-cli installation"',
                    'PATH="$cargo_install_root/bin:$(dirname "$cargo_bin"):/usr/bin:/bin:/usr/sbin:/sbin"',
                    '/bin/mv "$source_root" "$payload/source"',
                    "/usr/bin/lipo -archs",
                    "--algorithm sha256-tree-v2",
                    "artifactKind=pinned-tauri-cli-v2",
                    "cacheContractSha256=$TAURI_CARGO_CACHE_CONTRACT_SHA256",
                    "cacheNormalization=cargo-runtime-metadata-v1",
                    "dependencyMode=isolated-fetch-offline-locked-v1",
                    "macosDeploymentTarget=$MACOS_DEPLOYMENT_TARGET",
                    "payloadLayout=bin-and-patched-source-v1",
                    "xcodeBuild=$XCODE_BUILD_VERSION",
                    "xcodeVersion=$XCODE_VERSION",
                    "cfw_verify_release_toolchain_manifest",
                    "cfw_verify_tauri_toolchain_tree",
                ],
            },
            "singBoxCommitKey": "SING_BOX_COMMIT",
            "singBoxCommit": COMMIT,
            "patches": [
                {
                    "name": "sing-box security dependencies patch",
                    "pathKey": "SING_BOX_SECURITY_PATCH_PATH",
                    "sha256Key": "SING_BOX_SECURITY_PATCH_SHA256",
                    "sha256": SECURITY_SHA,
                },
                {
                    "name": "sing-box raw packet tun patch",
                    "pathKey": "SING_BOX_RAW_PACKET_PATCH_PATH",
                    "sha256Key": "SING_BOX_RAW_PACKET_PATCH_SHA256",
                    "sha256": RAW_SHA,
                },
                {
                    "name": "sing-box DNS failover patch",
                    "pathKey": "SING_BOX_DNS_FAILOVER_PATCH_PATH",
                    "sha256Key": "SING_BOX_DNS_FAILOVER_PATCH_SHA256",
                    "sha256": DNS_SHA,
                },
                {
                    "name": "sing-box endpoint conflict patch",
                    "pathKey": "SING_BOX_ENDPOINT_CONFLICT_PATCH_PATH",
                    "sha256Key": "SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
                    "sha256": ENDPOINT_SHA,
                },
            ],
            "combinedDiffSha256Key": "SING_BOX_COMBINED_DIFF_SHA256",
            "combinedDiffSha256": COMBINED_SHA,
            "sourceContract": {
                "patchedDiffSha256Key": "SING_BOX_PATCHED_DIFF_SHA256",
                "patchedDiffSha256": SECURITY_SHA,
                "patchedGoModSha256Key": "SING_BOX_PATCHED_GO_MOD_SHA256",
                "patchedGoModSha256": self.env["SING_BOX_PATCHED_GO_MOD_SHA256"],
                "patchedGoSumSha256Key": "SING_BOX_PATCHED_GO_SUM_SHA256",
                "patchedGoSumSha256": self.env["SING_BOX_PATCHED_GO_SUM_SHA256"],
            },
            "libboxModuleCacheContract": {
                "pathKey": "LIBBOX_MODULE_CACHE_CONTRACT_PATH",
                "path": LIBBOX_MODULE_CACHE_CONTRACT_PATH,
                "sha256Key": "LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
                "sha256": LIBBOX_MODULE_CACHE_CONTRACT_SHA,
            },
            "verifiedGoModuleInputKeys": [
                "GOMOBILE_MODULE_SUM",
                "GOVULNCHECK_MODULE_SUM",
                "LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
                "SING_BOX_UPSTREAM_GO_MOD_SHA256",
                "SING_BOX_UPSTREAM_GO_SUM_SHA256",
                "SING_BOX_PATCHED_GO_MOD_SHA256",
                "SING_BOX_PATCHED_GO_SUM_SHA256",
            ],
            "rejectedPatchDigests": list(REJECTED_PATCH_DIGESTS),
            "libboxBuildTags": {
                "pinKey": "LIBBOX_BUILD_TAGS",
                "value": BUILD_TAGS,
                "required": [
                    {"tag": "with_quic", "reason": "QUIC outbounds"},
                    {"tag": "with_utls", "reason": "uTLS fingerprints"},
                    {"tag": "with_clash_api", "reason": "engine start path needs the server"},
                    {"tag": "badlinkname", "reason": "Go linkname compatibility"},
                    {
                        "tag": "tfogo_checklinkname0",
                        "reason": "tfo-go linkname compatibility",
                    },
                    {"tag": "grpcnotrace", "reason": "no gRPC trace surface"},
                ],
                "engineStartPathBindings": [
                    {
                        "tag": "with_clash_api",
                        "path": CONTROLLER_RELATIVE_PATH,
                        "requiredWhenContains": CONTROLLER_TRIGGER,
                        "triggerRequired": True,
                        "reason": "the projected controller block needs the real server",
                    },
                    {
                        "tag": "with_clash_api",
                        "path": PROJECTION_RELATIVE_PATH,
                        "requiredWhenContains": PROJECTION_TRIGGER,
                        "triggerRequired": True,
                        "reason": "every projected configuration needs the real server",
                    }
                ],
            },
            "buildScripts": {
                "scripts/build_libbox.sh": {
                    "requirePinReferences": [
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
                    ],
                    "forbidNetworkRecursion": True,
                }
            },
            "artifactBindings": copy.deepcopy(SHIPPED_ARTIFACT_BINDINGS),
            "artifactSourceSha256": copy.deepcopy(
                SHIPPED_ARTIFACT_SOURCE_SHA256
            ),
        }
        self.lock = {
            "go": "1.26.6",
            "gomobile": "v0.1.13",
            "singBox": {
                "commit": COMMIT,
                "tag": "v1.13.15",
                "androidReferenceCommit": ANDROID_REFERENCE_COMMIT,
                "securityPatch": {
                    "path": PATCH_PATHS["security"],
                    "sha256": SECURITY_SHA,
                    "patchedDiffSha256": SECURITY_SHA,
                    "patchedGoModSha256": self.env["SING_BOX_PATCHED_GO_MOD_SHA256"],
                    "patchedGoSumSha256": self.env["SING_BOX_PATCHED_GO_SUM_SHA256"],
                },
                "rawPacketPatch": {"path": PATCH_PATHS["raw"], "sha256": RAW_SHA},
                "dnsFailoverPatch": {"path": PATCH_PATHS["dns"], "sha256": DNS_SHA},
                "endpointConflictPatch": {
                    "path": PATCH_PATHS["endpoint"],
                    "sha256": ENDPOINT_SHA,
                },
                "combinedDiffSha256": COMBINED_SHA,
            },
            "singBoxForAppleReference": {"commit": APPLE_REFERENCE_COMMIT},
        }
        self.build_libbox = (REPO_ROOT / "scripts/build_libbox.sh").read_text(
            encoding="utf-8"
        )
        self.libbox_contract = (
            REPO_ROOT / "scripts/libbox_source_contract.sh"
        ).read_text(encoding="utf-8")
        self.build_native = (
            REPO_ROOT / "scripts/build_native_products.sh"
        ).read_text(encoding="utf-8")
        self.build_unsigned = (
            REPO_ROOT / "scripts/build_unsigned_candidate.sh"
        ).read_text(encoding="utf-8")
        self.tauri_lock_patch = TAURI_LOCK_PATCH_BODY
        self.libbox_module_cache_contract = LIBBOX_MODULE_CACHE_CONTRACT_BODY
        self.xcodegen_patch = XCODEGEN_PATCH_BODY
        self.xcodegen_bootstrap = XCODEGEN_BOOTSTRAP
        self.tauri_installer = TAURI_INSTALLER
        self.ci_workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        special_artifact_files = {
            ".github/workflows/ci.yml",
            "scripts/build_libbox.sh",
            "scripts/build_native_products.sh",
            "scripts/build_unsigned_candidate.sh",
            "scripts/libbox_source_contract.sh",
        }
        self.extra_artifact_files: dict[str, str] = {
            relative: (REPO_ROOT / relative).read_text(encoding="utf-8")
            for relative in self.manifest["artifactBindings"]
            if relative not in special_artifact_files
        }
        self._extra_env_text = ""

    def env_text(self) -> str:
        lines = ["# generated test pins"]
        lines += [f"{key}={value}" for key, value in self.env.items()]
        return "\n".join(lines) + "\n" + self._extra_env_text

    def append_env_text(self, text: str) -> None:
        self._extra_env_text += text

    def sync_android_admission_source_pin(self) -> None:
        binding = self.manifest["runtimeTools"]["adb"]["sourceBinding"]
        binding["sha256"] = _sha(self.android_admission_source)
        binding["size"] = len(self.android_admission_source)

    def write(self, root: Path) -> Path:
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "native/macos/patches").mkdir(parents=True, exist_ok=True)
        controller = root / CONTROLLER_RELATIVE_PATH
        controller.parent.mkdir(parents=True, exist_ok=True)
        controller.write_text(self.controller_source, encoding="utf-8")
        projection = root / PROJECTION_RELATIVE_PATH
        projection.parent.mkdir(parents=True, exist_ok=True)
        projection.write_text(self.projection_source, encoding="utf-8")
        (root / MANIFEST_RELATIVE_PATH).write_text(json.dumps(self.manifest), encoding="utf-8")
        (root / "scripts/dependency_pins.env").write_text(self.env_text(), encoding="utf-8")
        for key, body in self.patch_bodies.items():
            (root / PATCH_PATHS[key]).write_bytes(body)
        for relative, body in self.packet_endpoint_files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        for relative, body in self.packet_lan_peer_files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(self.packet_lan_peer_modes.get(relative, 0o644))
        (root / "tools/packet-lan-peer").chmod(0o755)
        packet_lan_peer_build = root / "scripts/build_packet_lan_peer.sh"
        packet_lan_peer_build.write_bytes(self.packet_lan_peer_build_script)
        packet_lan_peer_build.chmod(self.packet_lan_peer_build_script_mode)
        packet_lan_peer_verify = root / "scripts/verify_packet_lan_peer.sh"
        packet_lan_peer_verify.write_bytes(self.packet_lan_peer_verify_script)
        packet_lan_peer_verify.chmod(self.packet_lan_peer_verify_script_mode)
        packet_lan_peer_artifact = root / "target/packet-lan-peer-linux-arm64"
        packet_lan_peer_artifact.parent.mkdir(parents=True, exist_ok=True)
        packet_lan_peer_artifact.write_bytes(self.packet_lan_peer_artifact)
        packet_lan_peer_artifact.chmod(self.packet_lan_peer_artifact_mode)
        android_admission = root / ANDROID_LAN_PEER_SOURCE_PATH
        android_admission.parent.mkdir(parents=True, exist_ok=True)
        android_admission.write_bytes(self.android_admission_source)
        for relative, body in self.physical_collector_files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        (root / "native/macos/Dependencies.lock.json").write_text(
            json.dumps(self.lock), encoding="utf-8"
        )
        (root / "scripts/build_libbox.sh").write_text(self.build_libbox, encoding="utf-8")
        (root / "scripts/libbox_source_contract.sh").write_text(
            self.libbox_contract, encoding="utf-8"
        )
        (root / "scripts/build_native_products.sh").write_text(self.build_native, encoding="utf-8")
        (root / "scripts/build_unsigned_candidate.sh").write_text(
            self.build_unsigned, encoding="utf-8"
        )
        (root / TAURI_PATCH_PATH).write_bytes(self.tauri_lock_patch)
        (root / TAURI_CACHE_CONTRACT_PATH).write_bytes(TAURI_CACHE_CONTRACT_BODY)
        (root / LIBBOX_MODULE_CACHE_CONTRACT_PATH).write_bytes(
            self.libbox_module_cache_contract
        )
        (root / XCODEGEN_PATCH_PATH).write_bytes(self.xcodegen_patch)
        (root / "scripts/bootstrap_release_toolchain.sh").write_text(
            self.xcodegen_bootstrap, encoding="utf-8"
        )
        (root / "scripts/install_pinned_tauri_cli.sh").write_text(
            self.tauri_installer, encoding="utf-8"
        )
        (root / ".github/workflows").mkdir(parents=True, exist_ok=True)
        (root / ".github/workflows/ci.yml").write_text(self.ci_workflow, encoding="utf-8")
        for relative, contents in self.extra_artifact_files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        return root


class PinnedBuildInputsTests(unittest.TestCase):
    def _pinned_identity_patches(self, fixture: Fixture) -> tuple[object, ...]:
        source_binding = fixture.manifest["runtimeTools"]["adb"]["sourceBinding"]
        return (
            mock.patch(
                "scripts.verify_pinned_build_inputs._PACKET_LAN_PEER_ARTIFACT_SHA256",
                _sha(fixture.packet_lan_peer_artifact),
            ),
            mock.patch(
                "scripts.verify_pinned_build_inputs._PACKET_LAN_PEER_ARTIFACT_SIZE",
                len(fixture.packet_lan_peer_artifact),
            ),
            mock.patch(
                "scripts.verify_pinned_build_inputs._ANDROID_LAN_PEER_SOURCE_SHA256",
                source_binding["sha256"],
            ),
            mock.patch(
                "scripts.verify_pinned_build_inputs._ANDROID_LAN_PEER_SOURCE_SIZE",
                source_binding["size"],
            ),
        )

    def _verify_written_fixture(self, fixture: Fixture, root: Path) -> None:
        with ExitStack() as stack:
            for identity_patch in self._pinned_identity_patches(fixture):
                stack.enter_context(identity_patch)
            verify(root)

    def _verify_source_written_fixture(self, fixture: Fixture, root: Path) -> None:
        with ExitStack() as stack:
            for identity_patch in self._pinned_identity_patches(fixture):
                stack.enter_context(identity_patch)
            verify_source_contract(root)

    def _verify_fixture(self, fixture: Fixture) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            self._verify_written_fixture(fixture, root)

    def _assert_fails(self, fixture: Fixture, pattern: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            with self.assertRaisesRegex(PinnedInputError, pattern):
                self._verify_written_fixture(fixture, root)

    # --- success ------------------------------------------------------------

    def test_correct_pins_pass(self) -> None:
        self._verify_fixture(Fixture())

    def test_source_contract_does_not_require_generated_packet_artifact(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            artifact = root / "target/packet-lan-peer-linux-arm64"
            artifact.unlink()
            artifact.parent.rmdir()
            self._verify_source_written_fixture(fixture, root)

    def test_source_contract_still_rejects_packet_source_drift(self) -> None:
        fixture = Fixture()
        fixture.packet_lan_peer_files["tools/packet-lan-peer/main.go"] += b"// drift\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            artifact = root / "target/packet-lan-peer-linux-arm64"
            artifact.unlink()
            artifact.parent.rmdir()
            with self.assertRaisesRegex(PinnedInputError, "packet LAN peer source tree"):
                self._verify_source_written_fixture(fixture, root)

    def test_real_repository_source_contract_passes(self) -> None:
        # Binds the shipped manifest, dependency_pins.env, patch files, native lock,
        # and offline build scripts together without relying on a generated target.
        verify_source_contract(REPO_ROOT)

    def test_build_boundary_uses_source_only_pinned_contract(self) -> None:
        boundary = (REPO_ROOT / "scripts/verify_build_boundaries.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '"$repo_root/scripts/verify_pinned_source_contract.py"', boundary
        )
        self.assertNotIn('"$repo_root/scripts/verify_pinned_build_inputs.py"', boundary)

    def test_packet_endpoint_source_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.packet_endpoint_files[
            "tools/packet-evidence-endpoint/main.go"
        ] += b"// drift\n"
        self._assert_fails(fixture, "packet evidence endpoint source digest drifted")

    def test_packet_endpoint_exact_source_set_is_required(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetEvidenceEndpoint"]["sourceFiles"].pop()
        self._assert_fails(
            fixture, "exact source, test, service, policy, host-key, and README set"
        )

    def test_packet_endpoint_build_digest_cannot_drift(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetEvidenceEndpoint"]["binarySha256"] = "0" * 64
        self._assert_fails(fixture, "build target, ports, or binary digest drifted")

    def test_packet_endpoint_readme_must_retain_reproducible_build(self) -> None:
        fixture = Fixture()
        readme_path = "tools/packet-evidence-endpoint/README.md"
        body = fixture.packet_endpoint_files[readme_path].replace(
            b"CGO_ENABLED=0", b"CGO_ENABLED=1"
        )
        fixture.packet_endpoint_files[readme_path] = body
        for entry in fixture.manifest["packetEvidenceEndpoint"]["sourceFiles"]:
            if entry["path"] == readme_path:
                entry["sha256"] = _sha(body)
        self._assert_fails(fixture, "README lacks build binding")

    def test_adb_runtime_tool_path_mutation_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["runtimeTools"]["adb"]["path"] = "/usr/local/bin/adb"
        self._assert_fails(fixture, "runtime-tool pin contract")

    def test_adb_runtime_tool_version_mutation_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["runtimeTools"]["adb"]["version"] = "37.0.0"
        self._assert_fails(fixture, "runtime-tool pin contract")

    def test_adb_runtime_tool_digest_mutation_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["runtimeTools"]["adb"]["sha256"] = "0" * 64
        self._assert_fails(fixture, "runtime-tool pin contract")

    def test_adb_runtime_tool_unknown_field_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["runtimeTools"]["adb"]["fallback"] = True
        self._assert_fails(fixture, "runtime-tool pin contract")

    def test_adb_admission_source_constant_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.android_admission_source = fixture.android_admission_source.replace(
            ADB_RUNTIME_TOOL_VERSION.encode(), b"37.0.0-incorrect", 1
        )
        fixture.sync_android_admission_source_pin()
        self._assert_fails(fixture, "ADB constants differ")

    def test_adb_admission_source_requires_literal_constants(self) -> None:
        fixture = Fixture()
        fixture.android_admission_source = fixture.android_admission_source.replace(
            b'ADB_VERSION: Final = "37.0.0-14910828"',
            b'ADB_VERSION: Final = "37.0.0-" + "14910828"',
            1,
        )
        fixture.sync_android_admission_source_pin()
        self._assert_fails(fixture, "ADB_VERSION must be a string literal")

    def test_adb_admission_source_reassignment_fails(self) -> None:
        fixture = Fixture()
        fixture.android_admission_source += b'ADB = Path("/tmp/unpinned-adb")\n'
        fixture.sync_android_admission_source_pin()
        self._assert_fails(fixture, "non-Final reassignment")

    def test_adb_admission_source_nested_reassignment_fails(self) -> None:
        fixture = Fixture()
        fixture.android_admission_source += (
            b'if True:\n    ADB_VERSION = "37.0.0-unpinned"\n'
        )
        fixture.sync_android_admission_source_pin()
        self._assert_fails(fixture, "exactly one source binding")

    def test_adb_admission_source_parameter_shadow_fails(self) -> None:
        fixture = Fixture()
        fixture.android_admission_source = fixture.android_admission_source.replace(
            b"def _fixed_spec(\n    role: str,\n",
            b"def _fixed_spec(\n    role: str,\n    ADB: Path,\n",
            1,
        )
        fixture.sync_android_admission_source_pin()
        self._assert_fails(fixture, "exactly one source binding")

    def test_adb_admission_source_whole_file_drift_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            source = root / ANDROID_LAN_PEER_SOURCE_PATH
            body = bytearray(source.read_bytes())
            body[-1] ^= 1
            source.write_bytes(body)
            with self.assertRaisesRegex(PinnedInputError, "SHA-256"):
                self._verify_written_fixture(fixture, root)

    def test_adb_admission_runtime_path_must_load_pinned_constant(self) -> None:
        fixture = Fixture()
        marker = f'ADB_SHA256: Final = "{ADB_RUNTIME_TOOL_SHA256}"\n'.encode()
        fixture.android_admission_source = fixture.android_admission_source.replace(
            marker,
            marker + b'RUNTIME_ADB: Final = Path("/tmp/unpinned-adb")\n',
            1,
        ).replace(b"prefix = (adb_path,", b"prefix = (RUNTIME_ADB,", 1)
        fixture.sync_android_admission_source_pin()
        self._assert_fails(fixture, "pinned or private ADB client")

    def test_packet_lan_peer_source_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.packet_lan_peer_files["tools/packet-lan-peer/main.go"] += b"// drift\n"
        self._assert_fails(fixture, "packet LAN peer source tree")

    def test_packet_lan_peer_extra_source_file_fails(self) -> None:
        fixture = Fixture()
        fixture.packet_lan_peer_files["tools/packet-lan-peer/extra.go"] = b"package main\n"
        self._assert_fails(fixture, "packet LAN peer source tree")

    def test_packet_lan_peer_source_mode_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.packet_lan_peer_modes["tools/packet-lan-peer/main.go"] = 0o600
        self._assert_fails(fixture, "packet LAN peer source tree")

    def test_packet_lan_peer_tree_digest_mutation_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetLanPeer"]["source"]["treeSha256"] = "0" * 64
        self._assert_fails(fixture, "packet LAN peer build-input contract")

    def test_packet_lan_peer_target_mutation_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetLanPeer"]["goToolchain"]["goarch"] = "amd64"
        self._assert_fails(fixture, "packet LAN peer build-input contract")

    def test_packet_lan_peer_integer_field_rejects_boolean_alias(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetLanPeer"]["protocol"]["port"] = True
        self._assert_fails(fixture, "packet LAN peer build-input contract")

    def test_packet_lan_peer_resource_limit_mutation_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetLanPeer"]["protocol"]["maximumRequestBytes"] = 65
        self._assert_fails(fixture, "packet LAN peer build-input contract")

    def test_packet_lan_peer_artifact_digest_mutation_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetLanPeer"]["artifact"]["sha256"] = "0" * 64
        self._assert_fails(fixture, "packet LAN peer build-input contract")

    def test_packet_lan_peer_artifact_type_alias_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetLanPeer"]["artifact"]["fileType"] = "file"
        self._assert_fails(fixture, "packet LAN peer build-input contract")

    def test_packet_lan_peer_artifact_link_count_rejects_boolean_alias(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetLanPeer"]["artifact"]["linkCount"] = True
        self._assert_fails(fixture, "packet LAN peer build-input contract")

    def test_packet_lan_peer_actual_artifact_symlink_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            artifact = root / "target/packet-lan-peer-linux-arm64"
            target = artifact.with_name("packet-lan-peer-real")
            artifact.rename(target)
            artifact.symlink_to(target.name)
            with self.assertRaisesRegex(PinnedInputError, "symlink|unsafe path"):
                self._verify_written_fixture(fixture, root)

    def test_packet_lan_peer_artifact_parent_symlink_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            target = root / "target"
            real_target = root / "target-real"
            target.rename(real_target)
            target.symlink_to(real_target.name, target_is_directory=True)
            with self.assertRaisesRegex(PinnedInputError, "parent.*symlink"):
                self._verify_written_fixture(fixture, root)

    def test_packet_lan_peer_artifact_parent_replacement_during_read_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            artifact = root / "target/packet-lan-peer-linux-arm64"
            artifact_identity = (artifact.stat().st_dev, artifact.stat().st_ino)
            real_read = os.read
            replaced = False

            def replace_parent(descriptor: int, count: int) -> bytes:
                nonlocal replaced
                metadata = os.fstat(descriptor)
                if not replaced and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == artifact_identity:
                    replaced = True
                    artifact.parent.rename(root / "target-held")
                    artifact.parent.mkdir(mode=0o755)
                    artifact.write_bytes(b"unpinned replacement")
                    artifact.chmod(0o555)
                return real_read(descriptor, count)

            with (
                mock.patch(
                    "scripts.verify_pinned_build_inputs.os.read",
                    side_effect=replace_parent,
                ),
                self.assertRaisesRegex(
                    PinnedInputError,
                    "parent.*changed|repository.*changed|current path",
                ),
            ):
                self._verify_written_fixture(fixture, root)
            self.assertTrue(replaced)

    def test_packet_lan_peer_actual_artifact_hardlink_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            artifact = root / "target/packet-lan-peer-linux-arm64"
            os.link(artifact, artifact.with_name("packet-lan-peer-hardlink"))
            with self.assertRaisesRegex(PinnedInputError, "exactly one hard link"):
                self._verify_written_fixture(fixture, root)

    def test_packet_lan_peer_actual_artifact_non_regular_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            artifact = root / "target/packet-lan-peer-linux-arm64"
            artifact.unlink()
            artifact.mkdir(mode=0o555)
            with self.assertRaisesRegex(PinnedInputError, "not a regular file"):
                self._verify_written_fixture(fixture, root)

    def test_packet_lan_peer_actual_artifact_mode_fails(self) -> None:
        fixture = Fixture()
        fixture.packet_lan_peer_artifact_mode = 0o755
        self._assert_fails(fixture, "mode is not 0555")

    def test_packet_lan_peer_actual_artifact_size_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            artifact = root / "target/packet-lan-peer-linux-arm64"
            artifact.chmod(0o755)
            artifact.write_bytes(artifact.read_bytes() + b"x")
            artifact.chmod(0o555)
            with self.assertRaisesRegex(PinnedInputError, "size is"):
                self._verify_written_fixture(fixture, root)

    def test_packet_lan_peer_actual_artifact_missing_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            (root / "target/packet-lan-peer-linux-arm64").unlink()
            with self.assertRaisesRegex(PinnedInputError, "missing"):
                self._verify_written_fixture(fixture, root)

    def test_packet_lan_peer_actual_artifact_owner_fails(self) -> None:
        fixture = Fixture()
        actual_uid = os.geteuid()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            with (
                mock.patch(
                    "scripts.verify_pinned_build_inputs.os.geteuid",
                    side_effect=(actual_uid, actual_uid + 1),
                ),
                self.assertRaisesRegex(PinnedInputError, "effective user"),
            ):
                self._verify_written_fixture(fixture, root)

    def test_packet_lan_peer_actual_artifact_digest_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            artifact = root / "target/packet-lan-peer-linux-arm64"
            artifact.chmod(0o755)
            body = bytearray(artifact.read_bytes())
            body[0] ^= 1
            artifact.write_bytes(body)
            artifact.chmod(0o555)
            with self.assertRaisesRegex(PinnedInputError, "SHA-256"):
                self._verify_written_fixture(fixture, root)

    def test_packet_lan_peer_actual_artifact_metadata_drift_fails(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            artifact = root / "target/packet-lan-peer-linux-arm64"
            target_identity = (artifact.stat().st_dev, artifact.stat().st_ino)
            real_fstat = os.fstat
            target_calls = 0

            def drifting_fstat(descriptor: int) -> os.stat_result:
                nonlocal target_calls
                metadata = real_fstat(descriptor)
                if (metadata.st_dev, metadata.st_ino) != target_identity:
                    return metadata
                target_calls += 1
                if target_calls != 2:
                    return metadata
                values = list(metadata)
                values[6] += 1
                return os.stat_result(values)

            with (
                mock.patch(
                    "scripts.verify_pinned_build_inputs.os.fstat",
                    side_effect=drifting_fstat,
                ),
                self.assertRaisesRegex(PinnedInputError, "metadata changed"),
            ):
                self._verify_written_fixture(fixture, root)

    def test_packet_lan_peer_deployment_mode_mutation_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetLanPeer"]["androidDeployment"][
            "binaryMode"
        ] = "0555"
        self._assert_fails(fixture, "packet LAN peer build-input contract")

    def test_packet_lan_peer_build_script_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.packet_lan_peer_build_script = (
            fixture.packet_lan_peer_build_script.replace(
                b"GOARCH=arm64", b"GOARCH=amd64", 1
            )
        )
        self._assert_fails(fixture, "packet LAN peer build script")

    def test_packet_lan_peer_verify_script_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.packet_lan_peer_verify_script = (
            fixture.packet_lan_peer_verify_script.replace(
                b"test -race -count=1", b"test -count=1", 1
            )
        )
        self._assert_fails(fixture, "packet LAN peer verification script")

    def test_packet_lan_peer_script_mode_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.packet_lan_peer_verify_script_mode = 0o700
        self._assert_fails(fixture, "packet LAN peer verification script")

    def test_packet_lan_peer_unknown_field_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["packetLanPeer"]["fallback"] = True
        self._assert_fails(fixture, "packet LAN peer build-input contract")

    def test_packet_lan_peer_missing_section_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.manifest["packetLanPeer"]
        self._assert_fails(fixture, "exact top-level shape")

    def test_physical_collector_module_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.physical_collector_files["tools/physical-collector/go.mod"] += (
            b"\n// drift\n"
        )
        self._assert_fails(fixture, "physical-collector go.mod digest drifted")

    def test_physical_collector_required_security_versions_are_exact(self) -> None:
        fixture = Fixture()
        fixture.manifest["physicalCollectorModule"]["requiredModuleFragments"][
            0
        ] = "google.golang.org/grpc v1.82.0"
        self._assert_fails(fixture, "physical-collector module pins differ")

    # --- wrong / missing pins -----------------------------------------------

    def test_wrong_tool_version_fails(self) -> None:
        fixture = Fixture()
        fixture.env["GO_VERSION"] = "1.26.4"
        self._assert_fails(fixture, "GO_VERSION")

    def test_missing_pin_fails(self) -> None:
        fixture = Fixture()
        del fixture.env["GOVULNCHECK_VERSION"]
        self._assert_fails(fixture, "GOVULNCHECK_VERSION")

    def test_coordinated_tool_pin_deletion_fails_fixed_policy(self) -> None:
        fixture = Fixture()
        del fixture.manifest["tools"]["GOVULNCHECK_VERSION"]
        del fixture.env["GOVULNCHECK_VERSION"]
        self._assert_fails(fixture, "fixed tool pin set")

    def test_wrong_commit_fails(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_COMMIT"] = "0" * 40
        self._assert_fails(fixture, "commit")

    def test_wrong_gomobile_commit_fails(self) -> None:
        fixture = Fixture()
        fixture.env["GOMOBILE_COMMIT"] = "0" * 40
        self._assert_fails(fixture, "gomobile commit")

    def test_missing_go_module_input_fails(self) -> None:
        fixture = Fixture()
        del fixture.env["GOMOBILE_MODULE_SUM"]
        self._assert_fails(fixture, "GOMOBILE_MODULE_SUM")

    def test_coordinated_go_module_input_deletion_fails_fixed_policy(self) -> None:
        fixture = Fixture()
        fixture.manifest["verifiedGoModuleInputKeys"].remove(
            "GOVULNCHECK_MODULE_SUM"
        )
        fixture.env["GOVULNCHECK_MODULE_SUM"] = "not-an-h1-sum"
        self._assert_fails(fixture, "fixed verified Go module input set")

    def test_go_module_input_policy_requires_strings_and_unique_keys(self) -> None:
        invalid_values = (
            None,
            {},
            [],
            [
                "GOMOBILE_MODULE_SUM",
                "GOVULNCHECK_MODULE_SUM",
                "LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
                "SING_BOX_UPSTREAM_GO_MOD_SHA256",
                "SING_BOX_UPSTREAM_GO_SUM_SHA256",
                "SING_BOX_PATCHED_GO_MOD_SHA256",
                7,
            ],
            [
                "GOMOBILE_MODULE_SUM",
                "GOVULNCHECK_MODULE_SUM",
                "LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
                "SING_BOX_UPSTREAM_GO_MOD_SHA256",
                "SING_BOX_UPSTREAM_GO_SUM_SHA256",
                "SING_BOX_PATCHED_GO_MOD_SHA256",
                "SING_BOX_PATCHED_GO_MOD_SHA256",
            ],
        )
        for value in invalid_values:
            with self.subTest(value=value):
                fixture = Fixture()
                fixture.manifest["verifiedGoModuleInputKeys"] = value
                self._assert_fails(fixture, "fixed verified Go module input set")

    def test_libbox_module_cache_contract_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.libbox_module_cache_contract += b"# unpinned package drift\n"
        self._assert_fails(fixture, "libbox module cache contract file digest")

    def test_libbox_module_cache_contract_env_digest_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_MODULE_CACHE_CONTRACT_SHA256"] = "a" * 64
        self._assert_fails(fixture, "libbox module cache contract digest")

    def test_libbox_module_cache_contract_path_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_MODULE_CACHE_CONTRACT_PATH"] = "scripts/other-contract.sh"
        self._assert_fails(fixture, "libbox module cache contract path")

    def test_missing_libbox_module_cache_contract_binding_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.manifest["libboxModuleCacheContract"]
        self._assert_fails(fixture, "exact top-level shape")

    def test_source_contract_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_PATCHED_GO_MOD_SHA256"] = "a" * 64
        self._assert_fails(fixture, "source contract patchedGoModSha256")

    def test_native_lock_source_contract_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.lock["singBox"]["securityPatch"]["patchedGoSumSha256"] = "a" * 64
        self._assert_fails(fixture, "securityPatch.patchedGoSumSha256")

    def test_native_lock_android_reference_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.lock["singBox"]["androidReferenceCommit"] = "a" * 40
        self._assert_fails(fixture, "singBox.androidReferenceCommit")

    def test_native_lock_apple_reference_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.lock["singBoxForAppleReference"]["commit"] = "a" * 40
        self._assert_fails(fixture, "singBoxForAppleReference.commit")

    def test_cargo_deny_ci_hard_coded_version_fails(self) -> None:
        fixture = Fixture()
        fixture.ci_workflow += (
            "\n      - run: cargo install cargo-deny --version 0.20.2 --locked\n"
        )
        self._assert_fails(fixture, "cargo-deny CI")

    # --- Tauri CLI source and lock bindings --------------------------------

    def test_xcodegen_patch_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.xcodegen_patch = b"tampered XcodeGen patch\n"
        self._assert_fails(fixture, "XcodeGen patch file digest")

    def test_xcodegen_bootstrap_must_apply_pinned_patch(self) -> None:
        fixture = Fixture()
        fixture.xcodegen_bootstrap = fixture.xcodegen_bootstrap.replace(
            '/usr/bin/git -C "$payload/source" apply --check "$xcodegen_patch"',
            "true",
        )
        self._assert_fails(fixture, "XcodeGen bootstrap lacks required pinned fragment")

    def test_tauri_cli_crate_digest_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.env["TAURI_CLI_CRATE_SHA256"] = "a" * 64
        self._assert_fails(fixture, "Tauri CLI crate digest")

    def test_tauri_cli_lock_patch_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.tauri_lock_patch = b"tampered tauri-cli lock patch\n"
        self._assert_fails(fixture, "lock patch digest")

    def test_tauri_cache_contract_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.extra_artifact_files[TAURI_CACHE_CONTRACT_PATH] = "tampered contract\n"
        self._assert_fails(fixture, "cache contract file digest")

    def test_tauri_cache_contract_env_digest_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.env["TAURI_CARGO_CACHE_CONTRACT_SHA256"] = "a" * 64
        self._assert_fails(fixture, "cache contract digest")

    def test_tauri_cache_contract_manifest_digest_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["tauriCli"]["cacheContractSha256"] = "a" * 64
        self._assert_fails(fixture, "cache contract digest")

    def test_tauri_cache_contract_path_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.manifest["tauriCli"]["cacheContractPath"] = "scripts/other.py"
        self._assert_fails(fixture, "cache contract is missing")

    def test_tauri_cache_contract_wrapper_cannot_be_noop(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            'cfw_run_release_python_script "$repo_root" "$cargo_cache_contract" '
            '    normalize-offline "$root"',
            "true",
        )
        self._assert_fails(fixture, "exact occurrences|required pinned fragment")

    def test_tauri_cache_contract_operation_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            'normalize-offline "$root"',
            'validate-preparation "$root"',
        )
        self._assert_fails(fixture, "exact occurrences|required pinned fragment")

    def test_tauri_cli_installer_must_normalize_before_and_after_install(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            'normalize_cargo_offline_cache "$offline_cargo_home"',
            "true",
            1,
        )
        self._assert_fails(fixture, "exact occurrences")

    def test_tauri_cli_installer_rejects_misordered_normalization(self) -> None:
        fixture = Fixture()
        call = 'normalize_cargo_offline_cache "$offline_cargo_home"'
        fixture.tauri_installer = fixture.tauri_installer.replace(call, "", 2)
        fixture.tauri_installer = fixture.tauri_installer.replace(
            '/usr/bin/ditto --noqtn "$prepared_cargo_home" "$offline_cargo_home"',
            '/usr/bin/ditto --noqtn "$prepared_cargo_home" "$offline_cargo_home"\n'
            f"{call}\n{call}",
        )
        self._assert_fails(fixture, "lacks ordered operation")

    def test_tauri_cli_installer_must_keep_fetch_and_install_warning_gates(self) -> None:
        for warning_gate in (
            'reject_cargo_warnings "$fetch_log" "Tauri CLI dependency preparation"',
            'reject_cargo_warnings "$install_log" "tauri-cli installation"',
        ):
            with self.subTest(warning_gate=warning_gate):
                fixture = Fixture()
                fixture.tauri_installer = fixture.tauri_installer.replace(
                    warning_gate,
                    "true",
                )
                self._assert_fails(fixture, "required pinned fragment|exact occurrences")

    def test_tauri_cli_installer_must_keep_locked_path_install(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace("--locked", "--offline")
        self._assert_fails(fixture, "required pinned fragment '--locked'")

    def test_tauri_cli_installer_must_isolate_cargo_home(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            'CARGO_HOME="$offline_cargo_home"', 'CARGO_HOME="$HOME/.cargo"'
        )
        self._assert_fails(fixture, "required pinned fragment 'CARGO_HOME")

    def test_tauri_cli_installer_must_isolate_network_preparation(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            'CARGO_HOME="$prepared_cargo_home"', 'CARGO_HOME="$HOME/.cargo"'
        )
        self._assert_fails(fixture, "required pinned fragment 'CARGO_HOME")

    def test_tauri_cli_installer_must_compile_offline(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace("--offline", "--frozen")
        self._assert_fails(fixture, "required pinned fragment '--offline'")

    def test_tauri_cli_installer_must_fail_fast_on_network_drift(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            "CARGO_NET_RETRY=0", "CARGO_NET_RETRY=10"
        )
        self._assert_fails(fixture, "required pinned fragment 'CARGO_NET_RETRY=0'")

    def test_tauri_cli_installer_must_separate_payload_from_source(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            'payload="$staging/payload/tauri-cli-$TAURI_CLI_VERSION"',
            'payload="$source_root"',
        )
        self._assert_fails(fixture, "required pinned fragment 'payload=")

    def test_ci_direct_tauri_cli_install_fails(self) -> None:
        fixture = Fixture()
        fixture.ci_workflow += "run: cargo install tauri-cli --version 2.11.4\n"
        self._assert_fails(fixture, "floating direct Tauri CLI installation")

    # --- patch digest failures ----------------------------------------------

    def test_wrong_patch_env_digest_fails(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_DNS_FAILOVER_PATCH_SHA256"] = "a" * 64
        self._assert_fails(fixture, "DNS failover")

    def test_wrong_endpoint_conflict_patch_env_digest_fails(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256"] = "a" * 64
        self._assert_fails(fixture, "endpoint conflict")

    def test_patch_file_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.patch_bodies["security"] = b"tampered body\n"
        self._assert_fails(fixture, "file digest")

    def test_missing_patch_file_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.patch_bodies["raw"]
        self._assert_fails(fixture, "missing, a symlink, or has an unsafe path")

    def test_coordinated_patch_policy_replacement_fails_fixed_policy(self) -> None:
        fixture = Fixture()
        replacement = "synthetic unrelated patch policy body\n"
        replacement_sha256 = _sha(replacement.encode("utf-8"))
        fixture.env["UNRELATED_PATCH_PATH"] = "scripts/unrelated.patch"
        fixture.env["UNRELATED_PATCH_SHA256"] = replacement_sha256
        fixture.extra_artifact_files["scripts/unrelated.patch"] = replacement
        fixture.manifest["patches"][3] = {
            "name": "unrelated replacement patch",
            "pathKey": "UNRELATED_PATCH_PATH",
            "sha256Key": "UNRELATED_PATCH_SHA256",
            "sha256": replacement_sha256,
        }
        self._assert_fails(fixture, "fixed patch policy set")

    def test_legacy_partial_digest_rejected(self) -> None:
        # Point the raw-packet patch entirely at the rejected legacy digest.
        fixture = Fixture()
        rejected_digest = REJECTED_PATCH_DIGESTS[0]
        fixture.env["SING_BOX_RAW_PACKET_PATCH_SHA256"] = rejected_digest
        fixture.manifest["patches"][1]["sha256"] = rejected_digest
        fixture.lock["singBox"]["rawPacketPatch"]["sha256"] = rejected_digest
        self._assert_fails(fixture, "rejected/legacy digest")

    def test_rejected_patch_digest_policy_cannot_be_disabled_or_malformed(self) -> None:
        invalid_values = (
            None,
            [],
            {},
            [REJECTED_PATCH_DIGESTS[0]],
            [
                REJECTED_PATCH_DIGESTS[0],
                REJECTED_PATCH_DIGESTS[0],
                REJECTED_PATCH_DIGESTS[2],
                REJECTED_PATCH_DIGESTS[3],
            ],
            [
                REJECTED_PATCH_DIGESTS[0],
                REJECTED_PATCH_DIGESTS[1],
                REJECTED_PATCH_DIGESTS[2],
                "not-a-digest",
            ],
            ["a" * 64, "b" * 64, "c" * 64, "d" * 64],
        )
        for value in invalid_values:
            with self.subTest(value=value):
                fixture = Fixture()
                fixture.manifest["rejectedPatchDigests"] = value
                self._assert_fails(fixture, "rejected patch")

    def test_combined_diff_equal_to_patch_rejected(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_COMBINED_DIFF_SHA256"] = SECURITY_SHA
        fixture.manifest["combinedDiffSha256"] = SECURITY_SHA
        fixture.lock["singBox"]["combinedDiffSha256"] = SECURITY_SHA
        self._assert_fails(fixture, "partial")

    # --- libbox build tags --------------------------------------------------

    def test_missing_engine_start_path_tag_fails(self) -> None:
        # The exact defect this check exists for: dropping with_clash_api while the
        # projection still injects experimental.clash_api, which makes box.New fail
        # on every engine start.
        fixture = Fixture()
        reduced = "with_quic,with_utls,badlinkname,tfogo_checklinkname0,grpcnotrace"
        fixture.env["LIBBOX_BUILD_TAGS"] = reduced
        fixture.manifest["libboxBuildTags"]["value"] = reduced
        self._assert_fails(fixture, "required tag 'with_clash_api'")

    def test_tag_list_drift_from_manifest_fails(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_BUILD_TAGS"] = "with_quic,grpcnotrace"
        self._assert_fails(fixture, "pinned libbox build tags LIBBOX_BUILD_TAGS")

    def test_missing_tag_pin_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.env["LIBBOX_BUILD_TAGS"]
        self._assert_fails(fixture, "LIBBOX_BUILD_TAGS")

    def test_malformed_tag_fails(self) -> None:
        fixture = Fixture()
        malformed = "with_quic, with_clash_api,grpcnotrace"
        fixture.env["LIBBOX_BUILD_TAGS"] = malformed
        fixture.manifest["libboxBuildTags"]["value"] = malformed
        self._assert_fails(fixture, "malformed")

    def test_repeated_tag_fails(self) -> None:
        fixture = Fixture()
        repeated = "with_quic,with_clash_api,grpcnotrace,with_quic"
        fixture.env["LIBBOX_BUILD_TAGS"] = repeated
        fixture.manifest["libboxBuildTags"]["value"] = repeated
        self._assert_fails(fixture, "repeat")

    def test_coordinated_build_tag_deletion_still_fails_fixed_policy(self) -> None:
        fixture = Fixture()
        reduced = BUILD_TAGS.replace("with_quic,", "", 1)
        fixture.env["LIBBOX_BUILD_TAGS"] = reduced
        fixture.manifest["libboxBuildTags"]["value"] = reduced
        fixture.manifest["libboxBuildTags"]["required"] = [
            entry
            for entry in fixture.manifest["libboxBuildTags"]["required"]
            if entry["tag"] != "with_quic"
        ]
        self._assert_fails(fixture, "differ from release policy")

    def test_same_cardinality_build_tag_replacement_fails_fixed_policy(self) -> None:
        fixture = Fixture()
        replaced = BUILD_TAGS.replace("with_quic", "with_fake", 1)
        fixture.env["LIBBOX_BUILD_TAGS"] = replaced
        fixture.manifest["libboxBuildTags"]["value"] = replaced
        fixture.manifest["libboxBuildTags"]["required"][0]["tag"] = "with_fake"
        self._assert_fails(fixture, "differ from release policy")

    def test_source_binding_without_required_tag_fails(self) -> None:
        # A source trigger may not be satisfied by the required-tag table alone:
        # removing the tag from both the pin and the required table still fails
        # because the tracked source still needs it.
        fixture = Fixture()
        reduced = "with_quic,with_utls,badlinkname,tfogo_checklinkname0,grpcnotrace"
        fixture.env["LIBBOX_BUILD_TAGS"] = reduced
        fixture.manifest["libboxBuildTags"]["value"] = reduced
        fixture.manifest["libboxBuildTags"]["required"] = [
            entry
            for entry in fixture.manifest["libboxBuildTags"]["required"]
            if entry["tag"] != "with_clash_api"
        ]
        self._assert_fails(fixture, "requires libbox build tag 'with_clash_api'")

    def test_vanished_source_trigger_fails(self) -> None:
        fixture = Fixture()
        fixture.controller_source = "fn experimental_value() {}\n"
        self._assert_fails(fixture, "no longer contains the pinned tag trigger")

    def test_missing_tag_binding_section_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.manifest["libboxBuildTags"]
        self._assert_fails(fixture, "exact top-level shape")

    def test_required_tag_without_reason_fails(self) -> None:
        fixture = Fixture()
        del fixture.manifest["libboxBuildTags"]["required"][1]["reason"]
        self._assert_fails(fixture, "required-tag entry is malformed")

    def test_engine_start_bindings_cannot_be_disabled_or_partial(self) -> None:
        invalid_values = (
            None,
            [],
            {},
            [Fixture().manifest["libboxBuildTags"]["engineStartPathBindings"][0]],
        )
        for value in invalid_values:
            with self.subTest(value=value):
                fixture = Fixture()
                fixture.manifest["libboxBuildTags"]["engineStartPathBindings"] = value
                self._assert_fails(fixture, "engine-start|source bindings")

    def test_engine_start_binding_schema_and_trigger_are_strict(self) -> None:
        fixture = Fixture()
        fixture.manifest["libboxBuildTags"]["engineStartPathBindings"][0][
            "triggerRequired"
        ] = False
        self._assert_fails(fixture, "must require its trigger")

        fixture = Fixture()
        del fixture.manifest["libboxBuildTags"]["engineStartPathBindings"][0][
            "reason"
        ]
        self._assert_fails(fixture, "source binding is malformed")

        fixture = Fixture()
        fixture.manifest["libboxBuildTags"]["engineStartPathBindings"].pop()
        self._assert_fails(fixture, "fixed engine-start paths")

    # --- malformed / unavailable inputs -------------------------------------

    def test_malformed_env_line_fails(self) -> None:
        fixture = Fixture()
        fixture.append_env_text("this is not a valid pin line\n")
        self._assert_fails(fixture, "malformed")

    def test_missing_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).unlink()
            with self.assertRaisesRegex(PinnedInputError, "manifest is missing"):
                verify(root)

    def test_malformed_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(PinnedInputError, "malformed"):
                verify(root)

    def test_manifest_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        for replacement, pattern in (
            ('"description":NaN', "non-finite"),
            ('"description":Infinity', "non-finite"),
            ('"description":-Infinity', "non-finite"),
            ('"description":1e999', "non-finite"),
            ('"description":1.5', "unsupported floating-point"),
            ('"description":99999999999999999999', "out-of-range"),
        ):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                root = Fixture().write(Path(temporary))
                path = root / MANIFEST_RELATIVE_PATH
                body = path.read_text(encoding="utf-8")
                body = body.replace(
                    '"description": "synthetic pinned build inputs"', replacement, 1
                )
                path.write_text(body, encoding="utf-8")
                with self.assertRaisesRegex(PinnedInputError, pattern):
                    verify(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            path = root / MANIFEST_RELATIVE_PATH
            body = path.read_text(encoding="utf-8")
            path.write_text(
                '{"schema":"cfw-pinned-build-inputs-v1",' + body[1:],
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PinnedInputError, "duplicate JSON field 'schema'"):
                verify(root)

    def test_manifest_rejects_non_utf8_oversize_and_inexact_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).write_bytes(b"\xff")
            with self.assertRaisesRegex(PinnedInputError, "strict UTF-8"):
                verify(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).write_bytes(
                b" " * (MAX_PINNED_MANIFEST_BYTES + 1)
            )
            with self.assertRaisesRegex(PinnedInputError, "byte bound"):
                verify(root)

        fixture = Fixture()
        fixture.manifest["unexpected"] = True
        self._assert_fails(fixture, "exact top-level shape")

    def test_manifest_rejects_hardlink_symlink_and_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            manifest = root / MANIFEST_RELATIVE_PATH
            os.link(manifest, root / "manifest-hardlink.json")
            with self.assertRaisesRegex(PinnedInputError, "exactly one hard link"):
                verify(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            manifest = root / MANIFEST_RELATIVE_PATH
            manifest.unlink()
            manifest.symlink_to(root / "scripts/dependency_pins.env")
            with self.assertRaisesRegex(PinnedInputError, "symlink|unsafe path"):
                verify(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            manifest_body = (root / MANIFEST_RELATIVE_PATH).read_bytes()
            real_open = os.open
            scripts_opens = 0

            def swap_parent_on_rebind(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal scripts_opens
                if path == "scripts" and dir_fd is not None and flags & os.O_DIRECTORY:
                    scripts_opens += 1
                    if scripts_opens == 2:
                        (root / "scripts").rename(root / "scripts-before-swap")
                        (root / "scripts").mkdir()
                        (root / MANIFEST_RELATIVE_PATH).write_bytes(manifest_body)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch(
                    "scripts.verify_pinned_build_inputs.os.open",
                    side_effect=swap_parent_on_rebind,
                ),
                self.assertRaisesRegex(PinnedInputError, "parent|changed"),
            ):
                verify(root)

    def test_native_lock_strict_json_and_identity_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture()
            root = fixture.write(Path(temporary))
            lock = root / "native/macos/Dependencies.lock.json"
            body = lock.read_text(encoding="utf-8")
            lock.write_text('{"go":"1.26.6",' + body[1:], encoding="utf-8")
            with self.assertRaisesRegex(PinnedInputError, "duplicate JSON field 'go'"):
                self._verify_written_fixture(fixture, root)

        fixture = Fixture()
        fixture.lock["unexpected"] = True
        self._assert_fails(fixture, "exact top-level shape")

        fixture = Fixture()
        fixture.lock["go"] = float("nan")
        self._assert_fails(fixture, "non-finite")

        fixture = Fixture()
        fixture.lock["singBox"]["unexpected"] = True
        self._assert_fails(fixture, "singBox table has an inexact shape")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture()
            root = fixture.write(Path(temporary))
            lock = root / "native/macos/Dependencies.lock.json"
            os.link(lock, root / "native-lock-hardlink.json")
            with self.assertRaisesRegex(PinnedInputError, "exactly one hard link"):
                self._verify_written_fixture(fixture, root)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture()
            root = fixture.write(Path(temporary))
            lock = root / "native/macos/Dependencies.lock.json"
            lock.write_bytes(b"\xff")
            with self.assertRaisesRegex(PinnedInputError, "strict UTF-8"):
                self._verify_written_fixture(fixture, root)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture()
            root = fixture.write(Path(temporary))
            lock = root / "native/macos/Dependencies.lock.json"
            lock.write_bytes(b" " * (MAX_NATIVE_LOCK_BYTES + 1))
            with self.assertRaisesRegex(PinnedInputError, "byte bound"):
                self._verify_written_fixture(fixture, root)

    def test_build_script_hardlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture()
            root = fixture.write(Path(temporary))
            script = root / "scripts/build_libbox.sh"
            os.link(script, root / "build-libbox-hardlink.sh")
            with self.assertRaisesRegex(PinnedInputError, "exactly one hard link"):
                self._verify_written_fixture(fixture, root)

    # --- native lock and build-script bindings ------------------------------

    def test_native_lock_mismatch_fails(self) -> None:
        fixture = Fixture()
        fixture.lock["singBox"]["rawPacketPatch"]["sha256"] = "b" * 64
        self._assert_fails(fixture, "rawPacketPatch")

    def test_endpoint_conflict_native_lock_mismatch_fails(self) -> None:
        fixture = Fixture()
        fixture.lock["singBox"]["endpointConflictPatch"]["sha256"] = "b" * 64
        self._assert_fails(fixture, "endpointConflictPatch")

    def test_build_script_missing_pin_reference_fails(self) -> None:
        fixture = Fixture()
        fixture.build_libbox = fixture.build_libbox.replace("$SING_BOX_COMMIT", "3708fa18")
        self._assert_fails(fixture, "floating version|artifact-hash")

    def test_build_script_network_action_fails(self) -> None:
        fixture = Fixture()
        fixture.build_libbox += "git clone https://example.com/sing-box\n"
        self._assert_fails(fixture, "network or recursive")

    def test_build_script_policy_set_cannot_be_disabled_or_replaced(self) -> None:
        canonical_rules = Fixture().manifest["buildScripts"]["scripts/build_libbox.sh"]
        invalid_values = (
            None,
            {},
            [],
            {"scripts/unrelated.sh": canonical_rules},
        )
        for value in invalid_values:
            with self.subTest(value=value):
                fixture = Fixture()
                fixture.manifest["buildScripts"] = value
                self._assert_fails(fixture, "fixed build-script policy set")

    def test_build_script_policy_schema_cannot_weaken_checks(self) -> None:
        mutations = (
            lambda rules: rules.clear(),
            lambda rules: rules.pop("requirePinReferences"),
            lambda rules: rules.update(requirePinReferences=[]),
            lambda rules: rules.update(requirePinReferences=None),
            lambda rules: rules["requirePinReferences"].pop(),
            lambda rules: rules.update(forbidNetworkRecursion=False),
            lambda rules: rules.update(forbidNetworkRecursion=None),
            lambda rules: rules.update(unexpected=True),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                fixture = Fixture()
                rules = fixture.manifest["buildScripts"]["scripts/build_libbox.sh"]
                mutate(rules)
                self._assert_fails(
                    fixture,
                    "build-script policy|required pin references|pin-reference policy|"
                    "must forbid network",
                )

    def test_missing_artifact_binding_fails(self) -> None:
        fixture = Fixture()
        fixture.build_native = '#!/usr/bin/env bash\necho "no binding"\n'
        self._assert_fails(fixture, "artifact source digest|artifact-hash binding")

    def test_artifact_binding_policy_cannot_delete_one_path(self) -> None:
        fixture = Fixture()
        missing = sorted(fixture.manifest["artifactBindings"])[0]
        del fixture.manifest["artifactBindings"][missing]
        self._assert_fails(fixture, "artifact bindings differ from release policy")

    def test_artifact_binding_policy_cannot_delete_one_fragment(self) -> None:
        fixture = Fixture()
        bindings = fixture.manifest["artifactBindings"][
            "scripts/notarization_transaction.py"
        ]
        bindings.pop()
        self._assert_fails(fixture, "artifact bindings differ from release policy")

    def test_artifact_source_digest_policy_cannot_delete_or_change_one_path(self) -> None:
        fixture = Fixture()
        relative = sorted(fixture.manifest["artifactSourceSha256"])[0]
        del fixture.manifest["artifactSourceSha256"][relative]
        self._assert_fails(fixture, "artifact source digest map")

        fixture = Fixture()
        relative = sorted(fixture.manifest["artifactSourceSha256"])[0]
        fixture.manifest["artifactSourceSha256"][relative] = "0" * 64
        self._assert_fails(fixture, "artifact source digest map identity")

    def test_dependency_pins_path_cannot_redirect(self) -> None:
        fixture = Fixture()
        fixture.manifest["dependencyPinsPath"] = "scripts/alternate-pins.env"
        self._assert_fails(fixture, "dependency pins path differs from release policy")

    def test_native_lock_path_cannot_redirect(self) -> None:
        fixture = Fixture()
        fixture.manifest["nativeLockPath"] = "native/macos/Alternate.lock.json"
        self._assert_fails(fixture, "native lock path differs from release policy")

    def test_ci_unsigned_python_must_match_the_dependency_pin(self) -> None:
        fixture = Fixture()
        fixture.env["PYTHON_VERSION"] = "3.14.6"
        fixture.manifest["tools"]["PYTHON_VERSION"] = "3.14.6"
        self._verify_fixture(fixture)

        fixture.ci_workflow = fixture.ci_workflow.replace(
            'python-version: "3.14.6"', 'python-version: "3.14.7"'
        )
        self._assert_fails(
            fixture,
            "artifact source digest|Python version does not exactly match",
        )

    def test_release_workflow_cannot_add_an_unreviewed_job(self) -> None:
        fixture = Fixture()
        fixture.env["PYTHON_VERSION"] = "3.14.6"
        fixture.manifest["tools"]["PYTHON_VERSION"] = "3.14.6"
        fixture.ci_workflow += """
  release-two:
    runs-on: macos-26
    timeout-minutes: 60
    steps:
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405
        id: validation-python
        with:
          python-version: "3.14.6"
          architecture: arm64
          update-environment: false
      - run: ./scripts/run_release_ci_gate.sh --validation-python-executable '${{ steps.validation-python.outputs.python-path }}' rust-test
"""
        self._assert_fails(fixture, "artifact source digest")

    def test_libbox_exact_contract_missing_metadata_binding_fails(self) -> None:
        fixture = Fixture()
        fixture.libbox_contract = fixture.libbox_contract.replace(
            "patchedGoSumSha256=$SING_BOX_PATCHED_GO_SUM_SHA256", "missing-binding"
        )
        self._assert_fails(fixture, "artifact source digest|artifact-hash binding")

    def test_production_orchestrator_binding_drift_fails(self) -> None:
        fixture = Fixture()
        path = "scripts/publication/orchestrator.py"
        self._verify_fixture(fixture)
        fixture.extra_artifact_files[path] = fixture.extra_artifact_files[path].replace(
            "require_verified=True", "require_verified=False"
        )
        self._assert_fails(fixture, "artifact source digest")

    def test_python_artifact_binding_cannot_be_satisfied_by_a_comment(self) -> None:
        fixture = Fixture()
        path = "scripts/evidence_manifest.py"
        binding = 'type(document["schema_version"]) is not int'
        source = fixture.extra_artifact_files[path]
        self.assertIn(binding, source)
        fixture.extra_artifact_files[path] = source.replace(
            binding,
            'not isinstance(document["schema_version"], int)',
            1,
        ) + f"\n# {binding}\n"
        binding_surface = pinned_verifier._artifact_binding_surface(
            fixture.extra_artifact_files[path],
            path,
        )
        self.assertNotIn(binding, binding_surface)
        self._assert_fails(fixture, "artifact source digest")

    def test_artifact_source_digest_rejects_shell_comment_only_binding(self) -> None:
        fixture = Fixture()
        binding = "/usr/bin/xcodebuild build"
        self.assertIn(binding, fixture.build_native)
        fixture.build_native = fixture.build_native.replace(
            binding,
            "/usr/bin/xcodebuild analyze",
            1,
        ) + f"\n# {binding}\n"
        self._assert_fails(fixture, "artifact source digest")

    def test_artifact_source_digest_rejects_python_dead_string_binding(self) -> None:
        fixture = Fixture()
        path = "scripts/evidence_manifest.py"
        binding = 'type(document["schema_version"]) is not int'
        source = fixture.extra_artifact_files[path]
        fixture.extra_artifact_files[path] = source.replace(
            binding,
            'not isinstance(document["schema_version"], int)',
            1,
        ) + f"\nDEAD_POLICY_TEXT = {binding!r}\n"
        self._assert_fails(fixture, "artifact source digest")

    def test_final_input_guard_cannot_be_removed_and_retained_as_a_comment(self) -> None:
        fixture = Fixture()
        path = "scripts/publication/orchestrator.py"
        source = fixture.extra_artifact_files[path]
        guarded_publish = (
            "    _require_final_inputs_unchanged(context, physical_candidate_manifest)\n"
            "    final_guard = _observe_signed_app_tree(context)"
        )
        self.assertIn(guarded_publish, source)
        fixture.extra_artifact_files[path] = source.replace(
            guarded_publish,
            "    pass\n    final_guard = _observe_signed_app_tree(context)",
            1,
        ) + "\n# _require_final_inputs_unchanged(context, physical_candidate_manifest)\n"
        with self.assertRaisesRegex(PinnedInputError, "release guard calls"):
            pinned_verifier._artifact_binding_surface(
                fixture.extra_artifact_files[path],
                path,
            )
        self._assert_fails(fixture, "artifact source digest")

    def test_self_excluded_verifier_still_requires_real_entrypoints(self) -> None:
        fixture = Fixture()
        path = "scripts/verify_pinned_build_inputs.py"
        source = fixture.extra_artifact_files[path]
        binding = "def verify_source_contract(repository: Path) -> None:"
        self.assertIn(binding, source)
        fixture.extra_artifact_files[path] = source.replace(
            binding,
            "def disabled_source_contract(repository: Path) -> None:",
            1,
        ) + f"\nDEAD_POLICY_TEXT = {binding!r}\n"
        with self.assertRaisesRegex(PinnedInputError, "entrypoint structure"):
            pinned_verifier._artifact_binding_surface(
                fixture.extra_artifact_files[path],
                path,
            )
        self._assert_fails(fixture, "entrypoint structure")

    def test_real_manifest_pins_complete_production_orchestrator_surface(self) -> None:
        manifest = json.loads((REPO_ROOT / MANIFEST_RELATIVE_PATH).read_text(encoding="utf-8"))
        bindings = manifest["artifactBindings"]
        self.assertEqual(
            set(manifest["artifactSourceSha256"]),
            set(bindings) - {"scripts/verify_pinned_build_inputs.py"},
        )
        for path in (
            "scripts/release_capability_inventory.json",
            "scripts/release_capability_inventory.py",
            "scripts/publication/orchestrator.py",
            "scripts/production_release_evidence.py",
            "scripts/publication/sealed_manifest.py",
        ):
            self.assertIn(path, bindings)
            self.assertTrue(bindings[path])


if __name__ == "__main__":
    unittest.main()
