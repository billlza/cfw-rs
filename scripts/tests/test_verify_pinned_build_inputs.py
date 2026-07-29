from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_pinned_build_inputs import (
    MANIFEST_RELATIVE_PATH,
    PinnedInputError,
    verify,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


# Synthetic, self-consistent patch bodies. Their real SHA-256 digests drive the
# generated manifest, env, and lock so the verifier logic can be exercised without
# needing SHA-256 preimages of the shipped design pins.
PATCH_BODIES = {
    "security": b"synthetic security dependencies patch body\n",
    "raw": b"synthetic raw packet tun patch body\n",
    "dns": b"synthetic dns failover patch body\n",
}
LEGACY_BODY = b"synthetic legacy partial digest body\n"
TAURI_LOCK_PATCH_BODY = b"synthetic tauri-cli spin lock patch body\n"
XCODEGEN_PATCH_BODY = b"synthetic XcodeGen installed-resource patch body\n"

SECURITY_SHA = _sha(PATCH_BODIES["security"])
RAW_SHA = _sha(PATCH_BODIES["raw"])
DNS_SHA = _sha(PATCH_BODIES["dns"])
COMBINED_SHA = _sha(b"synthetic combined diff body\n")
LEGACY_SHA = _sha(LEGACY_BODY)
TAURI_CRATE_SHA = _sha(b"synthetic official tauri-cli crate archive")
TAURI_UPSTREAM_LOCK_SHA = _sha(b"synthetic upstream tauri-cli Cargo.lock")
TAURI_LOCK_PATCH_SHA = _sha(TAURI_LOCK_PATCH_BODY)
TAURI_PATCHED_LOCK_SHA = _sha(b"synthetic patched tauri-cli Cargo.lock")
TAURI_SPIN_SHA = _sha(b"synthetic spin crate")
XCODEGEN_PATCH_SHA = _sha(XCODEGEN_PATCH_BODY)
XCODEGEN_PATCHED_SETTINGS_SHA = _sha(b"synthetic patched SettingsBuilder.swift")
COMMIT = "25a600db24f7680ad9806ce5427bd0ab8afe1114"
GOMOBILE_COMMIT = "9f03b8f25789099c5c8abef4a02085da783ba923"
TAURI_PATCH_PATH = "scripts/tauri-cli-spin.patch"
XCODEGEN_PATCH_PATH = "scripts/xcodegen-installed-resources.patch"

PATCH_PATHS = {
    "security": "native/macos/patches/security.patch",
    "raw": "native/macos/patches/raw-packet.patch",
    "dns": "native/macos/patches/dns-failover.patch",
}

BUILD_LIBBOX = """\
#!/usr/bin/env bash
set -euo pipefail
echo "$GO_VERSION $GOMOBILE_VERSION $GOMOBILE_COMMIT $GOMOBILE_MODULE_SUM $SING_BOX_VERSION $SING_BOX_COMMIT"
python3 hash_artifact.py "$out" \\
  --metadata "sourceCommit=$SING_BOX_COMMIT" \\
  --metadata "gomobileCommit=$GOMOBILE_COMMIT" \\
  --metadata "gomobileModuleSum=$GOMOBILE_MODULE_SUM" \\
  --metadata "securityPatchSha256=$SING_BOX_SECURITY_PATCH_SHA256" \\
  --metadata "rawPacketPatchSha256=$SING_BOX_RAW_PACKET_PATCH_SHA256" \\
  --metadata "dnsFailoverPatchSha256=$SING_BOX_DNS_FAILOVER_PATCH_SHA256" \\
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
BUILD_TAGS = "with_quic,with_clash_api,grpcnotrace"
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
git apply --unidiff-zero "$TAURI_CLI_LOCK_PATCH_PATH"
rustup which --toolchain "$rust_toolchain" cargo
/usr/bin/env -i CARGO_HOME="$prepared_cargo_home" \
  CARGO_HTTP_LOW_SPEED_LIMIT=1 CARGO_HTTP_MULTIPLEXING=true \
  CARGO_HTTP_TIMEOUT=600 CARGO_NET_RETRY=3 \
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse RUSTC="$rustc_bin" \
  cargo fetch --manifest-path "$cargo_manifest" --locked \
  --target aarch64-apple-darwin
/usr/bin/ditto --noqtn "$prepared_cargo_home" "$offline_cargo_home"
cfw_verify_release_toolchain_manifest
/usr/bin/env -i CARGO_HOME="$offline_cargo_home" CARGO_TARGET_DIR="$cargo_target" \
  CARGO_NET_OFFLINE=true CARGO_NET_RETRY=0 \
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse RUSTC="$rustc_bin" \
  cargo install --path "$source_root" --offline --locked \
  --target aarch64-apple-darwin
echo "tauri-cli-$TAURI_CLI_VERSION"
readonly payload="$staging/payload/tauri-cli-$TAURI_CLI_VERSION"
/bin/mv "$source_root" "$payload/source"
/usr/bin/lipo -archs "$payload/bin/cargo-tauri"
echo "--algorithm sha256-tree-v2"
echo "artifactKind=pinned-tauri-cli-v2"
echo "dependencyMode=isolated-fetch-offline-locked-v1"
echo "macosDeploymentTarget=$MACOS_DEPLOYMENT_TARGET"
echo "payloadLayout=bin-and-patched-source-v1"
echo "xcodeBuild=$XCODE_BUILD_VERSION"
echo "xcodeVersion=$XCODE_VERSION"
echo "cfw_verify_tauri_toolchain_tree"
"""
CI_WORKFLOW = """\
run: cargo install cargo-deny --version "$CARGO_DENY_VERSION" --locked
run: cargo deny --locked --target aarch64-apple-darwin check
run: ./scripts/install_pinned_tauri_cli.sh
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
            "RUST_VERSION": "1.97.1",
            "CARGO_DENY_VERSION": "0.20.2",
            "XCODEGEN_VERSION": "2.46.0",
            "XCODEGEN_COMMIT": "8445e778451c7e44237b90281bde622d764b0084",
            "XCODEGEN_SOURCE_SHA256": "a3270d0e5fce8f4dc2aa1801b0d932f6561cd24c0735e718d2455896b2359142",
            "XCODEGEN_PACKAGE_RESOLVED_SHA256": "2f0b0265e33ab55bbc6cab8ad209afa85821064a2cb6fe4a1df07b642f7cebcd",
            "XCODEGEN_PATCH_PATH": XCODEGEN_PATCH_PATH,
            "XCODEGEN_PATCH_SHA256": XCODEGEN_PATCH_SHA,
            "XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256": XCODEGEN_PATCHED_SETTINGS_SHA,
            "NODE_VERSION": "24.18.0",
            "GO_VERSION": "1.26.5",
            "TAURI_CLI_VERSION": "2.11.4",
            "TAURI_CLI_CRATE_SHA256": TAURI_CRATE_SHA,
            "TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256": TAURI_UPSTREAM_LOCK_SHA,
            "TAURI_CLI_LOCK_PATCH_PATH": TAURI_PATCH_PATH,
            "TAURI_CLI_LOCK_PATCH_SHA256": TAURI_LOCK_PATCH_SHA,
            "TAURI_CLI_PATCHED_CARGO_LOCK_SHA256": TAURI_PATCHED_LOCK_SHA,
            "TAURI_CLI_SPIN_VERSION": "0.9.9",
            "TAURI_CLI_SPIN_CRATE_SHA256": TAURI_SPIN_SHA,
            "GOMOBILE_VERSION": "v0.1.13",
            "GOMOBILE_COMMIT": GOMOBILE_COMMIT,
            "GOMOBILE_MODULE_SUM": "h1:foTOGKJetah9VwaJl1XJx5TswIAVg8NfYmHOhrOc95I=",
            "GOVULNCHECK_VERSION": "v1.6.0",
            "GOVULNCHECK_MODULE_SUM": "h1:FeMO9Rm/HwyduOztbvKcOw+zvDEPr4I4aQNSfevFcKY=",
            "SING_BOX_VERSION": "v1.13.14",
            "SING_BOX_COMMIT": COMMIT,
            "SING_BOX_UPSTREAM_GO_MOD_SHA256": _sha(b"upstream go.mod"),
            "SING_BOX_UPSTREAM_GO_SUM_SHA256": _sha(b"upstream go.sum"),
            "SING_BOX_SECURITY_PATCH_PATH": PATCH_PATHS["security"],
            "SING_BOX_SECURITY_PATCH_SHA256": SECURITY_SHA,
            "SING_BOX_RAW_PACKET_PATCH_PATH": PATCH_PATHS["raw"],
            "SING_BOX_RAW_PACKET_PATCH_SHA256": RAW_SHA,
            "SING_BOX_DNS_FAILOVER_PATCH_PATH": PATCH_PATHS["dns"],
            "SING_BOX_DNS_FAILOVER_PATCH_SHA256": DNS_SHA,
            "SING_BOX_PATCHED_DIFF_SHA256": SECURITY_SHA,
            "SING_BOX_COMBINED_DIFF_SHA256": COMBINED_SHA,
            "SING_BOX_PATCHED_GO_MOD_SHA256": _sha(b"patched go.mod"),
            "SING_BOX_PATCHED_GO_SUM_SHA256": _sha(b"patched go.sum"),
            "LIBBOX_BUILD_TAGS": BUILD_TAGS,
        }
        self.patch_bodies = dict(PATCH_BODIES)
        self.controller_source = CONTROLLER_SOURCE
        self.manifest = {
            "schema": "cfw-pinned-build-inputs-v1",
            "dependencyPinsPath": "scripts/dependency_pins.env",
            "nativeLockPath": "native/macos/Dependencies.lock.json",
            "tools": {
                "RUST_VERSION": "1.97.1",
                "CARGO_DENY_VERSION": "0.20.2",
                "XCODEGEN_VERSION": "2.46.0",
                "XCODEGEN_COMMIT": "8445e778451c7e44237b90281bde622d764b0084",
                "XCODEGEN_SOURCE_SHA256": "a3270d0e5fce8f4dc2aa1801b0d932f6561cd24c0735e718d2455896b2359142",
                "XCODEGEN_PACKAGE_RESOLVED_SHA256": "2f0b0265e33ab55bbc6cab8ad209afa85821064a2cb6fe4a1df07b642f7cebcd",
                "NODE_VERSION": "24.18.0",
                "GO_VERSION": "1.26.5",
                "GOMOBILE_VERSION": "v0.1.13",
                "GOVULNCHECK_VERSION": "v1.6.0",
                "TAURI_CLI_VERSION": "2.11.4",
                "SING_BOX_VERSION": "v1.13.14",
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
                    'cargo install cargo-deny --version "$CARGO_DENY_VERSION" --locked',
                    "cargo deny --locked --target aarch64-apple-darwin check",
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
                "ciWorkflowPath": ".github/workflows/ci.yml",
                "requiredCiFragment": "./scripts/install_pinned_tauri_cli.sh",
                "installerPath": "scripts/install_pinned_tauri_cli.sh",
                "requiredInstallerFragments": [
                    "https://static.crates.io/crates/tauri-cli/tauri-cli-$TAURI_CLI_VERSION.crate",
                    "$TAURI_CLI_CRATE_SHA256",
                    "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256",
                    "$TAURI_CLI_LOCK_PATCH_SHA256",
                    "$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256",
                    "$TAURI_CLI_SPIN_VERSION",
                    "$TAURI_CLI_SPIN_CRATE_SHA256",
                    'which --toolchain "$rust_toolchain"',
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
                    '/bin/mv "$source_root" "$payload/source"',
                    "/usr/bin/lipo -archs",
                    "--algorithm sha256-tree-v2",
                    "artifactKind=pinned-tauri-cli-v2",
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
                    "name": "security",
                    "pathKey": "SING_BOX_SECURITY_PATCH_PATH",
                    "sha256Key": "SING_BOX_SECURITY_PATCH_SHA256",
                    "sha256": SECURITY_SHA,
                },
                {
                    "name": "raw packet",
                    "pathKey": "SING_BOX_RAW_PACKET_PATCH_PATH",
                    "sha256Key": "SING_BOX_RAW_PACKET_PATCH_SHA256",
                    "sha256": RAW_SHA,
                },
                {
                    "name": "DNS failover",
                    "pathKey": "SING_BOX_DNS_FAILOVER_PATCH_PATH",
                    "sha256Key": "SING_BOX_DNS_FAILOVER_PATCH_SHA256",
                    "sha256": DNS_SHA,
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
            "verifiedGoModuleInputKeys": [
                "GOMOBILE_MODULE_SUM",
                "GOVULNCHECK_MODULE_SUM",
                "SING_BOX_UPSTREAM_GO_MOD_SHA256",
                "SING_BOX_UPSTREAM_GO_SUM_SHA256",
                "SING_BOX_PATCHED_GO_MOD_SHA256",
                "SING_BOX_PATCHED_GO_SUM_SHA256",
            ],
            "rejectedPatchDigests": [LEGACY_SHA],
            "libboxBuildTags": {
                "pinKey": "LIBBOX_BUILD_TAGS",
                "value": BUILD_TAGS,
                "required": [
                    {"tag": "with_quic", "reason": "QUIC outbounds"},
                    {"tag": "with_clash_api", "reason": "engine start path needs the server"},
                    {"tag": "grpcnotrace", "reason": "no gRPC trace surface"},
                ],
                "engineStartPathBindings": [
                    {
                        "tag": "with_clash_api",
                        "path": CONTROLLER_RELATIVE_PATH,
                        "requiredWhenContains": CONTROLLER_TRIGGER,
                        "triggerRequired": True,
                        "reason": "the projected controller block needs the real server",
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
                        "$SING_BOX_COMBINED_DIFF_SHA256",
                        "$SING_BOX_SECURITY_PATCH_SHA256",
                        "$SING_BOX_RAW_PACKET_PATCH_SHA256",
                        "$SING_BOX_DNS_FAILOVER_PATCH_SHA256",
                    ],
                    "forbidNetworkRecursion": True,
                }
            },
            "artifactBindings": {
                "scripts/libbox_source_contract.sh": list(LIBBOX_ARTIFACT_BINDINGS),
                "scripts/build_libbox.sh": [
                    "sourceCommit=$SING_BOX_COMMIT",
                    "gomobileCommit=$GOMOBILE_COMMIT",
                    "gomobileModuleSum=$GOMOBILE_MODULE_SUM",
                    "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256",
                ],
                "scripts/build_native_products.sh": [
                    "singBoxCommit=$SING_BOX_COMMIT",
                    "libbox_verify_xcframework_artifact",
                ],
                "scripts/build_unsigned_candidate.sh": [
                    "libbox_verify_xcframework_artifact",
                ],
            },
        }
        self.lock = {
            "go": "1.26.5",
            "gomobile": "v0.1.13",
            "singBox": {
                "commit": COMMIT,
                "tag": "v1.13.14",
                "securityPatch": {
                    "path": PATCH_PATHS["security"],
                    "sha256": SECURITY_SHA,
                    "patchedDiffSha256": SECURITY_SHA,
                    "patchedGoModSha256": self.env["SING_BOX_PATCHED_GO_MOD_SHA256"],
                    "patchedGoSumSha256": self.env["SING_BOX_PATCHED_GO_SUM_SHA256"],
                },
                "rawPacketPatch": {"path": PATCH_PATHS["raw"], "sha256": RAW_SHA},
                "dnsFailoverPatch": {"path": PATCH_PATHS["dns"], "sha256": DNS_SHA},
                "combinedDiffSha256": COMBINED_SHA,
            },
        }
        self.build_libbox = BUILD_LIBBOX
        self.libbox_contract = LIBBOX_CONTRACT
        self.build_native = BUILD_NATIVE
        self.build_unsigned = BUILD_UNSIGNED
        self.tauri_lock_patch = TAURI_LOCK_PATCH_BODY
        self.xcodegen_patch = XCODEGEN_PATCH_BODY
        self.xcodegen_bootstrap = XCODEGEN_BOOTSTRAP
        self.tauri_installer = TAURI_INSTALLER
        self.ci_workflow = CI_WORKFLOW
        self.extra_artifact_files: dict[str, str] = {}
        self._extra_env_text = ""

    def env_text(self) -> str:
        lines = ["# generated test pins"]
        lines += [f"{key}={value}" for key, value in self.env.items()]
        return "\n".join(lines) + "\n" + self._extra_env_text

    def append_env_text(self, text: str) -> None:
        self._extra_env_text += text

    def write(self, root: Path) -> Path:
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "native/macos/patches").mkdir(parents=True, exist_ok=True)
        controller = root / CONTROLLER_RELATIVE_PATH
        controller.parent.mkdir(parents=True, exist_ok=True)
        controller.write_text(self.controller_source, encoding="utf-8")
        (root / MANIFEST_RELATIVE_PATH).write_text(json.dumps(self.manifest), encoding="utf-8")
        (root / "scripts/dependency_pins.env").write_text(self.env_text(), encoding="utf-8")
        for key, body in self.patch_bodies.items():
            (root / PATCH_PATHS[key]).write_bytes(body)
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
    def _verify_fixture(self, fixture: Fixture) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            verify(fixture.write(Path(temporary)))

    def _assert_fails(self, fixture: Fixture, pattern: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            with self.assertRaisesRegex(PinnedInputError, pattern):
                verify(root)

    # --- success ------------------------------------------------------------

    def test_correct_pins_pass(self) -> None:
        self._verify_fixture(Fixture())

    def test_real_repository_passes(self) -> None:
        # Binds the shipped manifest, dependency_pins.env, patch files, native lock,
        # and offline build scripts together.
        verify(REPO_ROOT)

    # --- wrong / missing pins -----------------------------------------------

    def test_wrong_tool_version_fails(self) -> None:
        fixture = Fixture()
        fixture.env["GO_VERSION"] = "1.26.4"
        self._assert_fails(fixture, "GO_VERSION")

    def test_missing_pin_fails(self) -> None:
        fixture = Fixture()
        del fixture.env["GOVULNCHECK_VERSION"]
        self._assert_fails(fixture, "GOVULNCHECK_VERSION")

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

    def test_source_contract_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_PATCHED_GO_MOD_SHA256"] = "a" * 64
        self._assert_fails(fixture, "source contract patchedGoModSha256")

    def test_native_lock_source_contract_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.lock["singBox"]["securityPatch"]["patchedGoSumSha256"] = "a" * 64
        self._assert_fails(fixture, "securityPatch.patchedGoSumSha256")

    def test_cargo_deny_ci_hard_coded_version_fails(self) -> None:
        fixture = Fixture()
        fixture.ci_workflow = fixture.ci_workflow.replace(
            '"$CARGO_DENY_VERSION"', "0.20.2"
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

    def test_patch_file_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.patch_bodies["security"] = b"tampered body\n"
        self._assert_fails(fixture, "file digest")

    def test_missing_patch_file_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.patch_bodies["raw"]
        self._assert_fails(fixture, "missing or not regular")

    def test_legacy_partial_digest_rejected(self) -> None:
        # Point the raw-packet patch entirely at the rejected legacy digest.
        fixture = Fixture()
        fixture.patch_bodies["raw"] = LEGACY_BODY
        fixture.env["SING_BOX_RAW_PACKET_PATCH_SHA256"] = LEGACY_SHA
        fixture.manifest["patches"][1]["sha256"] = LEGACY_SHA
        fixture.lock["singBox"]["rawPacketPatch"]["sha256"] = LEGACY_SHA
        self._assert_fails(fixture, "rejected/legacy digest")

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
        reduced = "with_quic,grpcnotrace"
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

    def test_source_binding_without_required_tag_fails(self) -> None:
        # A source trigger may not be satisfied by the required-tag table alone:
        # removing the tag from both the pin and the required table still fails
        # because the tracked source still needs it.
        fixture = Fixture()
        reduced = "with_quic,grpcnotrace"
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
        self._assert_fails(fixture, "no libbox build tag binding")

    def test_required_tag_without_reason_fails(self) -> None:
        fixture = Fixture()
        del fixture.manifest["libboxBuildTags"]["required"][1]["reason"]
        self._assert_fails(fixture, "no recorded reason")

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

    # --- native lock and build-script bindings ------------------------------

    def test_native_lock_mismatch_fails(self) -> None:
        fixture = Fixture()
        fixture.lock["singBox"]["rawPacketPatch"]["sha256"] = "b" * 64
        self._assert_fails(fixture, "rawPacketPatch")

    def test_build_script_missing_pin_reference_fails(self) -> None:
        fixture = Fixture()
        fixture.build_libbox = fixture.build_libbox.replace("$SING_BOX_COMMIT", "25a600db")
        self._assert_fails(fixture, "floating version|artifact-hash")

    def test_build_script_network_action_fails(self) -> None:
        fixture = Fixture()
        fixture.build_libbox += "git clone https://example.com/sing-box\n"
        self._assert_fails(fixture, "network or recursive")

    def test_missing_artifact_binding_fails(self) -> None:
        fixture = Fixture()
        fixture.build_native = '#!/usr/bin/env bash\necho "no binding"\n'
        self._assert_fails(fixture, "artifact-hash binding")

    def test_libbox_exact_contract_missing_metadata_binding_fails(self) -> None:
        fixture = Fixture()
        fixture.libbox_contract = fixture.libbox_contract.replace(
            "patchedGoSumSha256=$SING_BOX_PATCHED_GO_SUM_SHA256", "missing-binding"
        )
        self._assert_fails(fixture, "artifact-hash binding")

    def test_production_orchestrator_binding_drift_fails(self) -> None:
        fixture = Fixture()
        path = "scripts/publication/orchestrator.py"
        fixture.manifest["artifactBindings"][path] = [
            'VALIDATION_BUILD = "40002"',
            'FINAL_BUILD = "40003"',
            "seal_production_evidence",
            "require_verified=True",
        ]
        fixture.extra_artifact_files[path] = (
            'VALIDATION_BUILD = "40002"\n'
            'FINAL_BUILD = "40003"\n'
            "def seal_production_evidence():\n"
            "    require_verified=True\n"
        )
        self._verify_fixture(fixture)
        fixture.extra_artifact_files[path] = fixture.extra_artifact_files[path].replace(
            "require_verified=True", "require_verified=False"
        )
        self._assert_fails(fixture, "artifact-hash binding")

    def test_real_manifest_pins_complete_production_orchestrator_surface(self) -> None:
        manifest = json.loads((REPO_ROOT / MANIFEST_RELATIVE_PATH).read_text(encoding="utf-8"))
        bindings = manifest["artifactBindings"]
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
