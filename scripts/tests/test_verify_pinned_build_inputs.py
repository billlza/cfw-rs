from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import verify_pinned_build_inputs as pinned_verifier
from scripts.verify_pinned_build_inputs import (
    MANIFEST_RELATIVE_PATH,
    MAX_PINNED_MANIFEST_BYTES,
    PinnedInputError,
    verify_source_contract,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPED_PINNED_MANIFEST = json.loads(
    (REPO_ROOT / MANIFEST_RELATIVE_PATH).read_text(encoding="utf-8")
)


# The shipped pin values, parsed by the verifier's own strict reader. Tests read
# every real value from here so that a pin bump edits
# scripts/dependency_pins.env and nothing that repeats it.
SHIPPED_PINS = pinned_verifier.load_dependency_pins(REPO_ROOT)
REJECTED_PATCH_DIGESTS = sorted(SHIPPED_PINNED_MANIFEST["rejectedPatchDigests"])
BUILD_TAGS = SHIPPED_PINS["LIBBOX_BUILD_TAGS"]
PACKET_ENDPOINT_PATHS = tuple(
    entry["path"]
    for entry in SHIPPED_PINNED_MANIFEST["packetEvidenceEndpoint"]["sourceFiles"]
)
PHYSICAL_COLLECTOR_PATHS = (
    SHIPPED_PINNED_MANIFEST["physicalCollectorModule"]["goModPath"],
    SHIPPED_PINNED_MANIFEST["physicalCollectorModule"]["goSumPath"],
)


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


# Synthetic, self-consistent patch bodies. Their real SHA-256 digests replace the
# shipped patch path and digest pins so the verifier logic can be exercised
# without needing SHA-256 preimages of the shipped patches.
PATCH_BODIES = {
    "socks": b"synthetic SOCKS lifecycle patch body\n",
    "security": b"synthetic security dependencies patch body\n",
    "raw": b"synthetic raw packet tun patch body\n",
    "dns": b"synthetic dns failover patch body\n",
    "endpoint": b"synthetic endpoint conflict patch body\n",
    "probe": b"profile probe patch fixture\n",
}
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
TAURI_CACHE_CONTRACT_SHA = _sha(TAURI_CACHE_CONTRACT_BODY)
LIBBOX_MODULE_CACHE_CONTRACT_SHA = _sha(LIBBOX_MODULE_CACHE_CONTRACT_BODY)
XCODEGEN_PATCH_SHA = _sha(XCODEGEN_PATCH_BODY)
TAURI_CACHE_CONTRACT_PATH = "scripts/tauri_cargo_cache_contract.py"
LIBBOX_MODULE_CACHE_CONTRACT_PATH = "scripts/libbox_module_cache_contract.sh"
XCODEGEN_PATCH_PATH = "scripts/xcodegen-installed-resources.patch"

PATCH_PATHS = {
    "socks": "native/macos/patches/socks-lifecycle.patch",
    "probe": "native/macos/patches/profile-probe.patch",
    "security": "native/macos/patches/security.patch",
    "raw": "native/macos/patches/raw-packet.patch",
    "dns": "native/macos/patches/dns-failover.patch",
    "endpoint": "native/macos/patches/endpoint-conflict.patch",
}
PATCH_PIN_PREFIXES = {
    "socks": "SING_BOX_SOCKS_LIFECYCLE_PATCH",
    "probe": "SING_BOX_PROFILE_PROBE_PATCH",
    "security": "SING_BOX_SECURITY_PATCH",
    "raw": "SING_BOX_RAW_PACKET_PATCH",
    "dns": "SING_BOX_DNS_FAILOVER_PATCH",
    "endpoint": "SING_BOX_ENDPOINT_CONFLICT_PATCH",
}

# A bounded occurrence of a pin value: not part of a longer identifier, number or
# dotted version (``27.0`` is not a copy of anything inside ``127.0.0.1``).
def _pin_value_pattern(value: str) -> re.Pattern[str]:
    return re.compile(
        r"(?<![A-Za-z0-9_.])" + re.escape(value) + r"(?![A-Za-z0-9_]|[.][0-9])"
    )


def _repeated_pin_values(text: str) -> list[str]:
    return sorted(
        key
        for key, value in SHIPPED_PINS.items()
        if _pin_value_pattern(value).search(text)
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
TAURI_INSTALLER = """\
#!/usr/bin/env bash
echo "https://static.crates.io/crates/tauri-cli/tauri-cli-$TAURI_CLI_VERSION.crate"
echo "$TAURI_CLI_CRATE_SHA256"
echo "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256"
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
verify_tauri_payload_source() {
  for required in Cargo.toml Cargo.lock LICENSE-APACHE-2.0 LICENSE-MIT; do
    test -f "$payload/source/$required"
  done
  printf '%s  %s\\n' "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$source/Cargo.lock" |
    shasum -a 256 --check >/dev/null
  "$python_bin" - <<'PY'
root = None
manifest = (root / "source/Cargo.toml").read_text(encoding="utf-8")
PY
}
render_tauri_workspace_manifest() {
  printf '[workspace]\\nmembers = ["tauri-cli-%s"]\\nresolver = "2"\\n' """ + "\\\n" + """    "$TAURI_CLI_VERSION"
}
reject_tauri_cargo_configuration() {
  cfw_run_release_python_script \
    "$repo_root" "$repo_root/scripts/release_cargo_inputs.py" \
    reject-ambient --repository "$repo_root" --release-home "$HOME" \
    --additional-working-directory "$source_root" ||
    die "ambient Cargo configuration is forbidden for the Tauri source"
}
verify_tauri_workspace_boundary() {
  local boundary_file
  for boundary_file in \
    "$cargo_manifest" \
    "$cargo_lock" \
    "$staging_workspace_manifest" \
    "$staging_workspace_lock"; do
    [[ -f "$boundary_file" && ! -L "$boundary_file" ]] ||
      die "Tauri workspace input must be a regular file: $boundary_file"
    [[ "$(stat -f '%l' "$boundary_file")" == "1" ]] ||
      die "Tauri workspace input must not have hard links: $boundary_file"
    [[ "$(stat -f '%u' "$boundary_file")" == "$(/usr/bin/id -u)" ]] ||
      die "Tauri workspace input must belong to the release account: $boundary_file"
  done
  [[ "$(stat -f '%Lp' "$staging_workspace_manifest")" == "600" && \
    "$(stat -f '%Lp' "$staging_workspace_lock")" == "600" ]] ||
    die "temporary Tauri workspace inputs must use mode 0600"
  printf '%s  %s\\n' \
    "$staging_workspace_manifest_sha256" "$staging_workspace_manifest" |
    shasum -a 256 --check >/dev/null
  printf '%s  %s\\n' \
    "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$cargo_lock" |
    shasum -a 256 --check >/dev/null
  printf '%s  %s\\n' \
    "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$staging_workspace_lock" |
    shasum -a 256 --check >/dev/null
  /usr/bin/cmp -s "$cargo_lock" "$staging_workspace_lock" ||
    die "Tauri source and workspace locks differ"
}
cargo_bin="$CFW_RELEASE_CARGO_EXECUTABLE"
rustc_bin="$CFW_RELEASE_RUSTC_EXECUTABLE"
[[ "$temporary_parent" != *:* ]]
staging="$(/usr/bin/mktemp -d "$temporary_parent/cfw-tauri-cli.XXXXXX")"
readonly staging_workspace_manifest="$staging/Cargo.toml"
readonly staging_workspace_lock="$staging/Cargo.lock"
staging_workspace_manifest_sha256="$(
  render_tauri_workspace_manifest | shasum -a 256 | /usr/bin/awk '{print $1}'
)"
readonly staging_workspace_manifest_sha256
readonly cargo_manifest="$source_root/Cargo.toml"
readonly cargo_lock="$source_root/Cargo.lock"
[[ -f "$cargo_manifest" && ! -L "$cargo_manifest" ]] ||
  die "the pinned Tauri CLI archive has no regular Cargo.toml"
[[ -f "$cargo_lock" && ! -L "$cargo_lock" ]] ||
  die "the pinned Tauri CLI archive has no regular Cargo.lock"
verify_cargo_preparation_cache "$prepared_cargo_home"
printf '%s  %s\\n' "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$cargo_lock" |
  shasum -a 256 --check
PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - \\
  "$cargo_manifest" \\
  "$cargo_lock" \\
  "$TAURI_CLI_VERSION" \\
  "$TAURI_CLI_SPIN_VERSION" \\
  "$TAURI_CLI_SPIN_CRATE_SHA256" <<'PY'
PY
echo "official Tauri CLI lock has unexpected spin records"
[[ ! -e "$staging_workspace_manifest" && ! -L "$staging_workspace_manifest" && \
  ! -e "$staging_workspace_lock" && ! -L "$staging_workspace_lock" ]] ||
  die "temporary Tauri workspace inputs already exist"
render_tauri_workspace_manifest >"$staging_workspace_manifest"
/bin/chmod 0600 "$staging_workspace_manifest"
/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"
verify_tauri_workspace_boundary
reject_tauri_cargo_configuration
if /usr/bin/env -i \
  HOME="$fetch_home" \
  TMPDIR="$fetch_tmp" \
  LANG=C \
  LC_ALL=C \
  PATH="$(dirname "$cargo_bin"):/usr/bin:/bin:/usr/sbin:/sbin" \
  DEVELOPER_DIR="$developer_dir" \
  SDKROOT="$sdk_root" \
  MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
  CARGO_HOME="$prepared_cargo_home" \
  CARGO_TARGET_DIR="$fetch_target" \
  CARGO_HTTP_LOW_SPEED_LIMIT=1 \
  CARGO_HTTP_MULTIPLEXING=true \
  CARGO_HTTP_TIMEOUT=600 \
  CARGO_NET_RETRY=3 \
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
  CARGO_TERM_COLOR=never \
  RUSTC="$rustc_bin" \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_SYSTEM=/dev/null \
  "$cargo_bin" fetch \
  --manifest-path "$cargo_manifest" \
  --locked \
  --target aarch64-apple-darwin 2>&1 | tee "$fetch_log"; then
  :
else
  die "checksum-bound Tauri CLI dependency preparation failed"
fi
reject_cargo_warnings "$fetch_log" "Tauri CLI dependency preparation"
verify_tauri_workspace_boundary
reject_tauri_cargo_configuration
verify_cargo_preparation_cache "$prepared_cargo_home"
/usr/bin/ditto --noqtn "$prepared_cargo_home" "$offline_cargo_home"
normalize_cargo_offline_cache "$offline_cargo_home"
cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/hash_artifact.py" \
  "$offline_cargo_home"
offline_cache_sha256_before="$(cfw_verify_release_toolchain_manifest)"
verify_tauri_workspace_boundary
reject_tauri_cargo_configuration
/usr/bin/env -i PATH="$cargo_install_root/bin:$(dirname "$cargo_bin"):/usr/bin:/bin:/usr/sbin:/sbin" \
  CARGO_HOME="$offline_cargo_home" CARGO_TARGET_DIR="$cargo_target" \
  CARGO_NET_OFFLINE=true CARGO_NET_RETRY=0 \
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse RUSTC="$rustc_bin" \
  "$cargo_bin" install --path "$source_root" --offline --locked \
  --target aarch64-apple-darwin
reject_cargo_warnings "$install_log" "tauri-cli installation"
verify_tauri_workspace_boundary
reject_tauri_cargo_configuration
normalize_cargo_offline_cache "$offline_cargo_home"
offline_cache_sha256_after="$(cfw_verify_release_toolchain_manifest)"
[[ "$offline_cache_sha256_after" == "$offline_cache_sha256_before" ]]
echo "tauri-cli-$TAURI_CLI_VERSION"
readonly payload="$staging/payload/tauri-cli-$TAURI_CLI_VERSION"
/bin/mv "$source_root" "$payload/source"
verify_tauri_payload_source
/usr/bin/lipo -archs "$payload/bin/cargo-tauri"
echo "--algorithm sha256-tree-v2"
echo "artifactKind=pinned-tauri-cli-v3"
echo "cacheContractSha256=$TAURI_CARGO_CACHE_CONTRACT_SHA256"
echo "cacheNormalization=cargo-runtime-metadata-v1"
echo "dependencyMode=isolated-fetch-offline-locked-v1"
echo "macosDeploymentTarget=$MACOS_DEPLOYMENT_TARGET"
echo "payloadLayout=bin-and-source-v1"
echo "xcodeBuild=$XCODE_BUILD_VERSION"
echo "xcodeVersion=$XCODE_VERSION"
echo "cfw_verify_tauri_toolchain_tree"
"""


def _replace_tauri_fixture_block(
    fixture: str,
    reference: str,
    start_marker: str,
    end_marker: str,
) -> str:
    fixture_start = fixture.index(start_marker)
    fixture_end = fixture.index(end_marker, fixture_start) + len(end_marker)
    reference_start = reference.index(start_marker)
    reference_end = reference.index(end_marker, reference_start) + len(end_marker)
    return (
        fixture[:fixture_start]
        + reference[reference_start:reference_end]
        + fixture[fixture_end:]
    )


_TAURI_INSTALLER_REFERENCE = (
    REPO_ROOT / "scripts/install_pinned_tauri_cli.sh"
).read_text(encoding="utf-8")
for _start_marker, _end_marker in (
    ("reject_tauri_cargo_configuration() {", "\n}"),
    ("verify_tauri_workspace_boundary() {", "\n}"),
    (
        'staging_workspace_manifest_sha256="$(',
        "\nreadonly staging_workspace_manifest_sha256",
    ),
):
    TAURI_INSTALLER = _replace_tauri_fixture_block(
        TAURI_INSTALLER,
        _TAURI_INSTALLER_REFERENCE,
        _start_marker,
        _end_marker,
    )

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
/usr/bin/strip -S "$xcodegen_bin_dir/xcodegen"
echo "patchSha256=$XCODEGEN_PATCH_SHA256"
echo "patchedSettingsBuilderSha256=$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256"
echo "XcodeGenResourceProbe.xcodeproj/project.pbxproj"
"""


class Fixture:
    """A self-consistent, mutable pinned-input repository fixture.

    The pin values are the shipped ones except where the fixture writes a
    synthetic tracked file (patches, contracts): there the path and digest pins
    name the synthetic file. The policy is the shipped policy except for the
    script fragment lists that the synthetic installer and bootstrap satisfy.
    """

    def __init__(self) -> None:
        self.env: dict[str, str] = dict(SHIPPED_PINS)
        for key, prefix in PATCH_PIN_PREFIXES.items():
            self.env[f"{prefix}_PATH"] = PATCH_PATHS[key]
            self.env[f"{prefix}_SHA256"] = _sha(PATCH_BODIES[key])
        self.env.update(
            {
                "XCODEGEN_PATCH_PATH": XCODEGEN_PATCH_PATH,
                "XCODEGEN_PATCH_SHA256": XCODEGEN_PATCH_SHA,
                "TAURI_CARGO_CACHE_CONTRACT_SHA256": TAURI_CACHE_CONTRACT_SHA,
                "LIBBOX_MODULE_CACHE_CONTRACT_PATH": LIBBOX_MODULE_CACHE_CONTRACT_PATH,
                "LIBBOX_MODULE_CACHE_CONTRACT_SHA256": LIBBOX_MODULE_CACHE_CONTRACT_SHA,
            }
        )
        self.patch_bodies = dict(PATCH_BODIES)
        self.packet_endpoint_files = {
            relative: (REPO_ROOT / relative).read_bytes()
            for relative in PACKET_ENDPOINT_PATHS
        }
        self.physical_collector_files = {
            relative: (REPO_ROOT / relative).read_bytes()
            for relative in PHYSICAL_COLLECTOR_PATHS
        }
        self.controller_source = CONTROLLER_SOURCE
        self.projection_source = PROJECTION_SOURCE
        shipped = copy.deepcopy(SHIPPED_PINNED_MANIFEST)
        self.manifest = {
            "schema": shipped["schema"],
            "description": "synthetic pinned build inputs",
            "pinFormats": shipped["pinFormats"],
            "packetEvidenceEndpoint": shipped["packetEvidenceEndpoint"],
            "physicalCollectorModule": shipped["physicalCollectorModule"],
            "xcodegen": {
                "patchPathKey": shipped["xcodegen"]["patchPathKey"],
                "patchSha256Key": shipped["xcodegen"]["patchSha256Key"],
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
                    '/usr/bin/strip -S "$xcodegen_bin_dir/xcodegen"',
                    "patchSha256=$XCODEGEN_PATCH_SHA256",
                    "patchedSettingsBuilderSha256=$XCODEGEN_PATCHED_SETTINGS_BUILDER_SHA256",
                    "XcodeGenResourceProbe.xcodeproj/project.pbxproj",
                ],
            },
            "cargoDeny": {
                "ciWorkflowPath": ".github/workflows/ci.yml",
                "requiredCiFragments": [
                    "run_release_ci_gate.sh",
                    "bootstrap-policy-tools",
                    "cargo-deny",
                ],
            },
            "tauriCli": {
                "cacheContractPath": TAURI_CACHE_CONTRACT_PATH,
                "cacheContractSha256Key": shipped["tauriCli"]["cacheContractSha256Key"],
                "ciWorkflowPath": ".github/workflows/ci.yml",
                "requiredCiFragment": "install-tauri-cli",
                "installerPath": "scripts/install_pinned_tauri_cli.sh",
                "requiredInstallerFragments": [
                    "https://static.crates.io/crates/tauri-cli/tauri-cli-$TAURI_CLI_VERSION.crate",
                    "$TAURI_CLI_CRATE_SHA256",
                    "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256",
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
                    '[[ "$temporary_parent" != *:* ]]',
                    'staging="$(/usr/bin/mktemp -d '
                    '"$temporary_parent/cfw-tauri-cli.XXXXXX")"',
                    'members = ["tauri-cli-%s"]',
                    'resolver = "2"',
                    'staging_workspace_manifest="$staging/Cargo.toml"',
                    'staging_workspace_lock="$staging/Cargo.lock"',
                    'render_tauri_workspace_manifest >"$staging_workspace_manifest"',
                    '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"',
                    'verify_tauri_workspace_boundary',
                    'reject_tauri_cargo_configuration',
                    '--additional-working-directory "$source_root"',
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
                    "artifactKind=pinned-tauri-cli-v3",
                    "cacheContractSha256=$TAURI_CARGO_CACHE_CONTRACT_SHA256",
                    "cacheNormalization=cargo-runtime-metadata-v1",
                    "dependencyMode=isolated-fetch-offline-locked-v1",
                    "macosDeploymentTarget=$MACOS_DEPLOYMENT_TARGET",
                    "payloadLayout=bin-and-source-v1",
                    "xcodeBuild=$XCODE_BUILD_VERSION",
                    "xcodeVersion=$XCODE_VERSION",
                    "cfw_verify_release_toolchain_manifest",
                    "cfw_verify_tauri_toolchain_tree",
                ],
            },
            "patches": shipped["patches"],
            "libboxModuleCacheContract": shipped["libboxModuleCacheContract"],
            "rejectedPatchDigests": shipped["rejectedPatchDigests"],
            "libboxBuildTags": shipped["libboxBuildTags"],
            "buildScripts": shipped["buildScripts"],
        }
        self.build_libbox = (REPO_ROOT / "scripts/build_libbox.sh").read_text(
            encoding="utf-8"
        )
        self.libbox_module_cache_contract = LIBBOX_MODULE_CACHE_CONTRACT_BODY
        self.xcodegen_patch = XCODEGEN_PATCH_BODY
        self.xcodegen_bootstrap = XCODEGEN_BOOTSTRAP
        self.tauri_installer = TAURI_INSTALLER
        self.ci_workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        self.extra_files: dict[str, str] = {}
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
        for relative, body in self.physical_collector_files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        (root / "scripts/build_libbox.sh").write_text(self.build_libbox, encoding="utf-8")
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
        for relative, contents in self.extra_files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        return root


class PinnedBuildInputsTests(unittest.TestCase):
    def _verify_fixture(self, fixture: Fixture) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            verify_source_contract(root)

    def _assert_fails(self, fixture: Fixture, pattern: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            with self.assertRaisesRegex(PinnedInputError, pattern):
                verify_source_contract(root)

    # --- success ------------------------------------------------------------

    def test_correct_pins_pass(self) -> None:
        self._verify_fixture(Fixture())

    def test_real_repository_source_contract_passes(self) -> None:
        # Binds the shipped policy, dependency_pins.env, patch files, and offline
        # build scripts together without relying on a generated target.
        verify_source_contract(REPO_ROOT)

    def test_verified_inputs_bind_exactly_the_checked_values(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            verified = verify_source_contract(fixture.write(Path(temporary)))
        self.assertEqual(dict(verified.pins), fixture.env)
        self.assertEqual(
            verified.patch_digests,
            tuple(
                fixture.env[patch["sha256Key"]]
                for patch in fixture.manifest["patches"]
            ),
        )
        self.assertEqual(
            set(verified.patch_digests),
            {_sha(body) for body in PATCH_BODIES.values()},
        )
        self.assertEqual(
            verified.combined_diff_sha256,
            fixture.env["SING_BOX_COMBINED_DIFF_SHA256"],
        )
        self.assertEqual(
            verified.rejected_patch_digests, frozenset(REJECTED_PATCH_DIGESTS)
        )
        with self.assertRaises(TypeError):
            verified.pins["GO_VERSION"] = "0.0.0"  # type: ignore[index]

    def test_value_bump_edits_only_the_pin_file_and_the_pinned_bytes(self) -> None:
        # A version bump and a patch change edit dependency_pins.env and the
        # patch itself; the fixture's policy is left untouched.
        fixture = Fixture()
        major, minor, patch = fixture.env["NODE_VERSION"].split(".")
        fixture.env["NODE_VERSION"] = f"{major}.{minor}.{int(patch) + 1}"
        fixture.env["NODE_DARWIN_ARM64_SHA256"] = _sha(b"next node archive")
        fixture.env["SING_BOX_COMBINED_DIFF_SHA256"] = _sha(b"next combined diff")
        fixture.patch_bodies["endpoint"] = b"next endpoint conflict patch body\n"
        fixture.env["SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256"] = _sha(
            fixture.patch_bodies["endpoint"]
        )
        with tempfile.TemporaryDirectory() as temporary:
            verified = verify_source_contract(fixture.write(Path(temporary)))
        self.assertEqual(verified.pins["NODE_VERSION"], f"{major}.{minor}.{int(patch) + 1}")
        self.assertIn(
            _sha(b"next endpoint conflict patch body\n"), verified.patch_digests
        )
        self.assertEqual(
            verified.combined_diff_sha256, _sha(b"next combined diff")
        )

    def test_product_go_bump_edits_only_the_pin_file(self) -> None:
        # The packet-evidence endpoint and the physical collector carry their
        # own Go identities, so a product Go bump leaves their policy, sources
        # and recorded digests untouched.
        fixture = Fixture()
        major, minor, patch = fixture.env["GO_VERSION"].split(".")
        next_go = f"{major}.{minor}.{int(patch) + 1}"
        fixture.env["GO_VERSION"] = next_go
        fixture.env["GO_DARWIN_ARM64_SHA256"] = _sha(b"next go archive")
        with tempfile.TemporaryDirectory() as temporary:
            verified = verify_source_contract(fixture.write(Path(temporary)))
        self.assertEqual(verified.pins["GO_VERSION"], next_go)

    def test_build_boundary_runs_the_pinned_source_contract_gate(self) -> None:
        boundary = (REPO_ROOT / "scripts/verify_build_boundaries.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '"$repo_root/scripts/verify_pinned_source_contract.py"', boundary
        )

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

    def test_endpoint_toolchain_pins_are_named_by_key_only(self) -> None:
        # The policy and the README recipe name the endpoint toolchain by key,
        # so moving it edits only its pins (and, once rebuilt, the binary pin
        # with the installer and identities that carry it).
        fixture = Fixture()
        major, minor, patch = fixture.env["PACKET_EVIDENCE_ENDPOINT_GO_VERSION"].split(".")
        next_go = f"{major}.{minor}.{int(patch) + 1}"
        fixture.env["PACKET_EVIDENCE_ENDPOINT_GO_VERSION"] = next_go
        fixture.env["PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256"] = _sha(
            b"next endpoint go archive"
        )
        with tempfile.TemporaryDirectory() as temporary:
            verified = verify_source_contract(fixture.write(Path(temporary)))
        self.assertEqual(verified.pins["PACKET_EVIDENCE_ENDPOINT_GO_VERSION"], next_go)

    def test_endpoint_and_product_go_pins_agree_on_one_release(self) -> None:
        fixture = Fixture()
        fixture.env["PACKET_EVIDENCE_ENDPOINT_GO_VERSION"] = fixture.env["GO_VERSION"]
        fixture.env["PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256"] = fixture.env[
            "GO_DARWIN_ARM64_SHA256"
        ]
        self._verify_fixture(fixture)
        fixture.env["PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256"] = _sha(
            b"mistyped endpoint go archive"
        )
        self._assert_fails(
            fixture, "pin one Go version with different archive digests"
        )

    def test_packet_endpoint_must_name_its_own_pin_keys(self) -> None:
        for field, other_key in (
            ("goVersionKey", "GO_VERSION"),
            ("goArchiveSha256Key", "GO_DARWIN_ARM64_SHA256"),
            ("binarySha256Key", "GO_RELEASE_TOOLS_GO_MOD_SHA256"),
        ):
            with self.subTest(field=field):
                fixture = Fixture()
                fixture.manifest["packetEvidenceEndpoint"][field] = other_key
                self._assert_fails(
                    fixture, "must name its own Go toolchain and binary pins"
                )

    def test_packet_endpoint_pins_must_keep_their_declared_formats(self) -> None:
        for key, other_format, declared in (
            ("PACKET_EVIDENCE_ENDPOINT_GO_VERSION", "apple-version", "version"),
            ("PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256", "go-build-tags", "sha256"),
            ("PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256", "go-build-tags", "sha256"),
        ):
            with self.subTest(key=key):
                fixture = Fixture()
                fixture.manifest["pinFormats"][key] = other_format
                self._assert_fails(
                    fixture, f"must name a declared {declared} pin, not '{key}'"
                )

    def test_packet_endpoint_build_target_ports_and_recipe_are_fixed(self) -> None:
        for name, mutate in (
            ("goos", lambda spec: spec.update(goos="darwin")),
            ("goarch", lambda spec: spec.update(goarch="arm64")),
            ("cgoEnabled", lambda spec: spec.update(cgoEnabled="1")),
            ("transportPort", lambda spec: spec.update(transportPort=44334)),
            ("dnsPort", lambda spec: spec.update(dnsPort=54)),
            ("readmePath", lambda spec: spec.update(readmePath="README.md")),
            ("recipe", lambda spec: spec["buildRecipe"].pop()),
        ):
            with self.subTest(field=name):
                fixture = Fixture()
                mutate(fixture.manifest["packetEvidenceEndpoint"])
                self._assert_fails(
                    fixture, "build target, ports, or build recipe drifted"
                )

    def _assert_endpoint_file_fails(
        self, relative: str, body: bytes, constant: str, pattern: str
    ) -> None:
        fixture = Fixture()
        fixture.packet_endpoint_files[relative] = body
        for entry in fixture.manifest["packetEvidenceEndpoint"]["sourceFiles"]:
            if entry["path"] == relative:
                entry["sha256"] = _sha(body)
        with mock.patch.object(pinned_verifier, constant, _sha(body)):
            self._assert_fails(fixture, pattern)

    def test_packet_endpoint_binary_pin_must_match_the_installer(self) -> None:
        fixture = Fixture()
        fixture.env["PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256"] = _sha(b"rebuilt endpoint")
        self._assert_fails(
            fixture,
            "installer must verify /tmp/packet-evidence-endpoint-linux-amd64 exactly "
            "once against PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256",
        )

    def test_packet_endpoint_installer_checks_each_binary_path_once_against_the_pin(
        self,
    ) -> None:
        installer_path = "tools/packet-evidence-endpoint/install-endpoint.sh"
        binary = SHIPPED_PINS["PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256"]
        staged = "/tmp/packet-evidence-endpoint-linux-amd64"
        installed = "/usr/local/libexec/cfw-packet-evidence-endpoint"

        def check(digest: str, path: str) -> str:
            return f"verify_sha256 \\\n  {digest} \\\n  {path}\n"

        shipped = (REPO_ROOT / installer_path).read_text(encoding="utf-8")
        for name, old, new, path in (
            (
                "installed binary digest",
                check(binary, installed),
                check("0" * 64, installed),
                installed,
            ),
            (
                "second staged binary check",
                check(binary, staged),
                check(binary, staged) + check("1" * 64, staged),
                staged,
            ),
        ):
            with self.subTest(change=name):
                self.assertEqual(shipped.count(old), 1)
                self._assert_endpoint_file_fails(
                    installer_path,
                    shipped.replace(old, new).encode("utf-8"),
                    "_PACKET_ENDPOINT_INSTALL_SCRIPT_SHA256",
                    f"installer must verify {path} exactly once against "
                    "PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256",
                )

    def test_packet_endpoint_identities_must_carry_the_binary_pin(self) -> None:
        policy_path = "scripts/physical_capture/packet_endpoints.json"
        shipped = json.loads((REPO_ROOT / policy_path).read_bytes())

        def wrong_binary(policy: dict) -> None:
            policy["identities"][2]["identity"]["endpoint_binary_sha256"] = "0" * 64

        for name, mutate, pattern in (
            (
                "wrong binary",
                wrong_binary,
                r"identities\[2\] does not carry PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256",
            ),
            (
                "identity is not an object",
                lambda policy: policy["identities"].__setitem__(1, "identity"),
                r"identities\[1\] does not carry PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256",
            ),
            (
                "entry without identity",
                lambda policy: policy["identities"][0].pop("identity"),
                r"identities\[0\] does not carry PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256",
            ),
            (
                "no identities",
                lambda policy: policy.update(identities=[]),
                "policy binds no instance identity",
            ),
            (
                "unknown top-level field",
                lambda policy: policy.update(unreviewed=True),
                "policy does not have its exact top-level shape",
            ),
        ):
            with self.subTest(change=name):
                policy = copy.deepcopy(shipped)
                mutate(policy)
                self._assert_endpoint_file_fails(
                    policy_path,
                    json.dumps(policy, indent=2).encode("utf-8") + b"\n",
                    "_PACKET_ENDPOINT_POLICY_SHA256",
                    pattern,
                )

    def test_packet_endpoint_readme_must_keep_the_exact_recipe(self) -> None:
        readme_path = "tools/packet-evidence-endpoint/README.md"
        shipped = (REPO_ROOT / readme_path).read_bytes()
        for name, old, new in (
            ("cgo", b"CGO_ENABLED=0", b"CGO_ENABLED=1"),
            (
                "archive check",
                b' "$archive" |\n    /usr/bin/shasum -a 256 --check\n',
                b' "$archive"\n',
            ),
            (
                "binary comparison",
                b"linux-amd64 | /usr/bin/shasum -a 256 --check\n",
                b"linux-amd64\n",
            ),
            ("errexit", b"  set -euo pipefail\n", b""),
            ("inherited environment", b"/usr/bin/env -i PATH", b"/usr/bin/env PATH"),
        ):
            with self.subTest(change=name):
                self.assertEqual(shipped.count(old), 1)
                body = shipped.replace(old, new)
                fixture = Fixture()
                fixture.packet_endpoint_files[readme_path] = body
                for entry in fixture.manifest["packetEvidenceEndpoint"]["sourceFiles"]:
                    if entry["path"] == readme_path:
                        entry["sha256"] = _sha(body)
                self._assert_fails(fixture, "README lacks the exact build recipe")

    def test_packet_endpoint_recipe_checks_inputs_before_use_and_output_after_build(
        self,
    ) -> None:
        # Guards the required recipe itself, which the verifier and the policy
        # could otherwise lose together.
        recipe = pinned_verifier._PACKET_ENDPOINT_BUILD_RECIPE
        self.assertEqual(
            list(recipe),
            SHIPPED_PINNED_MANIFEST["packetEvidenceEndpoint"]["buildRecipe"],
        )

        def line(fragment: str) -> int:
            matches = [index for index, text in enumerate(recipe) if fragment in text]
            self.assertEqual(len(matches), 1, fragment)
            return matches[0]

        self.assertEqual(recipe[:2], ("(", "  set -euo pipefail"))
        self.assertEqual(recipe[-1], ")")
        download = line(
            "https://go.dev/dl/go$PACKET_EVIDENCE_ENDPOINT_GO_VERSION.darwin-arm64.tar.gz"
        )
        archive_check = line(
            '"$PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256" "$archive" |'
        )
        extract = line('/usr/bin/tar -xzf "$archive"')
        build = line('"$work/go/bin/go" -C tools/packet-evidence-endpoint build')
        compare = line('"$PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256"')
        self.assertEqual(recipe[archive_check + 1], "    /usr/bin/shasum -a 256 --check")
        self.assertEqual(
            recipe[compare + 1],
            "    target/packet-evidence-endpoint-linux-amd64 | "
            "/usr/bin/shasum -a 256 --check",
        )
        self.assertLess(download, archive_check)
        self.assertLess(archive_check, extract)
        self.assertLess(extract, build)
        self.assertLess(build, compare)
        for flag in (
            "--proto '=https'",
            "/usr/bin/env -i",
            "GOTOOLCHAIN=local",
            "CGO_ENABLED=0",
            "GOOS=linux",
            "GOARCH=amd64",
            "-buildvcs=false",
            "-trimpath",
            "-ldflags='-s -w -buildid='",
        ):
            with self.subTest(flag=flag):
                self.assertTrue(any(flag in text for text in recipe[:compare]))

    def test_rooted_reader_descriptor_dup_failure_is_typed(self) -> None:
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            with mock.patch(
                "scripts.verify_pinned_build_inputs.os.dup",
                side_effect=OSError("fixture descriptor exhaustion"),
            ), self.assertRaisesRegex(
                PinnedInputError,
                "descriptor cannot be duplicated",
            ):
                verify_source_contract(root)

    def test_descriptor_cleanup_attempts_every_owned_descriptor(self) -> None:
        closed: list[int] = []

        def close(descriptor: int) -> None:
            closed.append(descriptor)
            if descriptor == 11:
                raise OSError("fixture close failure")

        with mock.patch(
            "scripts.verify_pinned_build_inputs.os.close",
            side_effect=close,
        ), self.assertRaisesRegex(PinnedInputError, "descriptor cleanup failed"):
            pinned_verifier._close_descriptors((11, 12, 13), "fixture")
        self.assertEqual(closed, [11, 12, 13])

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

    # --- pin key set and value formats --------------------------------------

    def test_missing_pin_fails(self) -> None:
        fixture = Fixture()
        del fixture.env["GOVULNCHECK_VERSION"]
        self._assert_fails(fixture, "missing required pins: GOVULNCHECK_VERSION")

    def test_coordinated_pin_deletion_fails_the_fixed_key_set(self) -> None:
        # Removing a pin from both the pin file and the policy cannot pass: the
        # fixed key set still requires it (build_native_products.sh, for one,
        # skips its Xcode identity check when XCODE_VERSION is unset).
        for key in ("XCODE_VERSION", "GOVULNCHECK_MODULE_SUM", "NPM_ARCHIVE_SHA256"):
            with self.subTest(key=key):
                fixture = Fixture()
                del fixture.env[key]
                del fixture.manifest["pinFormats"][key]
                self._assert_fails(
                    fixture, f"differs from the fixed release pin key set: {key}$"
                )

    def test_coordinated_pin_addition_fails_the_fixed_key_set(self) -> None:
        fixture = Fixture()
        fixture.env["UNDECLARED_TOOL_VERSION"] = "1.2.3"
        fixture.manifest["pinFormats"]["UNDECLARED_TOOL_VERSION"] = "version"
        self._assert_fails(
            fixture,
            "differs from the fixed release pin key set: UNDECLARED_TOOL_VERSION$",
        )

    def test_fixed_policies_name_only_fixed_pin_keys(self) -> None:
        referenced = {
            pinned_verifier.COMBINED_DIFF_PIN_KEY,
            pinned_verifier.PATCHED_DIFF_PIN_KEY,
            "PYTHON_VERSION",
        }
        for _name, path_key, sha256_key in pinned_verifier.REQUIRED_PATCH_POLICIES:
            referenced.update((path_key, sha256_key))
        for references in pinned_verifier.REQUIRED_BUILD_SCRIPT_POLICIES.values():
            self.assertTrue(all(reference.startswith("$") for reference in references))
            referenced.update(reference[1:] for reference in references)
        self.assertEqual(referenced - pinned_verifier.REQUIRED_PIN_KEYS, set())
        self.assertEqual(
            set(SHIPPED_PINNED_MANIFEST["pinFormats"]), pinned_verifier.REQUIRED_PIN_KEYS
        )

    def test_undeclared_pin_fails(self) -> None:
        fixture = Fixture()
        fixture.env["UNDECLARED_TOOL_VERSION"] = "1.2.3"
        self._assert_fails(
            fixture, "pins the policy does not declare: UNDECLARED_TOOL_VERSION"
        )

    def test_every_pin_format_rejects_a_malformed_value(self) -> None:
        malformed = {
            "apple-build": ("XCODE_BUILD_VERSION", "27a266a"),
            "apple-version": ("XCODE_VERSION", "27"),
            "git-commit": ("SING_BOX_COMMIT", "a" * 39),
            "go-build-tags": ("LIBBOX_BUILD_TAGS", "with_quic, with_utls"),
            "go-module-sum": ("GOVULNCHECK_MODULE_SUM", "not-an-h1-sum"),
            "go-module-version": ("SING_BOX_VERSION", "1.14.2"),
            "gomobile-target": ("LIBBOX_APPLE_PLATFORM", "macos"),
            "repository-path": ("XCODEGEN_AEXML_PATCH_PATH", "scripts/a b.patch"),
            "sha256": ("GO_DARWIN_ARM64_SHA256", "A" * 64),
            "version": ("GO_VERSION", "1.27"),
        }
        self.assertEqual(set(malformed), set(pinned_verifier.PIN_VALUE_FORMATS))
        for format_name, (key, value) in malformed.items():
            with self.subTest(format=format_name):
                fixture = Fixture()
                self.assertEqual(fixture.manifest["pinFormats"][key], format_name)
                fixture.env[key] = value
                self._assert_fails(fixture, f"{key} is not a {format_name} value")

    def test_repository_path_pin_rejects_unsafe_components(self) -> None:
        for value in ("../scripts/a.patch", "scripts/./a.patch", "/scripts/a.patch"):
            with self.subTest(value=value):
                fixture = Fixture()
                fixture.env["XCODEGEN_AEXML_PATCH_PATH"] = value
                self._assert_fails(
                    fixture,
                    "XCODEGEN_AEXML_PATCH_PATH (path has an unsafe component|path is "
                    "not repository-relative|is not a repository-path value)",
                )

    def test_pin_format_table_is_required_and_closed(self) -> None:
        for value in (None, {}, [], "sha256"):
            with self.subTest(value=value):
                fixture = Fixture()
                fixture.manifest["pinFormats"] = value
                self._assert_fails(fixture, "no pin format table")
        fixture = Fixture()
        fixture.manifest["pinFormats"]["GO_VERSION"] = "anything"
        self._assert_fails(fixture, "GO_VERSION declares an unknown format")

    def test_policy_rules_must_name_pins_of_their_format(self) -> None:
        fixture = Fixture()
        fixture.manifest["libboxModuleCacheContract"]["sha256Key"] = "GO_VERSION"
        self._assert_fails(fixture, "must name a declared sha256 pin, not 'GO_VERSION'")
        fixture = Fixture()
        fixture.manifest["xcodegen"]["patchPathKey"] = "XCODEGEN_UNDECLARED_PATH"
        self._assert_fails(fixture, "must name a declared repository-path pin")

    def test_policy_cannot_reintroduce_pin_value_copies(self) -> None:
        # The v1 manifest echoed dependency_pins.env values; none of those fields
        # may return, at the top level or inside a rule.
        for field in (
            "tools",
            "combinedDiffSha256Key",
            "dependencyPinsPath",
            "nativeLockPath",
            "sourceContract",
            "combinedDiffSha256",
            "singBoxCommit",
            "gomobileCommit",
            "verifiedGoModuleInputKeys",
        ):
            with self.subTest(field=field):
                fixture = Fixture()
                fixture.manifest[field] = "copied value"
                self._assert_fails(fixture, "exact top-level shape")
        for section, field, message in (
            ("xcodegen", "patchSha256", "exact XcodeGen patch binding"),
            ("tauriCli", "crateSha256", "exact Tauri CLI source binding"),
            ("tauriCli", "cacheContractSha256", "exact Tauri CLI source binding"),
            ("libboxModuleCacheContract", "sha256", "exact libbox module cache"),
            ("libboxBuildTags", "value", "no libbox build tag binding"),
        ):
            with self.subTest(section=section, field=field):
                fixture = Fixture()
                fixture.manifest[section][field] = "copied value"
                self._assert_fails(fixture, message)
        fixture = Fixture()
        fixture.manifest["patches"][0]["sha256"] = fixture.env[
            fixture.manifest["patches"][0]["sha256Key"]
        ]
        self._assert_fails(fixture, "malformed patch entry")

    def test_libbox_module_cache_contract_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.libbox_module_cache_contract += b"# unpinned package drift\n"
        self._assert_fails(fixture, "libbox module cache contract file digest")

    def test_libbox_module_cache_contract_env_digest_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_MODULE_CACHE_CONTRACT_SHA256"] = "a" * 64
        self._assert_fails(
            fixture,
            "libbox module cache contract file digest .* "
            "LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
        )

    def test_libbox_module_cache_contract_path_must_name_a_tracked_file(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_MODULE_CACHE_CONTRACT_PATH"] = "scripts/other-contract.sh"
        self._assert_fails(fixture, "libbox module cache contract is missing")

    def test_missing_libbox_module_cache_contract_binding_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.manifest["libboxModuleCacheContract"]
        self._assert_fails(fixture, "exact top-level shape")

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

    def test_tauri_cli_installer_requires_official_source_digest(self) -> None:
        fixture = Fixture()
        original = fixture.tauri_installer
        fixture.tauri_installer = original.replace(
            '"$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$cargo_lock" |',
            '"unbound" "$cargo_lock" |',
            1,
        )
        self.assertNotEqual(fixture.tauri_installer, original)
        self._assert_fails(
            fixture,
            "differs from release policy|Cargo control-file reference|"
            "lacks ordered operation|required pinned fragment|exact occurrences",
        )

    def test_tauri_cli_installer_requires_official_payload_digest(self) -> None:
        fixture = Fixture()
        original = fixture.tauri_installer
        fixture.tauri_installer = original.replace(
            '"$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$source/Cargo.lock" |',
            '"unbound" "$source/Cargo.lock" |',
            1,
        )
        self.assertNotEqual(fixture.tauri_installer, original)
        self._assert_fails(
            fixture,
            "differs from release policy|Cargo control-file reference|"
            "lacks ordered operation|required pinned fragment|exact occurrences",
        )

    def test_tauri_cli_installer_rejects_extra_unbound_lock_patch_apply(self) -> None:
        upstream_lock_check = (
            "printf '%s  %s\\n' \"$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256\" "
            '"$cargo_lock" |\n'
            "  shasum -a 256 --check\n"
        )
        unsafe_commands = (
            '/usr/bin/git -C "$source_root" apply --unidiff-zero "$lock_patch"',
            '/usr/bin/git -C "$staging/tauri-cli-$TAURI_CLI_VERSION" apply '
            '--unidiff-zero "$TAURI_CLI_LOCK_PATCH_PATH"',
            'git apply --unidiff-zero "$TAURI_CLI_LOCK_PATCH_PATH"',
        )
        for unsafe_command in unsafe_commands:
            with self.subTest(unsafe_command=unsafe_command):
                fixture = Fixture()
                original = fixture.tauri_installer
                fixture.tauri_installer = fixture.tauri_installer.replace(
                    upstream_lock_check,
                    unsafe_command + "\n" + upstream_lock_check,
                    1,
                )
                self.assertNotEqual(fixture.tauri_installer, original)
                self._assert_fails(
                    fixture,
                    "official source contains a patch apply operation",
                )

    def test_tauri_cli_installer_must_reject_colon_in_temporary_parent(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            '[[ "$temporary_parent" != *:* ]]',
            "true",
            1,
        )
        self._assert_fails(fixture, "required pinned fragment")

    def test_tauri_cli_installer_rejects_late_colon_path_check(self) -> None:
        fixture = Fixture()
        colon_check = '[[ "$temporary_parent" != *:* ]]\n'
        fixture.tauri_installer = fixture.tauri_installer.replace(
            colon_check,
            "",
            1,
        )
        fixture.tauri_installer = fixture.tauri_installer.replace(
            'echo "official Tauri CLI lock has unexpected spin records"',
            'echo "official Tauri CLI lock has unexpected spin records"' + "\n" + colon_check.rstrip(),
            1,
        )
        self._assert_fails(
            fixture,
            "lacks ordered operation|staging boundary",
        )

    def test_tauri_cli_installer_requires_one_member_workspace(self) -> None:
        for source, replacement in (
            ('members = ["tauri-cli-%s"]', "members = []"),
            ('resolver = "2"', 'resolver = "1"'),
        ):
            with self.subTest(source=source):
                fixture = Fixture()
                fixture.tauri_installer = fixture.tauri_installer.replace(
                    source,
                    replacement,
                    1,
                )
                self._assert_fails(fixture, "required pinned fragment|exact occurrences")

    def test_tauri_cli_installer_rejects_workspace_renderer_codrift(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            'resolver = "2"\\n\' \\\n',
            'resolver = "2"\\n[profile.release]\\ndebug = true\\n\' \\\n',
            1,
        )
        self._assert_fails(fixture, "exact occurrences")

    def test_tauri_cli_installer_requires_workspace_root_lock_copy(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"',
            "true",
            1,
        )
        self._assert_fails(fixture, "required pinned fragment|exact occurrences")

    def test_tauri_cli_installer_rejects_wrong_workspace_lock_source(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"',
            '/usr/bin/install -m 0600 "$cargo_manifest" "$staging_workspace_lock"',
            1,
        )
        self._assert_fails(
            fixture,
            "required pinned fragment|unexpected workspace input mutation",
        )

    def test_tauri_cli_installer_rejects_early_workspace_lock_copy(self) -> None:
        fixture = Fixture()
        copy = '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"\n'
        official_lock_check = (
            "printf '%s  %s\\n' \"$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256\" "
            '"$cargo_lock" |\n'
            "  shasum -a 256 --check\n"
        )
        original = fixture.tauri_installer
        fixture.tauri_installer = fixture.tauri_installer.replace(copy, "", 1)
        fixture.tauri_installer = fixture.tauri_installer.replace(
            official_lock_check,
            copy + official_lock_check,
            1,
        )
        self.assertNotEqual(fixture.tauri_installer, original)
        self._assert_fails(
            fixture,
            "unexpected Cargo control-file reference",
        )

    def test_tauri_cli_installer_rechecks_workspace_around_cargo(self) -> None:
        for call in (
            "\nverify_tauri_workspace_boundary\n",
            "\nreject_tauri_cargo_configuration\n",
        ):
            with self.subTest(call=call.strip()):
                fixture = Fixture()
                fixture.tauri_installer = fixture.tauri_installer.replace(
                    call,
                    "\ntrue\n",
                    1,
                )
                self._assert_fails(fixture, "exact occurrences")

    def test_tauri_cli_installer_rejects_extra_workspace_input_mutation(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"',
            '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"\n'
            '/bin/rm "$staging_workspace_lock"',
            1,
        )
        self._assert_fails(fixture, "unexpected workspace input mutation")

    def test_tauri_cli_installer_rejects_coordinated_workspace_mutations(
        self,
    ) -> None:
        approved_copy = (
            '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"'
        )
        for mutation in (
            'cp "$cargo_manifest" "$staging_workspace_lock"',
            '/bin/rm "$staging/Cargo.lock"',
            '/bin/rm "${staging}/Cargo.lock"',
            '/bin/rm "$staging"/Cargo.lock',
            "/bin/rm ${staging}/Cargo.lock",
            "/bin/rm $staging/Cargo.lock",
            'workspace_root="$staging"; /bin/rm "$workspace_root/Cargo.lock"',
            '/bin/rm "$cargo_lock"',
            '/bin/rm "${cargo_manifest}"',
            '/bin/rm "${cargo_lock:-}"',
            '/bin/rm "${cargo_manifest:?}"',
            '/bin/rm "${cargo_lock%}"',
            '/bin/rm "${cargo_manifest:0}"',
            'control_file="$cargo_lock"; /bin/rm "$control_file"',
        ):
            with self.subTest(mutation=mutation):
                fixture = Fixture()
                fixture.tauri_installer = fixture.tauri_installer.replace(
                    approved_copy,
                    f"{approved_copy}\n{mutation}",
                    1,
                )
                self._assert_fails(
                    fixture,
                    "unexpected Cargo control-file reference|"
                    "unexpected workspace input mutation",
                )

    def test_tauri_cli_installer_rejects_equal_count_control_file_rewrites(
        self,
    ) -> None:
        mutations = (
            (
                '[[ -f "$cargo_manifest" && ! -L "$cargo_manifest" ]] ||',
                '[[ -f "$cargo_manifest" && -f "$cargo_manifest" ]] ||',
            ),
            (
                '[[ -f "$cargo_lock" && ! -L "$cargo_lock" ]] ||',
                '[[ -f "$cargo_lock" && -f "$cargo_lock" ]] ||',
            ),
            (
                '[[ -f "$cargo_manifest" && ! -L "$cargo_manifest" ]] ||',
                'control_file="$cargo_manifest"; '
                '[[ -f "$control_file" && -n "$cargo_manifest" ]] ||',
            ),
        )
        for source, replacement in mutations:
            with self.subTest(replacement=replacement):
                fixture = Fixture()
                original = fixture.tauri_installer
                fixture.tauri_installer = original.replace(source, replacement, 1)
                self.assertNotEqual(fixture.tauri_installer, original)
                self.assertEqual(fixture.tauri_installer.count("$cargo_manifest"), 5)
                self.assertEqual(fixture.tauri_installer.count("$cargo_lock"), 8)
                self._assert_fails(
                    fixture,
                    "unexpected Cargo control-file reference",
                )

    def test_tauri_cli_installer_binds_workspace_boundary_failures(self) -> None:
        mutations = (
            (
                '[[ -f "$boundary_file" && ! -L "$boundary_file" ]] ||',
                '[[ -f "$boundary_file" ]] ||',
            ),
            (
                '[[ "$(stat -f \'%l\' "$boundary_file")" == "1" ]] ||',
                '[[ "$(stat -f \'%l\' "$boundary_file")" == "2" ]] ||',
            ),
            (
                '"$(stat -f \'%Lp\' "$staging_workspace_lock")" == "600"',
                '"$(stat -f \'%Lp\' "$staging_workspace_lock")" == "644"',
            ),
            (
                '"$staging_workspace_manifest_sha256" '
                '"$staging_workspace_manifest" |',
                '"$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" '
                '"$staging_workspace_manifest" |',
            ),
        )
        for source, replacement in mutations:
            with self.subTest(source=source):
                fixture = Fixture()
                fixture.tauri_installer = fixture.tauri_installer.replace(
                    source,
                    replacement,
                    1,
                )
                self._assert_fails(
                    fixture,
                    "differs from release policy|exact occurrences|"
                    "unexpected workspace input mutation",
                )

    def test_tauri_cli_installer_binds_complete_workspace_verifiers(
        self,
    ) -> None:
        mutations = (
            (
                "shasum -a 256 --check >/dev/null",
                "/usr/bin/true",
            ),
            (
                "printf '%s  %s\\n'",
                "printf '%s   %s\\n'",
            ),
            (
                'die "Tauri source and workspace locks differ"',
                ":",
            ),
            (
                "render_tauri_workspace_manifest | shasum -a 256 |",
                "render_tauri_workspace_manifest | /usr/bin/true |",
            ),
            (
                '--additional-working-directory "$source_root" ||',
                '--additional-working-directory "$source_root" || /usr/bin/true ||',
            ),
        )
        for source, replacement in mutations:
            with self.subTest(source=source):
                fixture = Fixture()
                if source in (
                    "shasum -a 256 --check >/dev/null",
                    "printf '%s  %s\\n'",
                ):
                    # Exercise the workspace verifier itself; the independent
                    # payload checksum gate must not mask a broken workspace.
                    start = fixture.tauri_installer.index(
                        "verify_tauri_workspace_boundary() {"
                    )
                    end = fixture.tauri_installer.index("\n}", start) + 2
                    boundary = fixture.tauri_installer[start:end]
                    self.assertIn(source, boundary)
                    fixture.tauri_installer = (
                        fixture.tauri_installer[:start]
                        + boundary.replace(source, replacement)
                        + fixture.tauri_installer[end:]
                    )
                else:
                    fixture.tauri_installer = fixture.tauri_installer.replace(
                        source,
                        replacement,
                    )
                self._assert_fails(
                    fixture,
                    "differs from release policy",
                )

    def test_tauri_cli_installer_requires_source_ancestor_config_check(self) -> None:
        fixture = Fixture()
        fixture.tauri_installer = fixture.tauri_installer.replace(
            '--additional-working-directory "$source_root"',
            "",
            1,
        )
        self._assert_fails(fixture, "required pinned fragment|exact occurrences")

    def test_tauri_cli_installer_requires_source_checksum_verifier(self) -> None:
        fixture = Fixture()
        original = fixture.tauri_installer
        fixture.tauri_installer = original.replace(
            'shasum -a 256 --check\n',
            '/usr/bin/true\n',
            1,
        )
        self.assertNotEqual(fixture.tauri_installer, original)
        self._assert_fails(
            fixture,
            "differs from release policy|Cargo control-file reference|"
            "lacks ordered operation|required pinned fragment|exact occurrences",
        )

    def test_tauri_cli_installer_requires_payload_checksum_verifier(self) -> None:
        fixture = Fixture()
        original = fixture.tauri_installer
        fixture.tauri_installer = original.replace(
            '    shasum -a 256 --check >/dev/null',
            '    /usr/bin/true',
            1,
        )
        self.assertNotEqual(fixture.tauri_installer, original)
        self._assert_fails(fixture, "exact occurrences")

    def test_tauri_cli_installer_requires_workspace_checksum_verifier(self) -> None:
        fixture = Fixture()
        original = fixture.tauri_installer
        fixture.tauri_installer = original.replace(
            '"$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$staging_workspace_lock" |',
            '"unbound" "$staging_workspace_lock" |',
            1,
        )
        self.assertNotEqual(fixture.tauri_installer, original)
        self._assert_fails(
            fixture,
            "differs from release policy|Cargo control-file reference|"
            "lacks ordered operation|required pinned fragment|exact occurrences",
        )

    def test_tauri_cli_installer_rejects_official_source_check_after_copy(self) -> None:
        fixture = Fixture()
        source_check = (
            "printf '%s  %s\\n' \"$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256\" "
            '"$cargo_lock" |\n'
            "  shasum -a 256 --check\n"
        )
        copy = '/usr/bin/install -m 0600 "$cargo_lock" "$staging_workspace_lock"\n'
        self.assertLess(
            fixture.tauri_installer.index(source_check),
            fixture.tauri_installer.index(copy),
        )
        fixture.tauri_installer = fixture.tauri_installer.replace(
            source_check, "", 1
        ).replace(copy, copy + source_check, 1)
        self._assert_fails(fixture, "Cargo control-file reference|lacks ordered operation")

    def test_tauri_cache_contract_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.extra_files[TAURI_CACHE_CONTRACT_PATH] = "tampered contract\n"
        self._assert_fails(fixture, "cache contract file digest")

    def test_tauri_cache_contract_env_digest_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.env["TAURI_CARGO_CACHE_CONTRACT_SHA256"] = "a" * 64
        self._assert_fails(fixture, "cache contract file digest")

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
        self._assert_fails(
            fixture,
            "patch sing-box DNS failover patch file digest [0-9a-f]{64} differs "
            "from the pinned SING_BOX_DNS_FAILOVER_PATCH_SHA256",
        )

    def test_wrong_endpoint_conflict_patch_env_digest_fails(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256"] = "a" * 64
        self._assert_fails(
            fixture,
            "patch sing-box endpoint conflict patch file digest [0-9a-f]{64} "
            "differs from the pinned SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
        )

    def test_patch_file_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.patch_bodies["security"] = b"tampered body\n"
        self._assert_fails(
            fixture,
            "patch sing-box security dependencies patch file digest "
            f"{_sha(b'tampered body' + bytes([10]))} differs from the pinned "
            "SING_BOX_SECURITY_PATCH_SHA256",
        )

    def test_missing_patch_file_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.patch_bodies["raw"]
        self._assert_fails(fixture, "missing, a symlink, or has an unsafe path")

    def test_coordinated_patch_policy_replacement_fails_fixed_policy(self) -> None:
        # Point one sing-box patch rule at another declared path/digest pin pair.
        fixture = Fixture()
        fixture.manifest["patches"][3] = {
            "name": "unrelated replacement patch",
            "pathKey": "XCODEGEN_DEPENDENCY_PATCH_PATH",
            "sha256Key": "XCODEGEN_DEPENDENCY_PATCH_SHA256",
        }
        self._assert_fails(fixture, "fixed patch policy set")

    def test_legacy_patch_bytes_are_rejected(self) -> None:
        # A rejected digest can only match when the legacy patch bytes return.
        # Treat the synthetic raw-packet body as such a legacy patch.
        fixture = Fixture()
        rejected = {*REJECTED_PATCH_DIGESTS[1:], RAW_SHA}
        fixture.manifest["rejectedPatchDigests"] = sorted(rejected)
        with mock.patch.object(
            pinned_verifier, "REQUIRED_REJECTED_PATCH_DIGESTS", frozenset(rejected)
        ):
            self._assert_fails(fixture, "pins a rejected/legacy digest: " + RAW_SHA)

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
        self._assert_fails(fixture, "equals a single patch digest")

    def test_combined_diff_equal_to_dependency_only_diff_rejected(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_COMBINED_DIFF_SHA256"] = fixture.env[
            "SING_BOX_PATCHED_DIFF_SHA256"
        ]
        self._assert_fails(fixture, "equals the partial go.mod/go.sum diff digest")

    # --- libbox build tags --------------------------------------------------

    def test_missing_engine_start_path_tag_fails(self) -> None:
        # The exact defect this check exists for: dropping with_clash_api while the
        # projection still injects experimental.clash_api, which makes box.New fail
        # on every engine start.
        fixture = Fixture()
        reduced = BUILD_TAGS.replace("with_clash_api,", "", 1)
        fixture.env["LIBBOX_BUILD_TAGS"] = reduced
        self._assert_fails(fixture, "required tag 'with_clash_api'")

    def test_tag_list_without_required_tags_fails(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_BUILD_TAGS"] = "with_quic,grpcnotrace"
        self._assert_fails(fixture, "missing the required tag")

    def test_tag_order_is_not_policy(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_BUILD_TAGS"] = ",".join(reversed(BUILD_TAGS.split(",")))
        self._verify_fixture(fixture)

    def test_missing_tag_pin_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.env["LIBBOX_BUILD_TAGS"]
        self._assert_fails(fixture, "LIBBOX_BUILD_TAGS")

    def test_malformed_tag_fails(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_BUILD_TAGS"] = "with_quic, with_clash_api,grpcnotrace"
        self._assert_fails(fixture, "LIBBOX_BUILD_TAGS is not a go-build-tags value")

    def test_repeated_tag_fails(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_BUILD_TAGS"] = BUILD_TAGS + ",with_quic"
        self._assert_fails(fixture, "repeat 'with_quic'")

    def test_coordinated_build_tag_deletion_still_fails_fixed_policy(self) -> None:
        fixture = Fixture()
        reduced = BUILD_TAGS.replace("with_quic,", "", 1)
        fixture.env["LIBBOX_BUILD_TAGS"] = reduced
        fixture.manifest["libboxBuildTags"]["required"] = [
            entry
            for entry in fixture.manifest["libboxBuildTags"]["required"]
            if entry["tag"] != "with_quic"
        ]
        self._assert_fails(fixture, "pinned libbox build tags differ from release policy")

    def test_same_cardinality_build_tag_replacement_fails_fixed_policy(self) -> None:
        fixture = Fixture()
        replaced = BUILD_TAGS.replace("with_quic", "with_fake", 1)
        fixture.env["LIBBOX_BUILD_TAGS"] = replaced
        entry = next(
            entry for entry in fixture.manifest["libboxBuildTags"]["required"]
            if entry["tag"] == "with_quic"
        )
        entry["tag"] = "with_fake"
        self._assert_fails(fixture, "pinned libbox build tags differ from release policy")

    def test_extra_build_tag_fails_fixed_policy(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_BUILD_TAGS"] = BUILD_TAGS + ",with_naive_outbound"
        self._assert_fails(fixture, "pinned libbox build tags differ from release policy")

    def test_required_tag_table_cannot_shrink(self) -> None:
        fixture = Fixture()
        fixture.manifest["libboxBuildTags"]["required"] = [
            entry
            for entry in fixture.manifest["libboxBuildTags"]["required"]
            if entry["tag"] != "grpcnotrace"
        ]
        self._assert_fails(fixture, "libbox required tags differ from release policy")

    def test_source_binding_without_required_tag_fails(self) -> None:
        # A source trigger may not be satisfied by the required-tag table alone:
        # removing the tag from both the pin and the required table still fails
        # because the tracked source still needs it.
        fixture = Fixture()
        reduced = BUILD_TAGS.replace("with_clash_api,", "", 1)
        fixture.env["LIBBOX_BUILD_TAGS"] = reduced
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
        self._assert_fails(fixture, "line [0-9]+ is malformed")

    def test_pin_file_is_split_like_bash(self) -> None:
        # A form feed or CR would be a line break to the Python parser but part
        # of a value to bash; both are rejected so the verified view is bash's.
        for separator in ("\f", "\r\n", "\v", "\x85"):
            with self.subTest(separator=repr(separator)):
                fixture = Fixture()
                go_version = fixture.env.pop("GO_VERSION")
                fixture.append_env_text(f"GO_VERSION={go_version}{separator}")
                self._assert_fails(fixture, "only printable ASCII lines separated by LF")
        fixture = Fixture()
        fixture.append_env_text(" NODE_VERSION=1.2.3\n")
        self._assert_fails(fixture, "is malformed")

    def test_duplicate_pin_fails(self) -> None:
        fixture = Fixture()
        fixture.append_env_text(f"GO_VERSION={fixture.env['GO_VERSION']}\n")
        self._assert_fails(fixture, "defines GO_VERSION more than once")

    def test_missing_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).unlink()
            with self.assertRaisesRegex(PinnedInputError, "manifest is missing"):
                verify_source_contract(root)

    def test_malformed_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(PinnedInputError, "malformed"):
                verify_source_contract(root)

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
                    verify_source_contract(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            path = root / MANIFEST_RELATIVE_PATH
            body = path.read_text(encoding="utf-8")
            path.write_text(
                '{"schema":"cfw-pinned-build-inputs-v2",' + body[1:],
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PinnedInputError, "duplicate JSON field 'schema'"):
                verify_source_contract(root)

    def test_manifest_rejects_non_utf8_oversize_and_inexact_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).write_bytes(b"\xff")
            with self.assertRaisesRegex(PinnedInputError, "strict UTF-8"):
                verify_source_contract(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).write_bytes(
                b" " * (MAX_PINNED_MANIFEST_BYTES + 1)
            )
            with self.assertRaisesRegex(PinnedInputError, "byte bound"):
                verify_source_contract(root)

        fixture = Fixture()
        fixture.manifest["unexpected"] = True
        self._assert_fails(fixture, "exact top-level shape")

    def test_manifest_rejects_hardlink_symlink_and_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            manifest = root / MANIFEST_RELATIVE_PATH
            os.link(manifest, root / "manifest-hardlink.json")
            with self.assertRaisesRegex(PinnedInputError, "exactly one hard link"):
                verify_source_contract(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            manifest = root / MANIFEST_RELATIVE_PATH
            manifest.unlink()
            manifest.symlink_to(root / "scripts/dependency_pins.env")
            with self.assertRaisesRegex(PinnedInputError, "symlink|unsafe path"):
                verify_source_contract(root)

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
                verify_source_contract(root)

    def test_build_script_hardlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture()
            root = fixture.write(Path(temporary))
            script = root / "scripts/build_libbox.sh"
            os.link(script, root / "build-libbox-hardlink.sh")
            with self.assertRaisesRegex(PinnedInputError, "exactly one hard link"):
                verify_source_contract(root)

    # --- build-script bindings ----------------------------------------------

    def test_build_script_missing_pin_reference_fails(self) -> None:
        fixture = Fixture()
        fixture.build_libbox = fixture.build_libbox.replace("$SING_BOX_COMMIT", "3708fa18")
        self._assert_fails(fixture, "floating version")

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

    def test_ci_unsigned_python_must_match_the_dependency_pin(self) -> None:
        fixture = Fixture()
        self._verify_fixture(fixture)

        pinned = fixture.env["PYTHON_VERSION"]
        major, minor, patch = pinned.split(".")
        fixture.ci_workflow = fixture.ci_workflow.replace(
            f'python-version: "{pinned}"',
            f'python-version: "{major}.{minor}.{int(patch) + 1}"',
        )
        self._assert_fails(fixture, "Python version does not exactly match")


class PinValueCopyTests(unittest.TestCase):
    """Pinned values are written only in scripts/dependency_pins.env."""

    def test_bounded_pin_value_search_finds_copies_but_not_substrings(self) -> None:
        rust = SHIPPED_PINS["RUST_VERSION"]
        self.assertEqual(
            _repeated_pin_values(f"toolchains/rust-{rust}/bin/rustc"), ["RUST_VERSION"]
        )
        self.assertEqual(_repeated_pin_values(f"rust {rust}0 and 1{rust}"), [])
        self.assertEqual(_repeated_pin_values(f"version {rust}.1"), [])

    def test_shipped_policy_repeats_no_pin_value(self) -> None:
        self.assertEqual(
            _repeated_pin_values(json.dumps(SHIPPED_PINNED_MANIFEST)), []
        )

    def test_current_documents_name_pin_keys_not_values(self) -> None:
        # Dated history (CHANGELOG, dated reviews, planning) keeps the values it
        # recorded; current-state documents must name the pin key instead.
        for relative in (
            "README.md",
            "RELEASE.md",
            "docs/parity-checklist.md",
            "docs/physical-evidence-v5.md",
            "docs/supply-chain.md",
            "native/macos/README.md",
            "tools/packet-evidence-endpoint/README.md",
            "tools/physical-transport-peer-ios/README.md",
        ):
            with self.subTest(document=relative):
                text = (REPO_ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(_repeated_pin_values(text), [])


class RepositoryRegularFileReaderTests(unittest.TestCase):
    """Rooted-reader failures inherited by every pinned-input and readiness read."""

    RELATIVE = "tools/fixture/input.txt"
    BODY = b"pinned fixture input\n"

    def _repository(self, temporary: str) -> tuple[Path, Path]:
        root = Path(temporary).resolve()
        source = root / self.RELATIVE
        source.parent.mkdir(parents=True)
        source.write_bytes(self.BODY)
        source.chmod(0o644)
        return root, source

    def _read(self, root: Path, *, maximum_size: int = 1024) -> bytes:
        return pinned_verifier.read_repository_regular_file(
            root,
            self.RELATIVE,
            "fixture input",
            maximum_size=maximum_size,
        )

    def test_owned_regular_file_is_returned_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self._repository(temporary)
            self.assertEqual(self._read(root), self.BODY)

    def test_symlinked_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, source = self._repository(temporary)
            target = source.with_name("input-real.txt")
            source.rename(target)
            source.symlink_to(target.name)
            with self.assertRaisesRegex(PinnedInputError, "symlink|unsafe path"):
                self._read(root)

    def test_symlinked_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, source = self._repository(temporary)
            parent = source.parent
            real_parent = parent.with_name("fixture-real")
            parent.rename(real_parent)
            parent.symlink_to(real_parent.name, target_is_directory=True)
            with self.assertRaisesRegex(PinnedInputError, "parent.*symlink"):
                self._read(root)

    def test_hard_linked_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, source = self._repository(temporary)
            os.link(source, source.with_name("input-hardlink.txt"))
            with self.assertRaisesRegex(PinnedInputError, "exactly one hard link"):
                self._read(root)

    def test_non_regular_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, source = self._repository(temporary)
            source.unlink()
            source.mkdir(mode=0o755)
            with self.assertRaisesRegex(PinnedInputError, "not a regular file"):
                self._read(root)

    def test_missing_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, source = self._repository(temporary)
            source.unlink()
            with self.assertRaisesRegex(PinnedInputError, "missing"):
                self._read(root)

    def test_foreign_owner_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self._repository(temporary)
            with (
                mock.patch(
                    "scripts.verify_pinned_build_inputs.os.geteuid",
                    return_value=os.geteuid() + 1,
                ),
                self.assertRaisesRegex(PinnedInputError, "effective user"),
            ):
                self._read(root)

    def test_group_or_other_writable_file_is_rejected(self) -> None:
        for mode in (0o664, 0o646):
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory() as temporary:
                root, source = self._repository(temporary)
                source.chmod(mode)
                with self.assertRaisesRegex(
                    PinnedInputError, "writable by group or other users"
                ):
                    self._read(root)

    def test_oversized_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self._repository(temporary)
            with self.assertRaisesRegex(PinnedInputError, "byte bound"):
                self._read(root, maximum_size=len(self.BODY) - 1)

    def test_metadata_drift_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, source = self._repository(temporary)
            source_identity = (source.stat().st_dev, source.stat().st_ino)
            real_read = os.read
            drifted = False

            def drift_mode(descriptor: int, count: int) -> bytes:
                nonlocal drifted
                metadata = os.fstat(descriptor)
                if not drifted and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == source_identity:
                    drifted = True
                    source.chmod(0o600)
                return real_read(descriptor, count)

            with (
                mock.patch(
                    "scripts.verify_pinned_build_inputs.os.read",
                    side_effect=drift_mode,
                ),
                self.assertRaisesRegex(PinnedInputError, "metadata changed"),
            ):
                self._read(root)
            self.assertTrue(drifted)

    def test_parent_replacement_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, source = self._repository(temporary)
            source_identity = (source.stat().st_dev, source.stat().st_ino)
            real_read = os.read
            replaced = False

            def replace_parent(descriptor: int, count: int) -> bytes:
                nonlocal replaced
                metadata = os.fstat(descriptor)
                if not replaced and (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == source_identity:
                    replaced = True
                    source.parent.rename(source.parent.with_name("fixture-held"))
                    source.parent.mkdir(mode=0o755)
                    source.write_bytes(b"unpinned replacement")
                    source.chmod(0o644)
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
                self._read(root)
            self.assertTrue(replaced)


class PinnedVerifierEntrypointTests(unittest.TestCase):
    def test_entrypoint_exits_nonzero_when_the_pinned_contract_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary).resolve() / "scripts"
            scripts.mkdir()
            for name in (
                "verify_pinned_build_inputs.py",
                "verify_pinned_source_contract.py",
            ):
                shutil.copyfile(REPO_ROOT / "scripts" / name, scripts / name)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(scripts / "verify_pinned_source_contract.py"),
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertTrue(
                completed.stderr.startswith("error: pinned source contract failed: "),
                completed.stderr,
            )


if __name__ == "__main__":
    unittest.main()
