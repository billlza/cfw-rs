#!/usr/bin/env bash
# Install the pinned Tauri CLI from its checksum-bound crates.io source archive.
#
# Tauri CLI 2.11.4's published Cargo.lock selects yanked spin 0.9.8. Cargo
# correctly warns when installing that lock directly. This bootstrap boundary
# applies the repository's digest-pinned, one-package lock update to spin 0.9.9,
# then installs from the resulting local source with --locked. Product builds
# remain offline and never invoke this script implicitly.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"

die() {
  echo "error: $*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die "usage: scripts/install_pinned_tauri_cli.sh"
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "the pinned Tauri CLI bootstrap supports only Apple Silicon macOS"

readonly configured_toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
if [[ "$configured_toolchain_root" == /* ]]; then
  selected_toolchain_root="$configured_toolchain_root"
else
  selected_toolchain_root="$repo_root/$configured_toolchain_root"
fi
mkdir -p "$selected_toolchain_root"
[[ -d "$selected_toolchain_root" && ! -L "$selected_toolchain_root" ]] ||
  die "toolchain root must be a real directory"
toolchain_root="$(cd "$selected_toolchain_root" && pwd -P)"
readonly selected_toolchain_root toolchain_root
readonly install_root="$toolchain_root/tauri-cli-$TAURI_CLI_VERSION"
readonly install_manifest="$toolchain_root/tauri-cli-$TAURI_CLI_VERSION.manifest.json"
readonly preparation_root="$toolchain_root/preparation/tauri-cli-$TAURI_CLI_VERSION"
readonly prepared_archive="$preparation_root/tauri-cli-$TAURI_CLI_VERSION.crate"
readonly prepared_cargo_home="$preparation_root/cargo-home"

verify_tauri_payload_layout() {
  local root="$1"
  local forbidden_prefix="${2:-}"
  local binary="$root/bin/cargo-tauri"
  local source="$root/source"

  [[ -d "$root" && ! -L "$root" ]] || die "Tauri CLI payload root is unsafe"
  [[ -x "$binary" && -f "$binary" && ! -L "$binary" ]] ||
    die "Tauri CLI payload has no regular executable"
  [[ "$(stat -f '%l' "$binary")" == "1" ]] ||
    die "Tauri CLI executable must not have hard links"
  [[ "$(/usr/bin/lipo -archs "$binary")" == "arm64" ]] ||
    die "Tauri CLI executable must be thin arm64"
  [[ -d "$source" && ! -L "$source" ]] ||
    die "Tauri CLI payload has no clean source tree"
  for required in Cargo.toml Cargo.lock LICENSE_APACHE-2.0 LICENSE_MIT; do
    [[ -f "$source/$required" && ! -L "$source/$required" ]] ||
      die "Tauri CLI payload source is missing $required"
    [[ "$(stat -f '%l' "$source/$required")" == "1" ]] ||
      die "Tauri CLI payload source file must not have hard links: $required"
  done
  printf '%s  %s\n' "$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256" "$source/Cargo.lock" |
    shasum -a 256 --check >/dev/null

  PYTHONDONTWRITEBYTECODE=1 python3 -B - \
    "$root" "$forbidden_prefix" "$TAURI_CLI_VERSION" <<'PY'
import os
import re
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
forbidden = sys.argv[2].encode("utf-8")
expected_version = sys.argv[3]
if {entry.name for entry in root.iterdir()} != {"bin", "source"}:
    raise SystemExit("error: Tauri CLI payload has an unexpected top-level layout")
if {entry.name for entry in (root / "bin").iterdir()} != {"cargo-tauri"}:
    raise SystemExit("error: Tauri CLI payload bin directory has unexpected entries")
for current, directories, files in os.walk(root / "source", topdown=True, followlinks=False):
    current_path = Path(current)
    for name in [*directories, *files]:
        path = current_path / name
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise SystemExit(f"error: Tauri CLI source contains a symlink: {path}")
        if name == "target" and stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"error: Tauri CLI payload contains a Cargo target tree: {path}")
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise SystemExit(f"error: Tauri CLI source contains a hard link: {path}")
            if forbidden and forbidden in path.read_bytes():
                raise SystemExit(f"error: Tauri CLI payload embeds its temporary build path: {path}")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"error: Tauri CLI source contains an unsupported entry: {path}")
binary = root / "bin/cargo-tauri"
if forbidden and forbidden in binary.read_bytes():
    raise SystemExit("error: Tauri CLI executable embeds its temporary build path")
manifest = (root / "source/Cargo.toml").read_text(encoding="utf-8")
if not re.search(r'(?m)^name = "tauri-cli"$', manifest):
    raise SystemExit("error: Tauri CLI payload source has the wrong package name")
if not re.search(rf'(?m)^version = "{re.escape(expected_version)}"$', manifest):
    raise SystemExit("error: Tauri CLI payload source has the wrong version")
PY
}

verify_cargo_preparation_cache() {
  local root="$1"
  [[ -d "$root" && ! -L "$root" ]] ||
    die "Tauri CLI preparation cache must be a real directory"
  PYTHONDONTWRITEBYTECODE=1 python3 -B - "$root" <<'PY'
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
allowed = {".global-cache", ".package-cache", ".package-cache-mutate", "registry"}
unexpected = sorted(entry.name for entry in root.iterdir() if entry.name not in allowed)
if unexpected:
    raise SystemExit(
        f"error: Tauri CLI preparation cache has unsafe top-level entries: {unexpected!r}"
    )
for current, directories, files in os.walk(root, topdown=True, followlinks=False):
    current_path = Path(current)
    for name in [*directories, *files]:
        path = current_path / name
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise SystemExit(f"error: Tauri CLI preparation cache contains a symlink: {path}")
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise SystemExit(
                    f"error: Tauri CLI preparation cache contains a hard link: {path}"
                )
        elif not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(
                f"error: Tauri CLI preparation cache contains an unsupported entry: {path}"
            )
PY
}

if [[ -e "$install_root" || -L "$install_root" || -e "$install_manifest" || -L "$install_manifest" ]]; then
  [[ -d "$install_root" && ! -L "$install_root" && -f "$install_manifest" && ! -L "$install_manifest" ]] ||
    die "refusing to reuse incomplete Tauri CLI evidence"
  cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
  installed_binary="$install_root/bin/cargo-tauri"
  verify_tauri_payload_layout "$install_root"
  [[ "$($installed_binary --version)" == "tauri-cli $TAURI_CLI_VERSION" ]] ||
    die "installed tauri-cli identity mismatch"
  cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
  echo "tauri-cli $TAURI_CLI_VERSION tree verified"
  exit 0
fi

readonly rust_toolchain="$RUST_VERSION-aarch64-apple-darwin"
rustup_bin="$(command -v rustup || true)"
[[ "$rustup_bin" == /* && -x "$rustup_bin" ]] ||
  die "an absolute rustup executable is required"
cargo_bin="$("$rustup_bin" which --toolchain "$rust_toolchain" cargo)"
rustc_bin="$("$rustup_bin" which --toolchain "$rust_toolchain" rustc)"
readonly rustup_bin cargo_bin rustc_bin
[[ "$cargo_bin" == /* && "$rustc_bin" == /* && -x "$cargo_bin" && -x "$rustc_bin" ]] ||
  die "rustup did not resolve absolute pinned cargo and rustc executables"
[[ "$(dirname "$cargo_bin")" == "$(dirname "$rustc_bin")" ]] ||
  die "pinned cargo and rustc must come from one toolchain"
[[ "$($rustc_bin --version | awk '{print $2}')" == "$RUST_VERSION" ]] ||
  die "rustc $RUST_VERSION for aarch64-apple-darwin is required"
[[ "$($cargo_bin --version | awk '{print $2}')" == "$RUST_VERSION" ]] ||
  die "cargo $RUST_VERSION for aarch64-apple-darwin is required"
[[ "$(/usr/bin/lipo -archs "$cargo_bin")" == "arm64" ]] ||
  die "pinned cargo must be thin arm64"
[[ "$(/usr/bin/lipo -archs "$rustc_bin")" == "arm64" ]] ||
  die "pinned rustc must be thin arm64"

developer_dir="${DEVELOPER_DIR:-$(xcode-select -p)}"
readonly developer_dir
[[ "$(DEVELOPER_DIR="$developer_dir" xcodebuild -version)" == \
  "Xcode $XCODE_VERSION"$'\n'"Build version $XCODE_BUILD_VERSION" ]] ||
  die "Xcode $XCODE_VERSION ($XCODE_BUILD_VERSION) is required"
sdk_root="$(DEVELOPER_DIR="$developer_dir" /usr/bin/xcrun --sdk macosx --show-sdk-path)"
readonly sdk_root

readonly lock_patch="$repo_root/$TAURI_CLI_LOCK_PATCH_PATH"
[[ -f "$lock_patch" && ! -L "$lock_patch" ]] ||
  die "the pinned Tauri CLI lock patch is missing or not a regular file"
printf '%s  %s\n' "$TAURI_CLI_LOCK_PATCH_SHA256" "$lock_patch" |
  shasum -a 256 --check

readonly temporary_parent="${TMPDIR:-/tmp}"
[[ -d "$temporary_parent" && ! -L "$temporary_parent" ]] ||
  die "the temporary directory is missing, not a directory, or a symlink"
staging="$(mktemp -d "$temporary_parent/cfw-tauri-cli.XXXXXX")"
cleanup() {
  /bin/rm -rf -- "$staging"
}
trap cleanup EXIT

readonly source_root="$staging/tauri-cli-$TAURI_CLI_VERSION"
mkdir -p "$preparation_root" "$prepared_cargo_home"
[[ -d "$preparation_root" && ! -L "$preparation_root" ]] ||
  die "Tauri CLI preparation root must be a real directory"
verify_cargo_preparation_cache "$prepared_cargo_home"
if [[ -e "$prepared_archive" || -L "$prepared_archive" ]]; then
  [[ -f "$prepared_archive" && ! -L "$prepared_archive" ]] ||
    die "cached Tauri CLI crate must be a regular file"
  printf '%s  %s\n' "$TAURI_CLI_CRATE_SHA256" "$prepared_archive" |
    shasum -a 256 --check >/dev/null
else
  readonly downloaded_archive="$staging/tauri-cli-$TAURI_CLI_VERSION.crate.download"
  curl --fail --location --proto '=https' --tlsv1.2 \
    "https://static.crates.io/crates/tauri-cli/tauri-cli-$TAURI_CLI_VERSION.crate" \
    --output "$downloaded_archive"
  printf '%s  %s\n' "$TAURI_CLI_CRATE_SHA256" "$downloaded_archive" |
    shasum -a 256 --check
  [[ ! -e "$prepared_archive" && ! -L "$prepared_archive" ]] ||
    die "Tauri CLI crate cache appeared concurrently"
  /usr/bin/install -m 0644 "$downloaded_archive" "$prepared_archive"
fi
readonly archive="$prepared_archive"

# The archive digest identifies the official payload. Validate its shape as a
# second boundary before asking tar to write it, rejecting links, special files,
# absolute paths, path traversal, and entries outside the expected crate root.
PYTHONDONTWRITEBYTECODE=1 python3 -B - "$archive" "tauri-cli-$TAURI_CLI_VERSION" <<'PY'
import sys
import tarfile
from pathlib import PurePosixPath

archive_path, expected_root = sys.argv[1:]
with tarfile.open(archive_path, mode="r:gz") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("error: the pinned Tauri CLI archive is empty")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or not path.parts or path.parts[0] != expected_root:
            raise SystemExit(f"error: unsafe Tauri CLI archive path: {member.name!r}")
        if any(part in ("", ".", "..") for part in path.parts):
            raise SystemExit(f"error: unsafe Tauri CLI archive component: {member.name!r}")
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"error: unsupported Tauri CLI archive entry: {member.name!r}")
PY
/usr/bin/tar -xzf "$archive" -C "$staging"
printf '%s  %s\n' "$TAURI_CLI_CRATE_SHA256" "$archive" |
  shasum -a 256 --check >/dev/null

readonly cargo_manifest="$source_root/Cargo.toml"
readonly cargo_lock="$source_root/Cargo.lock"
[[ -f "$cargo_manifest" && ! -L "$cargo_manifest" ]] ||
  die "the pinned Tauri CLI archive has no regular Cargo.toml"
[[ -f "$cargo_lock" && ! -L "$cargo_lock" ]] ||
  die "the pinned Tauri CLI archive has no regular Cargo.lock"
printf '%s  %s\n' "$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" "$cargo_lock" |
  shasum -a 256 --check

# The exact upstream lock digest was verified above, so the two zero-context
# scalar replacements cannot be redirected onto a different published lock.
git -C "$source_root" apply --unidiff-zero --check "$lock_patch"
git -C "$source_root" apply --unidiff-zero "$lock_patch"
printf '%s  %s\n' "$TAURI_CLI_LOCK_PATCH_SHA256" "$lock_patch" |
  shasum -a 256 --check >/dev/null
printf '%s  %s\n' "$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256" "$cargo_lock" |
  shasum -a 256 --check

PYTHONDONTWRITEBYTECODE=1 python3 -B - \
  "$cargo_manifest" \
  "$cargo_lock" \
  "$TAURI_CLI_VERSION" \
  "$TAURI_CLI_SPIN_VERSION" \
  "$TAURI_CLI_SPIN_CRATE_SHA256" <<'PY'
import re
import sys
from pathlib import Path

manifest_path, lock_path, cli_version, spin_version, spin_checksum = sys.argv[1:]
manifest = Path(manifest_path).read_text(encoding="utf-8")
if not re.search(r'(?m)^name = "tauri-cli"$', manifest):
    raise SystemExit("error: the pinned archive is not the tauri-cli crate")
if not re.search(rf'(?m)^version = "{re.escape(cli_version)}"$', manifest):
    raise SystemExit("error: the pinned archive has the wrong tauri-cli version")

records = []
for block in Path(lock_path).read_text(encoding="utf-8").split("[[package]]")[1:]:
    fields = dict(re.findall(r'(?m)^(name|version|checksum) = "([^"]+)"$', block))
    if fields.get("name") == "spin":
        records.append(fields)
expected = {"name": "spin", "version": spin_version, "checksum": spin_checksum}
if records != [expected]:
    raise SystemExit(f"error: patched Tauri CLI lock has unexpected spin records: {records!r}")
PY

# Network access is a resumable preparation phase. It uses only the dedicated
# cache below; a user's Cargo home is never consulted. A failed attempt leaves
# already checksum-verified crates available for the next explicit retry.
readonly fetch_home="$staging/fetch-home"
readonly fetch_target="$staging/fetch-target"
readonly fetch_tmp="$staging/fetch-tmp"
mkdir -p "$fetch_home" "$fetch_target" "$fetch_tmp"
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
  RUSTC="$rustc_bin" \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_SYSTEM=/dev/null \
  "$cargo_bin" fetch \
  --manifest-path "$cargo_manifest" \
  --locked \
  --target aarch64-apple-darwin; then
  :
else
  die "checksum-bound Tauri CLI dependency preparation failed; the isolated cache was preserved"
fi
verify_cargo_preparation_cache "$prepared_cargo_home"

# Final compilation gets a snapshot of the prepared cache and is forced
# offline. The snapshot is fully verified before and after Cargo executes, so
# the compile cannot mutate or substitute its dependency input.
readonly offline_cargo_home="$staging/offline-cargo-home"
readonly offline_cache_manifest="$staging/offline-cargo-home.manifest.json"
/usr/bin/ditto --noqtn "$prepared_cargo_home" "$offline_cargo_home"
verify_cargo_preparation_cache "$offline_cargo_home"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$offline_cargo_home" \
  --output "$offline_cache_manifest" \
  --algorithm sha256-tree-v2 \
  --metadata "artifactKind=pinned-tauri-offline-cache-v1" \
  --metadata "patchedCargoLockSha256=$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256" \
  --metadata "rustToolchain=$rust_toolchain"
offline_cache_sha256_before="$(cfw_verify_release_toolchain_manifest \
  "$repo_root" \
  "$offline_cargo_home" \
  "$offline_cache_manifest" \
  "artifactKind=pinned-tauri-offline-cache-v1" \
  "patchedCargoLockSha256=$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256" \
  "rustToolchain=$rust_toolchain")"
readonly offline_cache_sha256_before

readonly install_log="$staging/cargo-install.log"
readonly cargo_install_root="$staging/cargo-root"
readonly cargo_target="$staging/cargo-target"
readonly isolated_home="$staging/home"
readonly isolated_tmp="$staging/tmp"
mkdir -p "$cargo_install_root" "$cargo_target" "$isolated_home" "$isolated_tmp"
if /usr/bin/env -i \
  HOME="$isolated_home" \
  TMPDIR="$isolated_tmp" \
  LANG=C \
  LC_ALL=C \
  PATH="$(dirname "$cargo_bin"):/usr/bin:/bin:/usr/sbin:/sbin" \
  DEVELOPER_DIR="$developer_dir" \
  SDKROOT="$sdk_root" \
  MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" \
  CARGO_CACHE_RUSTC_INFO=0 \
  CARGO_HOME="$offline_cargo_home" \
  CARGO_INCREMENTAL=0 \
  CARGO_NET_OFFLINE=true \
  CARGO_TARGET_DIR="$cargo_target" \
  CARGO_NET_RETRY=0 \
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
  CARGO_TERM_COLOR=never \
  RUSTFLAGS="--remap-path-prefix=$staging=/cfw/toolchain-build" \
  RUSTC="$rustc_bin" \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_SYSTEM=/dev/null \
  "$cargo_bin" install \
  --path "$source_root" \
  --offline \
  --locked \
  --target aarch64-apple-darwin \
  --force \
  --root "$cargo_install_root" 2>&1 | tee "$install_log"; then
  :
else
  die "checksum-bound tauri-cli installation failed"
fi
readonly cargo_path_warning="^warning: be sure to add \`[^\`]+/bin\` to your PATH to be able to run the installed binaries\$"
[[ "$(grep -Ec "$cargo_path_warning" "$install_log")" == "1" ]] ||
  die "tauri-cli installation did not emit the exact expected Cargo PATH notice"
if grep -Ev "$cargo_path_warning" "$install_log" |
  grep -Eiq '(^|[[:space:]])warning([[:space:]]|:)'; then
  die "tauri-cli installation emitted a warning"
fi
offline_cache_sha256_after="$(cfw_verify_release_toolchain_manifest \
  "$repo_root" \
  "$offline_cargo_home" \
  "$offline_cache_manifest" \
  "artifactKind=pinned-tauri-offline-cache-v1" \
  "patchedCargoLockSha256=$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256" \
  "rustToolchain=$rust_toolchain")"
readonly offline_cache_sha256_after
[[ "$offline_cache_sha256_after" == "$offline_cache_sha256_before" ]] ||
  die "Tauri CLI offline dependency cache changed during compilation"

readonly cargo_installed_binary="$cargo_install_root/bin/cargo-tauri"
[[ -x "$cargo_installed_binary" ]] ||
  die "cargo-tauri was not installed at $cargo_installed_binary"
[[ ! -e "$source_root/target" && ! -L "$source_root/target" ]] ||
  die "isolated Tauri CLI build polluted the pinned source tree"
readonly payload="$staging/payload/tauri-cli-$TAURI_CLI_VERSION"
mkdir -p "$payload/bin"
/usr/bin/install -m 0755 "$cargo_installed_binary" "$payload/bin/cargo-tauri"
/bin/mv "$source_root" "$payload/source"
verify_tauri_payload_layout "$payload" "$staging"
[[ "$("$payload/bin/cargo-tauri" --version)" == "tauri-cli $TAURI_CLI_VERSION" ]] ||
  die "installed tauri-cli identity mismatch"
verify_tauri_payload_layout "$payload" "$staging"
python3 "$repo_root/scripts/hash_artifact.py" \
  "$payload" \
  --output "$staging/tauri-cli-$TAURI_CLI_VERSION.manifest.json" \
  --algorithm sha256-tree-v2 \
  --metadata "artifactKind=pinned-tauri-cli-v2" \
  --metadata "crateSha256=$TAURI_CLI_CRATE_SHA256" \
  --metadata "dependencyMode=isolated-fetch-offline-locked-v1" \
  --metadata "lockPatchSha256=$TAURI_CLI_LOCK_PATCH_SHA256" \
  --metadata "macosDeploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
  --metadata "patchedCargoLockSha256=$TAURI_CLI_PATCHED_CARGO_LOCK_SHA256" \
  --metadata "payloadLayout=bin-and-patched-source-v1" \
  --metadata "platform=darwin-arm64" \
  --metadata "rustToolchain=$rust_toolchain" \
  --metadata "spinCrateSha256=$TAURI_CLI_SPIN_CRATE_SHA256" \
  --metadata "spinVersion=$TAURI_CLI_SPIN_VERSION" \
  --metadata "upstreamCargoLockSha256=$TAURI_CLI_UPSTREAM_CARGO_LOCK_SHA256" \
  --metadata "version=$TAURI_CLI_VERSION" \
  --metadata "xcodeBuild=$XCODE_BUILD_VERSION" \
  --metadata "xcodeVersion=$XCODE_VERSION"
/bin/mv "$payload" "$install_root"
/bin/mv "$staging/tauri-cli-$TAURI_CLI_VERSION.manifest.json" "$install_manifest"
cfw_verify_tauri_toolchain_tree "$repo_root" "$toolchain_root"
echo "tauri-cli $TAURI_CLI_VERSION installed from checksum-bound patched source"
