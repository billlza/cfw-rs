#!/usr/bin/env bash
# Verify the complete, already signed macOS application before any release
# container or updater archive is created. This is intentionally fail closed.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/libbox_source_contract.sh
source "$repo_root/scripts/libbox_source_contract.sh"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"
readonly toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"

readonly expected_team_id="YKUPL7Z869"
readonly expected_version="0.4.0"
readonly expected_app_id="com.bill.clashformac"
readonly expected_extension_id="com.bill.clashformac.packet-tunnel"
readonly expected_extension_wrapper="$expected_extension_id.systemextension"
readonly expected_extension_executable="CFWPacketTunnel"
readonly expected_agent_id="com.bill.clashformac.proxy-agent"
readonly expected_authority_id="com.bill.clashformac.global-authority"
readonly expected_app_group="YKUPL7Z869.group.com.bill.clashformac"
readonly expected_agent_keychain_access_group="YKUPL7Z869.com.bill.clashformac.proxy-agent"
readonly expected_credential_keychain_access_group="YKUPL7Z869.com.bill.clashformac.credentials"
readonly expected_extension_keychain_access_group="YKUPL7Z869.com.bill.clashformac.packet-tunnel"
readonly expected_minimum_system="15.0"

die() {
  echo "error: $*" >&2
  exit 1
}

python_bin="${CFW_RELEASE_PYTHON_EXECUTABLE:-}"
[[ "$python_bin" == /* && -x "$python_bin" ]] ||
  die "closed release Python interpreter is unavailable"
readonly python_bin

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

plist_value() {
  /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null ||
    die "missing or unreadable plist key $2 in $1"
}

require_regular_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "expected a regular, non-symlink file: $path"
  [[ "$(stat -f '%l' "$path")" == "1" ]] || die "release input must not have hard links: $path"
}

assert_semver() {
  local version="$1"
  local semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
  [[ "$version" =~ $semver ]] || die "version is not a strict SemVer value: $version"
}

assert_bundle_info() {
  local bundle="$1"
  local expected_identifier="$2"
  local expected_package_type="$3"
  local info="$bundle/Contents/Info.plist"
  require_regular_file "$info"
  [[ "$(plist_value "$info" CFBundleIdentifier)" == "$expected_identifier" ]] ||
    die "unexpected bundle identifier in $bundle"
  [[ "$(plist_value "$info" CFBundlePackageType)" == "$expected_package_type" ]] ||
    die "unexpected package type in $bundle"
  [[ "$(plist_value "$info" LSMinimumSystemVersion)" == "$expected_minimum_system" ]] ||
    die "$bundle must declare macOS $expected_minimum_system as its minimum system"
  assert_semver "$(plist_value "$info" CFBundleShortVersionString)"
}

codesign_details() {
  local code="$1"
  codesign -d --verbose=4 "$code" 2>&1
}

assert_developer_id_signature() {
  local code="$1"
  local expected_identifier="${2:-}"
  local details certificate_prefix certificate_sha256
  codesign --verify --strict --verbose=4 "$code"
  details="$(codesign_details "$code")"
  local team_identifier
  team_identifier="$(printf '%s\n' "$details" | awk -F= '$1 == "TeamIdentifier" { print substr($0, 16); exit }')"
  [[ "$team_identifier" == "$expected_team_id" ]] ||
    die "signature Team ID mismatch for $code"
  [[ "$details" == *"Authority=Developer ID Application:"*"($expected_team_id)"* ]] ||
    die "Developer ID Application authority mismatch for $code"
  [[ "$details" =~ flags=.*runtime ]] || die "hardened runtime is missing for $code"
  local timestamp
  timestamp="$(printf '%s\n' "$details" | awk -F= '$1 == "Timestamp" { print substr($0, 11); exit }')"
  [[ -n "$timestamp" && "$timestamp" != "none" ]] ||
    die "secure signing timestamp is missing for $code"
  [[ "$details" != *"Signature=adhoc"* ]] || die "ad-hoc signature is forbidden for $code"
  if [[ -n "$expected_identifier" ]]; then
    local signed_identifier
    signed_identifier="$(printf '%s\n' "$details" | awk -F= '$1 == "Identifier" { print substr($0, 12); exit }')"
    [[ "$signed_identifier" == "$expected_identifier" ]] ||
      die "code signature identifier mismatch for $code"
  fi
  certificate_capture_sequence=$((certificate_capture_sequence + 1))
  certificate_prefix="$temporary_root/leaf-certificate-$certificate_capture_sequence-"
  codesign -d --extract-certificates="$certificate_prefix" "$code" >/dev/null 2>&1 ||
    die "cannot extract the Developer ID leaf certificate from $code"
  require_regular_file "${certificate_prefix}0"
  certificate_sha256="$(
    /usr/bin/shasum -a 256 "${certificate_prefix}0" |
      /usr/bin/awk '{print toupper($1)}'
  )"
  [[ "$certificate_sha256" == "$expected_signing_certificate_sha256" ]] ||
    die "Developer ID leaf certificate differs from the frozen preflight for $code"
}

extract_entitlements() {
  local code="$1"
  local output="$2"
  codesign -d --entitlements - --xml "$code" >"$output" 2>/dev/null ||
    die "cannot extract signed entitlements from $code"
  plutil -lint "$output" >/dev/null || die "invalid signed entitlements for $code"
}

verify_entitlements() {
  local entitlement_path="$1"
  local kind="$2"
  local bundle_identifier="$3"
  "$python_bin" -I -S -B -W error - "$entitlement_path" "$kind" "$bundle_identifier" \
    "$expected_team_id" "$expected_app_group" "$expected_agent_keychain_access_group" \
    "$expected_extension_keychain_access_group" "$repo_root" <<'PY'
import plistlib
from pathlib import Path
import sys

(
    path,
    kind,
    bundle_id,
    team_id,
    app_group,
    agent_keychain_group,
    extension_keychain_group,
    repo_root,
) = sys.argv[1:]
sys.path.insert(0, str(Path(repo_root) / "scripts"))
from release_entitlement_contract import EntitlementContractError
from release_entitlement_contract import KEYCHAIN_ACCESS_GROUPS
from release_entitlement_contract import verify_signed_keychain_access_group

with open(path, "rb") as handle:
    entitlements = plistlib.load(handle)

def require(key, expected):
    actual = entitlements.get(key)
    if actual != expected:
        raise SystemExit(
            f"error: {kind} signed entitlement {key!r} is {actual!r}, expected {expected!r}"
        )

require("com.apple.developer.team-identifier", team_id)
application_identifier = entitlements.get("com.apple.application-identifier")
if application_identifier is None:
    application_identifier = entitlements.get("application-identifier")
if application_identifier != f"{team_id}.{bundle_id}":
    raise SystemExit(
        f"error: {kind} application identifier is {application_identifier!r}, "
        f"expected {team_id}.{bundle_id!s}"
    )
try:
    verify_signed_keychain_access_group(
        entitlements, kind, agent_keychain_group, extension_keychain_group
    )
except EntitlementContractError as error:
    raise SystemExit(f"error: {error}") from error

identifier_keys = {
    key
    for key in ("com.apple.application-identifier", "application-identifier")
    if key in entitlements
}
if len(identifier_keys) != 1:
    raise SystemExit(f"error: {kind} must contain exactly one application identifier entitlement")
allowed_keys = {
    "com.apple.developer.team-identifier",
    *identifier_keys,
}

for forbidden in (
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.allow-jit",
):
    if entitlements.get(forbidden):
        raise SystemExit(f"error: {kind} contains forbidden release entitlement {forbidden}")

packet_tunnel = ["packet-tunnel-provider-systemextension"]
if kind == "host":
    allowed_keys.update({
        "com.apple.security.application-groups",
        "com.apple.developer.system-extension.install",
        "com.apple.developer.networking.networkextension",
        KEYCHAIN_ACCESS_GROUPS,
    })
    require("com.apple.security.application-groups", [app_group])
    require("com.apple.developer.system-extension.install", True)
    require("com.apple.developer.networking.networkextension", packet_tunnel)
elif kind == "packet-tunnel":
    allowed_keys.update({
        "com.apple.developer.networking.networkextension",
        "com.apple.security.app-sandbox",
        "com.apple.security.application-groups",
        "com.apple.security.network.client",
        "com.apple.security.network.server",
    })
    require("com.apple.developer.networking.networkextension", packet_tunnel)
    require("com.apple.security.app-sandbox", True)
    require("com.apple.security.application-groups", [app_group])
    require("com.apple.security.network.client", True)
    require("com.apple.security.network.server", True)
elif kind == "proxy-agent":
    allowed_keys.update({
        "com.apple.security.application-groups",
        KEYCHAIN_ACCESS_GROUPS,
    })
    require("com.apple.security.application-groups", [app_group])
unexpected = set(entitlements) - allowed_keys
if unexpected:
    raise SystemExit(f"error: {kind} contains unexpected signed entitlements: {sorted(unexpected)}")
PY
}

verify_provisioning_profile() {
  local bundle="$1"
  local kind="$2"
  local bundle_identifier="$3"
  local signed_entitlements="$4"
  local profile="$bundle/Contents/embedded.provisionprofile"
  local decoded_profile="$temporary_root/${kind}-profile.plist"
  local certificate_prefix="$temporary_root/${kind}-signing-certificate"
  require_regular_file "$profile"
  security cms -D -i "$profile" >"$decoded_profile" ||
    die "cannot decode provisioning profile for $bundle"
  plutil -lint "$decoded_profile" >/dev/null || die "invalid provisioning profile for $bundle"
  codesign -d --extract-certificates="$certificate_prefix" "$bundle" >/dev/null 2>&1 ||
    die "cannot extract signing certificate from $bundle"
  require_regular_file "${certificate_prefix}0"

  "$python_bin" -I -S -B -W error - \
    "$decoded_profile" "$signed_entitlements" "${certificate_prefix}0" \
    "$kind" "$bundle_identifier" "$expected_team_id" "$expected_app_group" \
    "$expected_agent_keychain_access_group" "$expected_extension_keychain_access_group" \
    "$repo_root" <<'PY'
from datetime import datetime, timezone
import plistlib
from pathlib import Path
import sys

(
    profile_path,
    signed_path,
    certificate_path,
    kind,
    bundle_id,
    team_id,
    app_group,
    agent_keychain_group,
    extension_keychain_group,
    repo_root,
) = sys.argv[1:]
sys.path.insert(0, str(Path(repo_root) / "scripts"))
from release_entitlement_contract import EntitlementContractError
from release_entitlement_contract import verify_profile_capability_authorizations
from release_entitlement_contract import verify_profile_keychain_access_group

with open(profile_path, "rb") as handle:
    profile = plistlib.load(handle)
with open(signed_path, "rb") as handle:
    signed = plistlib.load(handle)
with open(certificate_path, "rb") as handle:
    signing_certificate = handle.read()

if profile.get("TeamIdentifier") != [team_id]:
    raise SystemExit(f"error: {kind} provisioning TeamIdentifier is not exactly {team_id}")
if profile.get("ApplicationIdentifierPrefix") != [team_id]:
    raise SystemExit(f"error: {kind} provisioning application prefix is not exactly {team_id}")
if profile.get("ProvisionsAllDevices") is not True or profile.get("ProvisionedDevices"):
    raise SystemExit(f"error: {kind} must use an all-device Developer ID provisioning profile")
platforms = profile.get("Platform")
if not isinstance(platforms, list) or not ({"OSX", "macOS"} & set(platforms)):
    raise SystemExit(f"error: {kind} provisioning profile is not for macOS")
expiration = profile.get("ExpirationDate")
creation = profile.get("CreationDate")
now = datetime.now(timezone.utc)
if not isinstance(profile.get("UUID"), str) or not profile["UUID"]:
    raise SystemExit(f"error: {kind} provisioning profile has no UUID")
if not isinstance(creation, datetime) or creation.replace(tzinfo=timezone.utc) > now:
    raise SystemExit(f"error: {kind} provisioning profile has an invalid creation date")
if not isinstance(expiration, datetime):
    raise SystemExit(f"error: {kind} provisioning profile has no expiration date")
if expiration.replace(tzinfo=timezone.utc) <= now:
    raise SystemExit(f"error: {kind} provisioning profile has expired")
if signing_certificate not in profile.get("DeveloperCertificates", []):
    raise SystemExit(f"error: {kind} signing certificate is not authorized by its provisioning profile")

profile_entitlements = profile.get("Entitlements")
if not isinstance(profile_entitlements, dict):
    raise SystemExit(f"error: {kind} provisioning profile has no entitlements")
if profile_entitlements.get("com.apple.developer.team-identifier") != team_id:
    raise SystemExit(f"error: {kind} provisioning profile Team ID entitlement mismatch")
profile_app_id = profile_entitlements.get("com.apple.application-identifier")
if profile_app_id is None:
    profile_app_id = profile_entitlements.get("application-identifier")
if profile_app_id != f"{team_id}.{bundle_id}":
    raise SystemExit(f"error: {kind} provisioning profile application identifier mismatch")
try:
    verify_profile_keychain_access_group(
        profile_entitlements,
        kind,
        agent_keychain_group,
        extension_keychain_group,
        team_id,
    )
    verify_profile_capability_authorizations(
        profile_entitlements,
        signed,
        kind,
        team_id,
        app_group,
    )
except EntitlementContractError as error:
    raise SystemExit(f"error: {kind} provisioning profile {error}") from error
if profile_entitlements.get("get-task-allow") or profile_entitlements.get("com.apple.security.get-task-allow"):
    raise SystemExit(f"error: {kind} provisioning profile permits debugging")
PY
}

verify_bundle_security() {
  local bundle="$1"
  local kind="$2"
  local identifier="$3"
  local entitlements="$temporary_root/${kind}-entitlements.plist"
  assert_developer_id_signature "$bundle" "$identifier"
  extract_entitlements "$bundle" "$entitlements"
  verify_entitlements "$entitlements" "$kind" "$identifier"
  verify_provisioning_profile "$bundle" "$kind" "$identifier" "$entitlements"
}

verify_macho() {
  local binary="$1"
  local architectures
  local build_details
  architectures="$(lipo -archs "$binary")"
  [[ "$architectures" == "arm64" ]] || die "Mach-O must be thin arm64: $binary ($architectures)"
  build_details="$(vtool -show-build "$binary")"
  [[ "$build_details" =~ platform[[:space:]]+MACOS ]] || die "Mach-O is not a macOS binary: $binary"
  [[ "$build_details" =~ minos[[:space:]]+$expected_minimum_system([[:space:]]|$) ]] ||
    die "Mach-O deployment target must be $expected_minimum_system: $binary"
  assert_developer_id_signature "$binary"
}

verify_tombstone_provenance() {
  local embedded_binary="$1"
  local staged_root="$native_products_root/CFWLegacyTombstone"
  local staged_binary="$staged_root/cfw-helper-tombstone"
  local manifest="$native_products_root/CFWLegacyTombstone.manifest.json"
  require_regular_file "$staged_binary"
  require_regular_file "$manifest"
  "$python_bin" -I -S -B -W error - \
    "$repo_root" "$manifest" "$staged_binary" "$build_number" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
staged_binary = Path(sys.argv[3])
build_number = sys.argv[4]
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
metadata = manifest.get("metadata", {})

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

expected_metadata = {
    "artifactKind": "legacy-service-tombstone-v1",
    "architecture": "arm64",
    "buildNumber": build_number,
    "deploymentTarget": "15.0",
    "signingMode": "developer-id",
    "rustVersion": "1.97.1",
    "sourceSha256": digest(root / "crates/cfw-legacy-tombstone/src/main.rs"),
    "cargoManifestSha256": digest(root / "crates/cfw-legacy-tombstone/Cargo.toml"),
    "cargoLockSha256": digest(root / "Cargo.lock"),
}
if metadata != expected_metadata:
    raise SystemExit("error: legacy tombstone manifest is not bound to current source and lockfile")
entries = manifest.get("entries")
expected_entry = {
    "path": "cfw-helper-tombstone",
    "sha256": digest(staged_binary),
    "size": staged_binary.stat().st_size,
    "type": "file",
}
if entries != [expected_entry]:
    raise SystemExit("error: legacy tombstone manifest contains an unexpected artifact set")
encoded_entry = json.dumps(
    expected_entry, ensure_ascii=True, sort_keys=True, separators=(",", ":")
) + "\n"
tree_digest = hashlib.sha256(encoded_entry.encode("utf-8")).hexdigest()
if (
    manifest.get("algorithm") != "sha256-tree-v1"
    or manifest.get("root") != "CFWLegacyTombstone"
    or manifest.get("sha256") != tree_digest
):
    raise SystemExit("error: legacy tombstone tree identity is invalid")

markers = (b"mihomo", b"clash-rs", b"clash-darwin", b"CFW_CORE_KIND", b"core install", b"want_core")
payload = staged_binary.read_bytes()
found = [marker.decode("ascii") for marker in markers if marker in payload]
if found:
    raise SystemExit(f"error: staged tombstone contains retired supervisor markers: {found}")
PY

  local staged_uuid embedded_uuid
  staged_uuid="$(dwarfdump --uuid "$staged_binary" | awk '$1 == "UUID:" && $3 == "(arm64)" { print $2 }')"
  embedded_uuid="$(dwarfdump --uuid "$embedded_binary" | awk '$1 == "UUID:" && $3 == "(arm64)" { print $2 }')"
  [[ -n "$staged_uuid" && "$embedded_uuid" == "$staged_uuid" ]] ||
    die "embedded tombstone does not match the source-bound staged build"
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

for command in codesign dwarfdump file find lipo plutil security shasum spctl stat vtool xcrun; do
  require_command "$command"
done
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "release verification requires Apple Silicon macOS"

pre_notary=0
if [[ "${1:-}" == "--pre-notary" ]]; then
  pre_notary=1
  shift
fi
app_path="${1:-}"
native_products_root="${2:-}"
[[ $# == 4 && "$3" == "--context" ]] ||
  die "usage: scripts/verify_release_app.sh [--pre-notary] APP NATIVE_PRODUCTS --context CONTEXT"
verification_context="$4"
[[ "$app_path" == /* ]] || die "application path must be absolute"
[[ "$native_products_root" == /* ]] || die "native products root must be absolute"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "application must be a non-symlink directory: $app_path"
[[ -d "$native_products_root" && ! -L "$native_products_root" ]] ||
  die "native products root must be a non-symlink directory"

build_number="$(PYTHONDONTWRITEBYTECODE=1 "$python_bin" -I -S -B -W error - \
  "$repo_root" "$app_path" "$native_products_root" "$verification_context" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1] + "/scripts")
from release_build_identity import (
    CandidateBundleContext,
    candidate_bundle_verification_paths,
)

try:
    context = CandidateBundleContext(sys.argv[4])
except ValueError:
    raise SystemExit("error: release application verification context is invalid")
paths = candidate_bundle_verification_paths(
    Path(sys.argv[1]), sys.argv[2], sys.argv[3], context
)
if context is CandidateBundleContext.UNSIGNED_HOST:
    raise SystemExit("error: release application verification rejects unsigned-host context")
print(paths.build_identity.build_version)
PY
)" || die "bundle build identity is invalid"
[[ "$build_number" == "40033" ]] ||
  die "release application is not the fixed GA build 40033"
case "$verification_context" in
  signing-attempt-work|signing-attempt-publish-ready)
    ((pre_notary == 1)) ||
      die "private signing-attempt verification is allowed only before notarization"
    ;;
  canonical-native-content)
    ;;
  *)
    die "release application verification context is invalid"
    ;;
esac
signing_preflight_manifest="$repo_root/target/candidates/0.4.0/ga/40033/profiles/signing-preflight.json"
require_regular_file "$signing_preflight_manifest"
expected_signing_certificate_sha256="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/release_signing_preflight.py" \
  --print-certificate-sha256 "$signing_preflight_manifest")" ||
  die "cannot reopen the frozen Developer ID certificate fingerprint"
readonly expected_signing_certificate_sha256
[[ "$expected_signing_certificate_sha256" =~ ^[0-9A-F]{64}$ ]] ||
  die "frozen Developer ID certificate fingerprint is malformed"

native_source_sha256="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/hash_native_build_inputs.py")" ||
  die "cannot hash current native build inputs"
source_identity="$(cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/repository_source_identity.py")" ||
  die "cannot derive current release source identity"
read -r repository_commit release_source_sha256 <<<"$source_identity"
[[ -n "$repository_commit" && -n "$release_source_sha256" ]] ||
  die "current release source identity is incomplete"
libbox_manifest="$repo_root/target/native-dependencies/Libbox.xcframework.manifest.json"
require_regular_file "$libbox_manifest"
go_toolchain_tree_sha256="$(
  cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root"
)" || die "cannot verify the pinned Go toolchain tree"
go_tools_tree_sha256="$(
  cfw_verify_go_release_tools_tree "$repo_root" "$toolchain_root"
)" || die "cannot verify the pinned Go release-tools tree"
go_module_cache_tree_sha256="$(
  cfw_verify_go_module_cache_tree "$repo_root" "$toolchain_root"
)" || die "cannot verify the pinned Go module-cache tree"
libbox_manifest_sha256="$(shasum -a 256 "$libbox_manifest" | awk '{print $1}')"
libbox_tree_sha256="$(libbox_verify_xcframework_artifact \
  "$repo_root" \
  "$repo_root/target/native-dependencies/Libbox.xcframework" \
  "$libbox_manifest" \
  "$go_toolchain_tree_sha256" \
  "$go_tools_tree_sha256" \
  "$go_module_cache_tree_sha256")" || die "Libbox artifact does not match the current release contract"

for product in \
  CFWGlobalAuthority \
  CFWNativeBridge.framework \
  CFWProxyAgent.app \
  "$expected_extension_wrapper"; do
  cfw_run_release_python_script \
    "$repo_root" "$repo_root/scripts/verify_artifact_manifest.py" \
    "$native_products_root/$product" \
    "$native_products_root/$product.manifest.json" \
    --metadata "buildNumber=$build_number" \
    --metadata "libboxManifestSha256=$libbox_manifest_sha256" \
    --metadata "libboxTreeSha256=$libbox_tree_sha256" \
    --metadata "nativeSourceSha256=$native_source_sha256" \
    --metadata "releaseSourceSha256=$release_source_sha256" \
    --metadata "repositoryCommit=$repository_commit" \
    --metadata "signingMode=developer-id"
done

cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/verify_candidate_bundle.py" \
  "$app_path" \
  --native-products-root "$native_products_root" \
  --context "$verification_context"

"$python_bin" -I -S -B -W error - "$app_path" <<'PY'
import os
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1]).resolve(strict=True)
def fail_walk(error):
    raise OSError(f"cannot enumerate release bundle: {error}") from error

for directory, names, files in os.walk(root, followlinks=False, onerror=fail_walk):
    for name in names + files:
        path = Path(directory, name)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            target = path.resolve(strict=True)
            try:
                target.relative_to(root)
            except ValueError:
                raise SystemExit(f"error: app symlink escapes the bundle root: {path} -> {target}")
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise SystemExit(f"error: app file has multiple hard links: {path}")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"error: unsupported special file in app bundle: {path}")
PY

/usr/bin/find "$app_path/Contents" -print >/dev/null ||
  die "cannot enumerate the complete application bundle"

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/cfw-release-verify.XXXXXX")"
trap '/bin/rm -rf "$temporary_root"' EXIT
certificate_capture_sequence=0

assert_bundle_info "$app_path" "$expected_app_id" APPL

extension_path="$app_path/Contents/Library/SystemExtensions/$expected_extension_wrapper"
agent_path="$app_path/Contents/Library/LoginItems/CFWProxyAgent.app"
authority_path="$app_path/Contents/Library/HelperTools/CFWGlobalAuthority"
tombstone_path="$app_path/Contents/Library/HelperTools/cfw-helper-tombstone"
authority_plist="$app_path/Contents/Library/LaunchDaemons/com.bill.clashformac.global-authority.plist"
tombstone_plist="$app_path/Contents/Library/LaunchDaemons/com.bill.clashformac.helper.plist"
proxy_agent_plist="$app_path/Contents/Library/LaunchAgents/com.bill.clashformac.proxy-agent.plist"
[[ -d "$extension_path" && ! -L "$extension_path" ]] || die "Packet Tunnel bundle is missing or is a symlink"
[[ -d "$agent_path" && ! -L "$agent_path" ]] || die "ProxyAgent bundle is missing or is a symlink"

nested_apps=()
nested_apps_file="$temporary_root/nested-apps"
/usr/bin/find "$app_path/Contents" -type d -name '*.app' -print0 >"$nested_apps_file" ||
  die "cannot enumerate nested application bundles"
while IFS= read -r -d '' entry; do nested_apps+=("$entry"); done <"$nested_apps_file"
[[ ${#nested_apps[@]} == 1 && "${nested_apps[0]}" == "$agent_path" ]] ||
  die "release bundle must contain exactly the expected ProxyAgent app"
symlinked_app="$temporary_root/symlinked-app"
/usr/bin/find "$app_path/Contents" -type l -name '*.app' -print -quit >"$symlinked_app" ||
  die "cannot scan for symlinked application bundles"
if [[ -s "$symlinked_app" ]]; then
  die "symlinked nested application bundles are forbidden"
fi

system_extensions=()
system_extensions_file="$temporary_root/system-extensions"
/usr/bin/find "$app_path/Contents" -type d -name '*.systemextension' -print0 >"$system_extensions_file" ||
  die "cannot enumerate System Extension bundles"
while IFS= read -r -d '' entry; do system_extensions+=("$entry"); done <"$system_extensions_file"
[[ ${#system_extensions[@]} == 1 && "${system_extensions[0]}" == "$extension_path" ]] ||
  die "release bundle must contain exactly the expected Packet Tunnel system extension"
symlinked_extension="$temporary_root/symlinked-extension"
/usr/bin/find "$app_path/Contents" -type l -name '*.systemextension' -print -quit >"$symlinked_extension" ||
  die "cannot scan for symlinked System Extension bundles"
if [[ -s "$symlinked_extension" ]]; then
  die "symlinked System Extension bundles are forbidden"
fi

helper_entries=()
helper_entries_file="$temporary_root/helper-entries"
/usr/bin/find "$app_path/Contents/Library/HelperTools" -mindepth 1 -maxdepth 1 -print0 >"$helper_entries_file" ||
  die "cannot enumerate release HelperTools"
while IFS= read -r -d '' entry; do helper_entries+=("$entry"); done <"$helper_entries_file"
[[ ${#helper_entries[@]} == 2 ]] || die "HelperTools must contain exactly the Authority and tombstone"
authority_seen=0
tombstone_seen=0
for entry in "${helper_entries[@]}"; do
  case "$entry" in
    "$authority_path") authority_seen=$((authority_seen + 1)) ;;
    "$tombstone_path") tombstone_seen=$((tombstone_seen + 1)) ;;
    *) die "unexpected HelperTools entry: $entry" ;;
  esac
done
[[ $authority_seen -eq 1 && $tombstone_seen -eq 1 ]] ||
  die "HelperTools does not match the closed release layout"
launch_daemon_entries=()
launch_daemon_entries_file="$temporary_root/launch-daemon-entries"
/usr/bin/find "$app_path/Contents/Library/LaunchDaemons" -mindepth 1 -maxdepth 1 -print0 >"$launch_daemon_entries_file" ||
  die "cannot enumerate release LaunchDaemons"
while IFS= read -r -d '' entry; do launch_daemon_entries+=("$entry"); done <"$launch_daemon_entries_file"
[[ ${#launch_daemon_entries[@]} == 2 ]] || die "LaunchDaemons must contain exactly the Authority and tombstone plists"
authority_plist_seen=0
tombstone_plist_seen=0
for entry in "${launch_daemon_entries[@]}"; do
  case "$entry" in
    "$authority_plist") authority_plist_seen=$((authority_plist_seen + 1)) ;;
    "$tombstone_plist") tombstone_plist_seen=$((tombstone_plist_seen + 1)) ;;
    *) die "unexpected LaunchDaemons entry: $entry" ;;
  esac
done
[[ $authority_plist_seen -eq 1 && $tombstone_plist_seen -eq 1 ]] ||
  die "LaunchDaemons does not match the closed release layout"
require_regular_file "$authority_path"
require_regular_file "$authority_plist"
require_regular_file "$tombstone_path"
require_regular_file "$tombstone_plist"
cmp -s "$authority_plist" "$repo_root/native/macos/Config/com.bill.clashformac.global-authority.plist" ||
  die "embedded Global Authority plist differs from the reviewed source plist"
[[ "$(plist_value "$authority_plist" Label)" == "$expected_authority_id" ]] ||
  die "Global Authority launchd label mismatch"
[[ "$(plist_value "$authority_plist" BundleProgram)" == "Contents/Library/HelperTools/CFWGlobalAuthority" ]] ||
  die "Global Authority launchd BundleProgram mismatch"
[[ "$(plist_value "$authority_plist" UserName)" == "root" ]] ||
  die "Global Authority must run as root"
"$python_bin" -I -S -B -W error - \
  "$authority_plist" "$expected_team_id" "$expected_app_id" <<'PY'
import plistlib
import sys

path, team_id, app_id = sys.argv[1:]
with open(path, "rb") as handle:
    plist = plistlib.load(handle)
expected = {
    f"{team_id}.group.com.bill.clashformac.global-authority.host": True,
    f"{team_id}.group.com.bill.clashformac.global-authority.proxy-agent": True,
    f"{team_id}.group.com.bill.clashformac.global-authority.provider": True,
}
if plist.get("MachServices") != expected:
    raise SystemExit("error: Global Authority launchd MachServices contract mismatch")
if plist.get("AssociatedBundleIdentifiers") != [app_id]:
    raise SystemExit("error: Global Authority associated bundle identifier mismatch")
PY
cmp -s "$tombstone_plist" "$repo_root/apps/cfw-tauri-shell/macos/legacy-tombstone/com.bill.clashformac.helper.plist" ||
  die "embedded legacy tombstone plist differs from the reviewed source plist"
launch_agent_entries=()
launch_agent_entries_file="$temporary_root/launch-agent-entries"
/usr/bin/find "$app_path/Contents/Library/LaunchAgents" -mindepth 1 -maxdepth 1 -print0 >"$launch_agent_entries_file" ||
  die "cannot enumerate release LaunchAgents"
while IFS= read -r -d '' entry; do launch_agent_entries+=("$entry"); done <"$launch_agent_entries_file"
[[ ${#launch_agent_entries[@]} == 1 && "${launch_agent_entries[0]}" == "$proxy_agent_plist" ]] ||
  die "only the exact authenticated ProxyAgent plist is allowed under LaunchAgents"
require_regular_file "$proxy_agent_plist"
cmp -s "$proxy_agent_plist" "$repo_root/native/macos/Config/com.bill.clashformac.proxy-agent.plist" ||
  die "embedded ProxyAgent launchd plist differs from the reviewed source plist"
[[ "$(plist_value "$proxy_agent_plist" Label)" == "$expected_agent_id" ]] ||
  die "ProxyAgent launchd label mismatch"
[[ "$(plist_value "$proxy_agent_plist" BundleProgram)" == "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent" ]] ||
  die "ProxyAgent launchd BundleProgram mismatch"
[[ "$(plist_value "$proxy_agent_plist" MachServices:$expected_agent_id)" == "true" ]] ||
  die "ProxyAgent launchd MachServices contract mismatch"
verify_tombstone_provenance "$tombstone_path"
assert_developer_id_signature "$authority_path" "$expected_authority_id"

for retired_path in \
  "$app_path/Contents/Resources/resources/cores" \
  "$app_path/Contents/Resources/resources/helpers" \
  "$app_path/Contents/Resources/cores" \
  "$app_path/Contents/Resources/helpers"; do
  [[ ! -e "$retired_path" && ! -L "$retired_path" ]] || die "retired helper/core artifact is present: $retired_path"
done
retired_entries="$temporary_root/retired-entries"
/usr/bin/find "$app_path/Contents" \( -iname 'mihomo*' -o -iname 'clash-rs*' -o -name 'cfw-helper' -o -type d -name cores \) -print -quit >"$retired_entries" ||
  die "cannot scan the app bundle for retired engine artifacts"
if [[ -s "$retired_entries" ]]; then
  die "retired executable or helper name is present in the app bundle"
fi

assert_bundle_info "$extension_path" "$expected_extension_id" SYSX
[[ "$(plist_value "$extension_path/Contents/Info.plist" CFBundleExecutable)" == "$expected_extension_executable" ]] ||
  die "Packet Tunnel executable identity mismatch"
require_regular_file "$extension_path/Contents/MacOS/$expected_extension_executable"
assert_bundle_info "$agent_path" "$expected_agent_id" APPL

app_version="$(plist_value "$app_path/Contents/Info.plist" CFBundleShortVersionString)"
[[ "$app_version" == "$expected_version" ]] ||
  die "release app version must be exactly $expected_version"
[[ "$(plist_value "$extension_path/Contents/Info.plist" CFBundleShortVersionString)" == "$app_version" ]] ||
  die "Packet Tunnel version does not match the host app"
[[ "$(plist_value "$agent_path/Contents/Info.plist" CFBundleShortVersionString)" == "$app_version" ]] ||
  die "ProxyAgent version does not match the host app"
[[ "$(plist_value "$extension_path/Contents/Info.plist" NetworkExtension:NEMachServiceName)" == "$expected_team_id.$expected_extension_id" ]] ||
  die "Packet Tunnel Mach service identity mismatch"
[[ "$(plist_value "$extension_path/Contents/Info.plist" NetworkExtension:NEProviderClasses:com.apple.networkextension.packet-tunnel)" == "CFWPacketTunnel.PacketTunnelProvider" ]] ||
  die "Packet Tunnel provider class identity mismatch"
[[ "$(plist_value "$agent_path/Contents/Info.plist" CFWAppGroupIdentifier)" == "$expected_app_group" ]] ||
  die "ProxyAgent Info.plist App Group mismatch"
[[ "$(plist_value "$agent_path/Contents/Info.plist" CFWExpectedHostBundleIdentifier)" == "$expected_app_id" ]] ||
  die "ProxyAgent expected host bundle identifier mismatch"
[[ "$(plist_value "$agent_path/Contents/Info.plist" CFWExpectedTeamIdentifier)" == "$expected_team_id" ]] ||
  die "ProxyAgent expected Team ID mismatch"
[[ "$(plist_value "$agent_path/Contents/Info.plist" CFWProxyJournalKeychainAccessGroup)" == "$expected_agent_keychain_access_group" ]] ||
  die "ProxyAgent journal Keychain access group mismatch"
[[ "$(plist_value "$agent_path/Contents/Info.plist" CFWCredentialKeychainAccessGroup)" == "$expected_credential_keychain_access_group" ]] ||
  die "ProxyAgent shared credential Keychain access group mismatch"
[[ "$(plist_value "$agent_path/Contents/Info.plist" CFWProxyAgentMachServiceName)" == "$expected_agent_id" ]] ||
  die "ProxyAgent Mach service identity mismatch"
[[ "$(plist_value "$agent_path/Contents/Info.plist" LSBackgroundOnly)" == "true" ]] ||
  die "ProxyAgent must remain a background-only application"
[[ "$(plist_value "$agent_path/Contents/Info.plist" LSMultipleInstancesProhibited)" == "true" ]] ||
  die "ProxyAgent must prohibit multiple instances"

verify_bundle_security "$app_path" host "$expected_app_id"
verify_bundle_security "$extension_path" packet-tunnel "$expected_extension_id"
verify_bundle_security "$agent_path" proxy-agent "$expected_agent_id"

macho_count=0
macho_candidates="$temporary_root/macho-candidates"
/usr/bin/find "$app_path/Contents" -type f -print0 >"$macho_candidates" ||
  die "cannot enumerate candidate application binaries"
while IFS= read -r -d '' candidate; do
  file_description="$(file -b "$candidate")" ||
    die "cannot identify release bundle file type: $candidate"
  if [[ "$file_description" == Mach-O* ]]; then
    verify_macho "$candidate"
    macho_count=$((macho_count + 1))
  elif [[ -x "$candidate" ]]; then
    die "executable non-Mach-O file is forbidden in the release app: $candidate"
  fi
done <"$macho_candidates"
[[ $macho_count -gt 0 ]] || die "application bundle contains no Mach-O code"

codesign --verify --deep --strict --verbose=4 "$app_path"
if [[ $pre_notary -eq 0 ]]; then
  xcrun stapler validate "$app_path"
  cfw_run_release_python_script \
    "$repo_root" "$repo_root/scripts/gatekeeper_assessment.py" \
    --target "$app_path" \
    --assessment-type execute
fi

echo "release app verified: $app_path"
echo "identity: $expected_team_id / $expected_app_id / $expected_extension_id / $expected_agent_id"
echo "platform: arm64 / macOS $expected_minimum_system+"
echo "build number: $build_number"
if [[ $pre_notary -eq 1 ]]; then
  echo "notarization: pre-submission identity gate only"
fi
