#!/bin/bash -p
# Perform one private GA signing attempt. The Python transaction is the only
# supported caller and keeps the signing-attempt root locked for this process.
set -euo pipefail
umask 077
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
# shellcheck source=scripts/release_bundle_codesign.sh
source "$repo_root/scripts/release_bundle_codesign.sh"
cfw_seal_release_tool_environment production

die() {
  echo "error: $*" >&2
  exit 1
}

[[ $# -eq 1 && "$1" == "--transaction-owned" ]] ||
  die "this helper is owned by signing_attempt_transaction.py"
: "${CFW_SIGNING_ATTEMPT_WORK:?transaction work root is unavailable}"
: "${CFW_SIGNING_CERTIFICATE_SHA1:?frozen signing certificate SHA-1 is unavailable}"
: "${CFW_SIGNING_CERTIFICATE_SHA256:?frozen signing certificate SHA-256 is unavailable}"
[[ "$CFW_SIGNING_CERTIFICATE_SHA1" =~ ^[0-9A-F]{40}$ ]] ||
  die "frozen signing certificate SHA-1 is malformed"
[[ "$CFW_SIGNING_CERTIFICATE_SHA256" =~ ^[0-9A-F]{64}$ ]] ||
  die "frozen signing certificate SHA-256 is malformed"

readonly frozen_root="$repo_root/target/candidates/0.4.0/ga/40040"
readonly attempt_work="$CFW_SIGNING_ATTEMPT_WORK"
[[ -d "$attempt_work" && ! -L "$attempt_work" ]] ||
  die "transaction work root is not a real directory"
[[ "$(stat -f '%Lp' "$attempt_work")" == "700" ]] ||
  die "transaction work root mode is not 0700"

readonly native_products="$frozen_root/native-products"
readonly profiles_root="$frozen_root/profiles"
readonly entitlements_root="$frozen_root/entitlements"
readonly pre_sign_app="$frozen_root/pre-sign/Clash for Mac.app"
readonly signing_input_root="$attempt_work/signing-input"
readonly staged_app="$signing_input_root/Clash for Mac.app"
readonly signed_native_products="$attempt_work/signed-native-products"
readonly host_profile="$profiles_root/host.provisionprofile"
readonly proxy_profile="$profiles_root/proxy-agent.provisionprofile"
readonly packet_profile="$profiles_root/packet-tunnel.provisionprofile"
readonly host_release_xcent="$entitlements_root/Host.release.xcent"
readonly proxy_release_xcent="$entitlements_root/ProxyAgent.release.xcent"
readonly packet_release_xcent="$entitlements_root/PacketTunnel.release.xcent"
readonly authority_entitlements="$entitlements_root/GlobalAuthority.entitlements"

[[ "$(find "$attempt_work" -mindepth 1 -maxdepth 1 -print -quit)" == "" ]] ||
  die "transaction work root is not empty"
mkdir -m 0700 "$signing_input_root" "$signed_native_products"
/usr/bin/ditto --noqtn "$pre_sign_app" "$staged_app"

/usr/bin/install -m 0644 "$host_profile" \
  "$staged_app/Contents/embedded.provisionprofile"
proxy_app="$staged_app/Contents/Library/LoginItems/CFWProxyAgent.app"
packet_extension="$staged_app/Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension"
/usr/bin/install -m 0644 "$proxy_profile" \
  "$proxy_app/Contents/embedded.provisionprofile"
/usr/bin/install -m 0644 "$packet_profile" \
  "$packet_extension/Contents/embedded.provisionprofile"

bridge="$staged_app/Contents/Frameworks/CFWNativeBridge.framework"
authority="$staged_app/Contents/Library/HelperTools/CFWGlobalAuthority"
tombstone="$staged_app/Contents/Library/HelperTools/cfw-helper-tombstone"
readonly authority_designated_requirement='designated => anchor apple generic and identifier "com.bill.clashformac.global-authority" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "YKUPL7Z869"'
cfw_codesign_distribution_bundle --force --options runtime --timestamp \
  --identifier com.bill.clashformac.native-bridge \
  --sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$bridge"
cfw_codesign_distribution_bundle --force --options runtime --timestamp \
  --identifier com.bill.clashformac.global-authority \
  -r="$authority_designated_requirement" \
  --entitlements "$authority_entitlements" \
  --sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$authority"
readonly authority_requirement_root="$attempt_work/authority-requirement"
readonly authority_requirement_text="$authority_requirement_root/signed.txt"
readonly authority_requirement_expected="$authority_requirement_root/expected.csreq"
readonly authority_requirement_actual="$authority_requirement_root/actual.csreq"
/bin/mkdir -m 0700 "$authority_requirement_root" ||
  die "cannot create the private Global Authority requirement verification root"
/usr/bin/codesign -d -r "$authority_requirement_text" "$authority" \
  >/dev/null 2>&1 || die "cannot extract the Global Authority designated requirement"
/usr/bin/csreq -r="$authority_designated_requirement" \
  -b "$authority_requirement_expected" >/dev/null 2>&1 ||
  die "cannot compile the expected Global Authority designated requirement"
/usr/bin/csreq -r "$authority_requirement_text" \
  -b "$authority_requirement_actual" >/dev/null 2>&1 ||
  die "cannot compile the signed Global Authority designated requirement"
/usr/bin/cmp -s -- "$authority_requirement_expected" "$authority_requirement_actual" ||
  die "Global Authority designated requirement mismatch"
/bin/rm -- \
  "$authority_requirement_text" \
  "$authority_requirement_expected" \
  "$authority_requirement_actual" >/dev/null 2>&1 ||
  die "cannot remove the Global Authority requirement verification files"
/bin/rmdir "$authority_requirement_root" >/dev/null 2>&1 ||
  die "cannot remove the private Global Authority requirement verification root"
cfw_codesign_distribution_bundle --force --options runtime --timestamp \
  --entitlements "$proxy_release_xcent" \
  --sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$proxy_app"
cfw_codesign_distribution_bundle --force --options runtime --timestamp \
  --entitlements "$packet_release_xcent" \
  --sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$packet_extension"
cfw_codesign_distribution_bundle --force --options runtime --timestamp \
  --sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$tombstone"
for nested in "$bridge" "$authority" "$proxy_app" "$packet_extension" "$tombstone"; do
  /usr/bin/codesign --verify --strict --verbose=4 "$nested"
done

/usr/bin/ditto --noqtn "$bridge" "$signed_native_products/CFWNativeBridge.framework"
/usr/bin/ditto --noqtn "$authority" "$signed_native_products/CFWGlobalAuthority"
/usr/bin/ditto --noqtn "$proxy_app" "$signed_native_products/CFWProxyAgent.app"
/usr/bin/ditto --noqtn \
  "$packet_extension" \
  "$signed_native_products/com.bill.clashformac.packet-tunnel.systemextension"
mkdir -m 0700 "$signed_native_products/CFWLegacyTombstone"
/usr/bin/ditto --noqtn \
  "$tombstone" \
  "$signed_native_products/CFWLegacyTombstone/cfw-helper-tombstone"
for product in \
  CFWGlobalAuthority \
  CFWNativeBridge.framework \
  CFWProxyAgent.app \
  com.bill.clashformac.packet-tunnel.systemextension \
  CFWLegacyTombstone; do
  cfw_run_release_python_script \
    "$repo_root" \
    "$repo_root/scripts/promote_signed_native_manifest.py" \
    "$native_products/$product" \
    "$native_products/$product.manifest.json" \
    "$signed_native_products/$product" \
    "$signed_native_products/$product.manifest.json"
  cfw_run_release_python_script \
    "$repo_root" \
    "$repo_root/scripts/verify_artifact_manifest.py" \
    "$signed_native_products/$product" \
    "$signed_native_products/$product.manifest.json" \
    --metadata "buildNumber=40040" \
    --metadata "signingMode=developer-id"
done

cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/verify_legacy_tombstone_provenance.py" \
  --repository "$repo_root" \
  --build-number "$CFW_BUILD_NUMBER" \
  --deployment-target "$MACOS_DEPLOYMENT_TARGET" \
  --rust-version "$RUST_VERSION" \
  --pre-sign-artifact "$native_products/CFWLegacyTombstone" \
  --pre-sign-manifest "$native_products/CFWLegacyTombstone.manifest.json" \
  --signed-artifact "$signed_native_products/CFWLegacyTombstone" \
  --signed-manifest "$signed_native_products/CFWLegacyTombstone.manifest.json" \
  --embedded-app "$staged_app" \
  --context signing-attempt-work

"$repo_root/scripts/verify_candidate_bundle.sh" \
  "$staged_app" "$signed_native_products" \
  --context signing-attempt-work
cfw_codesign_distribution_bundle --force --options runtime --timestamp \
  --entitlements "$host_release_xcent" \
  --sign "$CFW_SIGNING_CERTIFICATE_SHA1" "$staged_app"
/usr/bin/codesign --verify --deep --strict --verbose=4 "$staged_app"
"$repo_root/scripts/verify_release_app.sh" \
  --pre-notary "$staged_app" "$signed_native_products" \
  --context signing-attempt-work
