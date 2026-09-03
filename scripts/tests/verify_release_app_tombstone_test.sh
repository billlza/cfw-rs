#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../verify_release_app.sh
source "$repo_root/scripts/verify_release_app.sh"

tombstone_test_root="$(mktemp -d "${TMPDIR:-/tmp}/cfw-tombstone-provenance.XXXXXX")"
tombstone_test_root="$(cd "$tombstone_test_root" && pwd -P)"
trap '/bin/rm -rf "$tombstone_test_root"' EXIT
fixture_repository="$tombstone_test_root/repository"
fixture_ga_root="$fixture_repository/target/candidates/0.4.0/ga/40041"
pre_sign_products="$fixture_ga_root/native-products"
transactions_root="$fixture_ga_root/transactions"
attempts_root="$transactions_root/signing-attempts"
attempt_root="$attempts_root/00000001"
attempt_output="$attempt_root/work"
signing_input="$attempt_output/signing-input"
signed_products="$attempt_output/signed-native-products"
pre_sign_root="$pre_sign_products/CFWLegacyTombstone"
signed_root="$signed_products/CFWLegacyTombstone"
embedded_app="$signing_input/Clash for Mac.app"
embedded_binary="$embedded_app/Contents/Library/HelperTools/cfw-helper-tombstone"
fixture_source="$tombstone_test_root/tombstone.c"
fixture_binary="$tombstone_test_root/tombstone"
/bin/mkdir -p \
  "$fixture_repository/crates/cfw-legacy-tombstone/src" \
  "$pre_sign_root" \
  "$signed_root" \
  "$embedded_app/Contents/Library/HelperTools"
for private_directory in \
  "$transactions_root" \
  "$attempts_root" \
  "$attempt_root" \
  "$attempt_output" \
  "$signing_input" \
  "$signed_products"; do
  /bin/chmod 0700 "$private_directory"
done
/bin/cp \
  "$repo_root/crates/cfw-legacy-tombstone/src/main.rs" \
  "$fixture_repository/crates/cfw-legacy-tombstone/src/main.rs"
/bin/cp \
  "$repo_root/crates/cfw-legacy-tombstone/Cargo.toml" \
  "$fixture_repository/crates/cfw-legacy-tombstone/Cargo.toml"
/bin/cp "$repo_root/Cargo.lock" "$fixture_repository/Cargo.lock"
"$python_bin" -I -S -B -W error - "$embedded_app" <<'PY'
import plistlib
import sys
from pathlib import Path

app = Path(sys.argv[1])
identity = {
    "CFBundleShortVersionString": "0.4.0",
    "CFBundleVersion": "40041",
}
for relative in (
    "Contents/Info.plist",
    "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/Resources/Info.plist",
    "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/Info.plist",
    "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension/Contents/Info.plist",
):
    path = app / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(identity, sort_keys=True))
    path.chmod(0o644)
PY
/usr/bin/printf '%s\n' 'int main(void) { return 0; }' >"$fixture_source"
clang_binary="$(/usr/bin/xcrun --find clang)"
macos_sdk="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
[[ "$clang_binary" == /* && -x "$clang_binary" && -d "$macos_sdk" ]] || {
  echo "error: tombstone fixture requires the selected Apple clang" >&2
  exit 1
}
"$clang_binary" \
  -arch arm64 \
  -isysroot "$macos_sdk" \
  "-mmacosx-version-min=$MACOS_DEPLOYMENT_TARGET" \
  -Wall -Wextra -Werror \
  "$fixture_source" \
  -o "$fixture_binary"
/bin/cp "$fixture_binary" "$pre_sign_root/cfw-helper-tombstone"
/bin/cp "$fixture_binary" "$signed_root/cfw-helper-tombstone"
/bin/cp "$fixture_binary" "$embedded_binary"
/bin/chmod 0755 \
  "$pre_sign_root/cfw-helper-tombstone" \
  "$signed_root/cfw-helper-tombstone" \
  "$embedded_binary"

source_sha256="$(
  /usr/bin/shasum -a 256 \
    "$repo_root/crates/cfw-legacy-tombstone/src/main.rs" |
    /usr/bin/awk '{print $1}'
)"
cargo_manifest_sha256="$(
  /usr/bin/shasum -a 256 \
    "$repo_root/crates/cfw-legacy-tombstone/Cargo.toml" |
    /usr/bin/awk '{print $1}'
)"
cargo_lock_sha256="$(
  /usr/bin/shasum -a 256 "$repo_root/Cargo.lock" |
    /usr/bin/awk '{print $1}'
)"

cfw_run_release_python_script \
  "$repo_root" "$repo_root/scripts/hash_artifact.py" \
  "$pre_sign_root" \
  --output "$pre_sign_products/CFWLegacyTombstone.manifest.json" \
  --metadata "artifactKind=legacy-service-tombstone-v1" \
  --metadata "architecture=arm64" \
  --metadata "buildNumber=40041" \
  --metadata "deploymentTarget=$MACOS_DEPLOYMENT_TARGET" \
  --metadata "signingMode=pre-sign" \
  --metadata "rustVersion=$RUST_VERSION" \
  --metadata "sourceSha256=$source_sha256" \
  --metadata "cargoManifestSha256=$cargo_manifest_sha256" \
  --metadata "cargoLockSha256=$cargo_lock_sha256"

write_signed_manifest() {
  cfw_run_release_python_script \
    "$repo_root" "$repo_root/scripts/promote_signed_native_manifest.py" \
    "$pre_sign_root" \
    "$pre_sign_products/CFWLegacyTombstone.manifest.json" \
    "$signed_root" \
    "$signed_products/CFWLegacyTombstone.manifest.json"
}

verify_tombstone_provenance_fixture() {
  cfw_run_release_python_script \
    "$repo_root" "$repo_root/scripts/verify_legacy_tombstone_provenance.py" \
    --repository "$fixture_repository" \
    --build-number 40041 \
    --deployment-target "$MACOS_DEPLOYMENT_TARGET" \
    --rust-version "$RUST_VERSION" \
    --pre-sign-artifact "$pre_sign_root" \
    --pre-sign-manifest "$pre_sign_products/CFWLegacyTombstone.manifest.json" \
    --signed-artifact "$signed_root" \
    --signed-manifest "$signed_products/CFWLegacyTombstone.manifest.json" \
    --embedded-app "$embedded_app" \
    --context signing-attempt-work
}

write_signed_manifest
verify_tombstone_provenance_fixture

dwarfdump_binary="$(/usr/bin/xcrun --find dwarfdump)"
signed_uuid="$(
  "$dwarfdump_binary" --uuid "$signed_root/cfw-helper-tombstone" |
    /usr/bin/awk '$1 == "UUID:" && $3 == "(arm64)" { print $2 }'
)"
/usr/bin/printf '%s\n' 'embedded-byte-drift' >>"$embedded_binary"
embedded_uuid="$(
  "$dwarfdump_binary" --uuid "$embedded_binary" |
    /usr/bin/awk '$1 == "UUID:" && $3 == "(arm64)" { print $2 }'
)"
[[ -n "$signed_uuid" && "$embedded_uuid" == "$signed_uuid" ]] || {
  echo "error: embedded drift fixture did not preserve the Mach-O UUID" >&2
  exit 1
}
if (verify_tombstone_provenance_fixture) >/dev/null 2>&1; then
  echo "error: embedded tombstone byte drift was accepted" >&2
  exit 1
fi
/bin/cp "$signed_root/cfw-helper-tombstone" "$embedded_binary"
/bin/chmod 0755 "$embedded_binary"
verify_tombstone_provenance_fixture

for tombstone_mode_target in \
  "$pre_sign_root/cfw-helper-tombstone" \
  "$signed_root/cfw-helper-tombstone" \
  "$embedded_binary"; do
  /bin/chmod 0644 "$tombstone_mode_target"
  if (verify_tombstone_provenance_fixture) >/dev/null 2>&1; then
    echo "error: non-executable tombstone mode was accepted" >&2
    exit 1
  fi
  /bin/chmod 0755 "$tombstone_mode_target"
  verify_tombstone_provenance_fixture
done

"$python_bin" -I -S -B -W error - \
  "$signed_products/CFWLegacyTombstone.manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
value = json.loads(manifest.read_text(encoding="utf-8"))
value["metadata"]["preSignManifestSha256"] = "0" * 64
manifest.write_text(json.dumps(value), encoding="utf-8")
PY
if (verify_tombstone_provenance_fixture) >/dev/null 2>&1; then
  echo "error: mutated tombstone promotion lineage was accepted" >&2
  exit 1
fi

/bin/rm "$signed_products/CFWLegacyTombstone.manifest.json"
write_signed_manifest
verify_tombstone_provenance_fixture
echo "verify release app tombstone provenance test passed"
