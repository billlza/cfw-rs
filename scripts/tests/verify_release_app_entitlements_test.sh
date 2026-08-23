#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../verify_release_app.sh
source "$repo_root/scripts/verify_release_app.sh"
entitlement_test_python="${CFW_RELEASE_PYTHON_EXECUTABLE:-}"
[[ -x "$entitlement_test_python" ]] || {
  echo "error: entitlement fixture requires closed Python" >&2
  exit 1
}

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/cfw-entitlement-test.XXXXXX")"
trap '/bin/rm -rf "$temporary_root"' EXIT

write_fixture() {
  local path="$1"
  local kind="$2"
  local keychain_mode="$3"
  PYTHONDONTWRITEBYTECODE=1 "$entitlement_test_python" -I -S -B -W error - \
    "$path" "$kind" "$keychain_mode" "$expected_team_id" \
    "$expected_app_group" "$expected_agent_keychain_access_group" \
    "$expected_extension_keychain_access_group" <<'PY'
import plistlib
import sys

(
    path,
    kind,
    keychain_mode,
    team_id,
    app_group,
    agent_keychain_group,
    extension_keychain_group,
) = sys.argv[1:]
bundle_ids = {
    "host": "com.bill.clashformac",
    "packet-tunnel": "com.bill.clashformac.packet-tunnel",
    "proxy-agent": "com.bill.clashformac.proxy-agent",
}
entitlements = {
    "com.apple.application-identifier": f"{team_id}.{bundle_ids[kind]}",
    "com.apple.developer.team-identifier": team_id,
}
if kind != "packet-tunnel":
    entitlements["com.apple.security.application-groups"] = [app_group]
packet_tunnel = ["packet-tunnel-provider-systemextension"]
if kind == "host":
    entitlements.update(
        {
            "com.apple.developer.system-extension.install": True,
            "com.apple.developer.networking.networkextension": packet_tunnel,
        }
    )
elif kind == "packet-tunnel":
    entitlements.update(
        {
            "com.apple.developer.networking.networkextension": packet_tunnel,
            "com.apple.security.app-sandbox": True,
            "com.apple.security.application-groups": [app_group],
            "com.apple.security.network.client": True,
            "com.apple.security.network.server": True,
        }
    )
if keychain_mode == "exact":
    host_group = agent_keychain_group.removesuffix(".proxy-agent")
    credential_group = f"{host_group}.credentials"
    expected_groups = {
        "host": [host_group, credential_group],
        "packet-tunnel": [extension_keychain_group],
        "proxy-agent": [agent_keychain_group, credential_group],
    }[kind]
    entitlements["keychain-access-groups"] = expected_groups
elif keychain_mode == "app-group":
    entitlements["com.apple.security.application-groups"] = [app_group]
elif keychain_mode == "wrong-app-group":
    entitlements["com.apple.security.application-groups"] = ["unexpected.group"]
elif keychain_mode == "wildcard":
    entitlements["keychain-access-groups"] = [f"{team_id}.*"]
elif keychain_mode == "wildcard-extra":
    entitlements["keychain-access-groups"] = [f"{team_id}.*", "com.apple.token"]
elif keychain_mode == "broad":
    entitlements["keychain-access-groups"] = ["*"]
elif keychain_mode == "wrong-wildcard":
    entitlements["keychain-access-groups"] = [f"{team_id}.*", "WRONGTEAM1.*"]
elif keychain_mode == "wrong":
    entitlements["keychain-access-groups"] = [f"WRONG.{bundle_ids['proxy-agent']}"]
elif keychain_mode == "extra":
    host_group = agent_keychain_group.removesuffix(".proxy-agent")
    entitlements["keychain-access-groups"] = [
        agent_keychain_group,
        f"{host_group}.credentials",
        "unexpected.group",
    ]

with open(path, "wb") as handle:
    plistlib.dump(entitlements, handle, sort_keys=True)
PY
}

expect_rejected() {
  local path="$1"
  local kind="$2"
  local bundle_id="$3"
  if verify_entitlements "$path" "$kind" "$bundle_id" >/dev/null 2>&1; then
    echo "error: expected entitlement fixture to be rejected: $path" >&2
    exit 1
  fi
}

profile_fixture="$temporary_root/profile.plist"
certificate_fixture="$temporary_root/signing-certificate.der"
printf '%s' 'test-signing-certificate' >"$certificate_fixture"
bundle_fixture="$temporary_root/Fixture.app"
mkdir -p "$bundle_fixture/Contents"
printf '%s' 'profile-placeholder' >"$bundle_fixture/Contents/embedded.provisionprofile"

write_profile_fixture() {
  local entitlements_path="$1"
  PYTHONDONTWRITEBYTECODE=1 "$entitlement_test_python" -I -S -B -W error - \
    "$profile_fixture" "$entitlements_path" "$certificate_fixture" \
    "$expected_team_id" <<'PY'
from datetime import datetime, timedelta, timezone
import plistlib
import sys

profile_path, entitlements_path, certificate_path, team_id = sys.argv[1:]
with open(entitlements_path, "rb") as handle:
    entitlements = plistlib.load(handle)
profile_keys = {
    "application-identifier",
    "com.apple.application-identifier",
    "com.apple.developer.networking.networkextension",
    "com.apple.developer.system-extension.install",
    "com.apple.developer.team-identifier",
    "com.apple.security.application-groups",
    "keychain-access-groups",
}
entitlements = {
    key: value for key, value in entitlements.items() if key in profile_keys
}
with open(certificate_path, "rb") as handle:
    certificate = handle.read()
now = datetime.now(timezone.utc).replace(tzinfo=None)
profile = {
    "ApplicationIdentifierPrefix": [team_id],
    "CreationDate": now - timedelta(days=1),
    "DeveloperCertificates": [certificate],
    "Entitlements": entitlements,
    "ExpirationDate": now + timedelta(days=1),
    "Platform": ["OSX"],
    "ProvisionsAllDevices": True,
    "TeamIdentifier": [team_id],
    "UUID": "11111111-1111-1111-1111-111111111111",
}
with open(profile_path, "wb") as handle:
    plistlib.dump(profile, handle, sort_keys=True)
PY
}

write_portal_profile_fixture() {
  local signed_entitlements_path="$1"
  local kind="$2"
  write_profile_fixture "$signed_entitlements_path"
  PYTHONDONTWRITEBYTECODE=1 "$entitlement_test_python" -I -S -B -W error - \
    "$profile_fixture" "$kind" "$expected_team_id" <<'PY'
import plistlib
import sys

path, kind, team_id = sys.argv[1:]
with open(path, "rb") as handle:
    profile = plistlib.load(handle)
entitlements = profile["Entitlements"]
entitlements["com.apple.security.application-groups"] = [
    "group.com.bill.clashformac",
    f"{team_id}.*",
]
entitlements["keychain-access-groups"] = [f"{team_id}.*"]
if kind in {"host", "packet-tunnel"}:
    entitlements["com.apple.developer.networking.networkextension"] = [
        "packet-tunnel-provider-systemextension",
        "app-proxy-provider-systemextension",
        "content-filter-provider-systemextension",
        "dns-proxy-systemextension",
        "dns-settings",
        "relay",
        "url-filter-provider",
        "hotspot-provider",
    ]
if kind == "host":
    entitlements["com.apple.developer.system-extension.install"] = True
else:
    entitlements.pop("com.apple.developer.system-extension.install", None)
if kind == "proxy-agent":
    entitlements.pop("com.apple.developer.networking.networkextension", None)
with open(path, "wb") as handle:
    plistlib.dump(profile, handle, sort_keys=True)
PY
}

security() {
  [[ "$1" == "cms" && "$2" == "-D" && "$3" == "-i" ]] || return 1
  plutil -convert xml1 -o - "$profile_fixture"
}

codesign() {
  local argument
  for argument in "$@"; do
    case "$argument" in
      --extract-certificates=*)
        /bin/cp "$certificate_fixture" "${argument#--extract-certificates=}0"
        return 0
        ;;
    esac
  done
  return 1
}

expect_profile_rejected() {
  local kind="$1"
  local bundle_id="$2"
  local signed_entitlements="$3"
  if verify_provisioning_profile \
    "$bundle_fixture" \
    "$kind" \
    "$bundle_id" \
    "$signed_entitlements" >/dev/null 2>&1; then
    echo "error: expected provisioning fixture to be rejected: $profile_fixture" >&2
    exit 1
  fi
}

write_fixture "$temporary_root/proxy-valid.plist" proxy-agent exact
verify_entitlements "$temporary_root/proxy-valid.plist" proxy-agent "$expected_agent_id"
write_profile_fixture "$temporary_root/proxy-valid.plist"
verify_provisioning_profile \
  "$bundle_fixture" \
  proxy-agent \
  "$expected_agent_id" \
  "$temporary_root/proxy-valid.plist"
write_portal_profile_fixture "$temporary_root/proxy-valid.plist" proxy-agent
verify_provisioning_profile \
  "$bundle_fixture" \
  proxy-agent \
  "$expected_agent_id" \
  "$temporary_root/proxy-valid.plist"
write_fixture "$temporary_root/proxy-profile-wildcard-extra.plist" proxy-agent wildcard-extra
write_profile_fixture "$temporary_root/proxy-profile-wildcard-extra.plist"
verify_provisioning_profile \
  "$bundle_fixture" \
  proxy-agent \
  "$expected_agent_id" \
  "$temporary_root/proxy-valid.plist"
write_fixture "$temporary_root/proxy-profile-wildcard.plist" proxy-agent wildcard
write_profile_fixture "$temporary_root/proxy-profile-wildcard.plist"
verify_provisioning_profile \
  "$bundle_fixture" \
  proxy-agent \
  "$expected_agent_id" \
  "$temporary_root/proxy-valid.plist"

write_fixture "$temporary_root/proxy-missing.plist" proxy-agent absent
expect_rejected "$temporary_root/proxy-missing.plist" proxy-agent "$expected_agent_id"
write_profile_fixture "$temporary_root/proxy-missing.plist"
expect_profile_rejected \
  proxy-agent \
  "$expected_agent_id" \
  "$temporary_root/proxy-valid.plist"
write_fixture "$temporary_root/proxy-profile-wrong-wildcard.plist" proxy-agent wrong-wildcard
write_profile_fixture "$temporary_root/proxy-profile-wrong-wildcard.plist"
expect_profile_rejected \
  proxy-agent \
  "$expected_agent_id" \
  "$temporary_root/proxy-valid.plist"
write_fixture "$temporary_root/proxy-wrong.plist" proxy-agent wrong
expect_rejected "$temporary_root/proxy-wrong.plist" proxy-agent "$expected_agent_id"
write_profile_fixture "$temporary_root/proxy-wrong.plist"
expect_profile_rejected \
  proxy-agent \
  "$expected_agent_id" \
  "$temporary_root/proxy-valid.plist"
write_fixture "$temporary_root/proxy-profile-broad.plist" proxy-agent broad
write_profile_fixture "$temporary_root/proxy-profile-broad.plist"
expect_profile_rejected \
  proxy-agent \
  "$expected_agent_id" \
  "$temporary_root/proxy-valid.plist"
write_fixture "$temporary_root/proxy-extra.plist" proxy-agent extra
expect_rejected "$temporary_root/proxy-extra.plist" proxy-agent "$expected_agent_id"

write_fixture "$temporary_root/host-valid.plist" host exact
verify_entitlements "$temporary_root/host-valid.plist" host "$expected_app_id"
write_fixture "$temporary_root/host-overprivileged.plist" host wrong
expect_rejected "$temporary_root/host-overprivileged.plist" host "$expected_app_id"
write_fixture "$temporary_root/host-profile-wildcard.plist" host wildcard
write_profile_fixture "$temporary_root/host-profile-wildcard.plist"
verify_provisioning_profile \
  "$bundle_fixture" \
  host \
  "$expected_app_id" \
  "$temporary_root/host-valid.plist"
write_portal_profile_fixture "$temporary_root/host-valid.plist" host
verify_provisioning_profile \
  "$bundle_fixture" \
  host \
  "$expected_app_id" \
  "$temporary_root/host-valid.plist"

write_fixture "$temporary_root/tunnel-valid.plist" packet-tunnel absent
verify_entitlements "$temporary_root/tunnel-valid.plist" packet-tunnel "$expected_extension_id"
write_profile_fixture "$temporary_root/tunnel-valid.plist"
verify_provisioning_profile \
  "$bundle_fixture" \
  packet-tunnel \
  "$expected_extension_id" \
  "$temporary_root/tunnel-valid.plist"
write_portal_profile_fixture "$temporary_root/tunnel-valid.plist" packet-tunnel
verify_provisioning_profile \
  "$bundle_fixture" \
  packet-tunnel \
  "$expected_extension_id" \
  "$temporary_root/tunnel-valid.plist"
write_fixture "$temporary_root/tunnel-overprivileged.plist" packet-tunnel exact
expect_rejected \
  "$temporary_root/tunnel-overprivileged.plist" \
  packet-tunnel \
  "$expected_extension_id"
write_fixture "$temporary_root/tunnel-app-group.plist" packet-tunnel wrong-app-group
expect_rejected \
  "$temporary_root/tunnel-app-group.plist" \
  packet-tunnel \
  "$expected_extension_id"
write_profile_fixture "$temporary_root/tunnel-overprivileged.plist"
expect_profile_rejected \
  packet-tunnel \
  "$expected_extension_id" \
  "$temporary_root/tunnel-valid.plist"
write_fixture "$temporary_root/tunnel-profile-wildcard.plist" packet-tunnel wildcard
write_profile_fixture "$temporary_root/tunnel-profile-wildcard.plist"
verify_provisioning_profile \
  "$bundle_fixture" \
  packet-tunnel \
  "$expected_extension_id" \
  "$temporary_root/tunnel-valid.plist"
write_fixture "$temporary_root/tunnel-profile-app-group.plist" packet-tunnel app-group
write_profile_fixture "$temporary_root/tunnel-profile-app-group.plist"
verify_provisioning_profile \
  "$bundle_fixture" \
  packet-tunnel \
  "$expected_extension_id" \
  "$temporary_root/tunnel-valid.plist"
write_fixture "$temporary_root/tunnel-profile-wrong-wildcard.plist" packet-tunnel wrong-wildcard
write_profile_fixture "$temporary_root/tunnel-profile-wrong-wildcard.plist"
expect_profile_rejected \
  packet-tunnel \
  "$expected_extension_id" \
  "$temporary_root/tunnel-valid.plist"

echo "release entitlement negative tests passed"
