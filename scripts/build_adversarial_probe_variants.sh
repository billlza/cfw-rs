#!/bin/bash
set -euo pipefail
umask 077

if [[ ${EUID} -ne 0 ]]; then
  echo "error: adversarial probe installation requires root" >&2
  exit 1
fi

if [[ -z ${CFW_RELEASE_SIGNING_IDENTITY:-} ]]; then
  echo "error: CFW_RELEASE_SIGNING_IDENTITY is required" >&2
  exit 1
fi

if [[ -z ${CFW_ADVERSARIAL_SAME_TEAM_NON_DEVELOPER_IDENTITY:-} ]]; then
  echo "error: CFW_ADVERSARIAL_SAME_TEAM_NON_DEVELOPER_IDENTITY is required" >&2
  exit 1
fi

if [[ ${CFW_ADVERSARIAL_SAME_TEAM_NON_DEVELOPER_IDENTITY} == "${CFW_RELEASE_SIGNING_IDENTITY}" ]]; then
  echo "error: wrong-designated-requirement requires a distinct signing identity" >&2
  exit 1
fi

readonly REPOSITORY="/Users/bill/cfw-rs"
readonly PACKAGE="${REPOSITORY}/native/macos"
readonly INSTALL_ROOT="/Library/Application Support/Clash for Mac/ReleaseVerification/Adversarial"
SCRATCH_ROOT=$(/usr/bin/mktemp -d /private/var/tmp/cfw-adversarial-probes.XXXXXX)
readonly SCRATCH_ROOT
readonly DIGEST_FILE="${SCRATCH_ROOT}/signed-binary-digests"
readonly EXTERNAL_DIGEST_FILE="${SCRATCH_ROOT}/signed-external-fixture-digests"
readonly PACKAGE_DOCUMENT="${SCRATCH_ROOT}/package.json"
readonly PRODUCT_ENTITLEMENTS="${REPOSITORY}/scripts/physical_capture/signing/adversarial-product.entitlements.plist"
readonly EMPTY_ENTITLEMENTS="${REPOSITORY}/scripts/physical_capture/signing/adversarial-empty.entitlements.plist"
readonly SWIFT="/usr/bin/swift"
readonly CODESIGN="/usr/bin/codesign"
readonly INSTALL="/usr/bin/install"
readonly SHASUM="/usr/bin/shasum"
readonly PRODUCT_TEAM_ID="YKUPL7Z869"
readonly PRODUCT_HOST_SIGNING_ID="com.bill.clashformac"
readonly PRODUCT_APP_GROUP="YKUPL7Z869.group.com.bill.clashformac"
readonly HOST_REQUIREMENT="anchor apple generic and identifier \"${PRODUCT_HOST_SIGNING_ID}\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"${PRODUCT_TEAM_ID}\" and entitlement[\"com.apple.security.application-groups\"] = \"${PRODUCT_APP_GROUP}\""
readonly SAME_TEAM_HOST_REQUIREMENT="anchor apple generic and identifier \"${PRODUCT_HOST_SIGNING_ID}\" and certificate leaf[subject.OU] = \"${PRODUCT_TEAM_ID}\" and entitlement[\"com.apple.security.application-groups\"] = \"${PRODUCT_APP_GROUP}\""

cleanup() {
  case "${SCRATCH_ROOT}" in
    /private/var/tmp/cfw-adversarial-probes.*)
      /bin/rm -rf -- "${SCRATCH_ROOT}"
      ;;
    *)
      echo "error: refusing to clean an unexpected scratch path" >&2
      ;;
  esac
}
trap cleanup EXIT

require_safe_existing_directory() {
  local directory=$1
  [[ -e ${directory} ]] || return 0
  if [[ ! -d ${directory} || -L ${directory} ]]; then
    echo "error: unsafe install ancestor ${directory}" >&2
    exit 1
  fi
  local owner mode
  owner=$(/usr/bin/stat -f '%u' "${directory}")
  mode=$(/usr/bin/stat -f '%Lp' "${directory}")
  if [[ ${owner} -ne 0 ]] || (( (8#${mode} & 8#022) != 0 )); then
    echo "error: install ancestor is not root-owned and non-writable: ${directory}" >&2
    exit 1
  fi
}

for install_ancestor in \
  "/Library" \
  "/Library/Application Support" \
  "/Library/Application Support/Clash for Mac" \
  "/Library/Application Support/Clash for Mac/ReleaseVerification" \
  "${INSTALL_ROOT}"
do
  require_safe_existing_directory "${install_ancestor}"
done
"${INSTALL}" -d -o root -g wheel -m 0755 "${INSTALL_ROOT}"
require_safe_existing_directory "${INSTALL_ROOT}"

readonly CASES=(
  wrong-team-id
  wrong-bundle-identifier
  wrong-designated-requirement
  wrong-entitlement
  same-team-unknown-bundle
)
readonly DEFINES=(
  CFW_ADVERSARIAL_WRONG_TEAM_ID
  CFW_ADVERSARIAL_WRONG_BUNDLE_IDENTIFIER
  CFW_ADVERSARIAL_WRONG_DESIGNATED_REQUIREMENT
  CFW_ADVERSARIAL_WRONG_ENTITLEMENT
  CFW_ADVERSARIAL_SAME_TEAM_UNKNOWN_BUNDLE
)

build_product() {
  local scratch=$1
  local product=$2
  shift 2
  "${SWIFT}" build \
    --package-path "${PACKAGE}" \
    --scratch-path "${scratch}" \
    --configuration release \
    --product "${product}" \
    "$@" >/dev/null
  local binary_directory
  binary_directory=$("${SWIFT}" build \
    --package-path "${PACKAGE}" \
    --scratch-path "${scratch}" \
    --configuration release \
    --show-bin-path \
    "$@")
  echo "${binary_directory}/${product}"
}

sign_product() {
  local source=$1
  local destination=$2
  local identity=$3
  local identifier=$4
  local entitlements=$5
  shift 5
  local timestamp_argument=--timestamp
  if [[ ${identity} == - ]]; then
    timestamp_argument=--timestamp=none
  fi
  "${INSTALL}" -d -o root -g wheel -m 0755 "$(/usr/bin/dirname "${destination}")"
  "${INSTALL}" -o root -g wheel -m 0755 "${source}" "${destination}"
  "${CODESIGN}" --force --sign "${identity}" --identifier "${identifier}" \
    --options runtime "${timestamp_argument}" --entitlements "${entitlements}" "$@" "${destination}"
  "${CODESIGN}" --verify --strict --verbose=4 "${destination}"
}

verify_wrong_designated_requirement_isolated() {
  local destination=$1
  "${CODESIGN}" --verify --strict -R="${SAME_TEAM_HOST_REQUIREMENT}" "${destination}"

  local requirement_exit=0
  "${CODESIGN}" --verify --strict -R="${HOST_REQUIREMENT}" "${destination}" \
    >/dev/null 2>&1 || requirement_exit=$?
  if [[ ${requirement_exit} -ne 3 ]]; then
    echo "error: wrong-designated-requirement did not isolate the Developer ID certificate requirement" >&2
    exit 1
  fi
}

controller_scratch="${SCRATCH_ROOT}/controller"
controller_bin=$(build_product "${controller_scratch}" CFWAdversarialProbe)
sign_product \
  "${controller_bin}" \
  "${INSTALL_ROOT}/CFWAdversarialProbe" \
  "${CFW_RELEASE_SIGNING_IDENTITY}" \
  "${PRODUCT_HOST_SIGNING_ID}" \
  "${PRODUCT_ENTITLEMENTS}"

/usr/bin/touch "${DIGEST_FILE}"

for index in "${!CASES[@]}"; do
  case_id=${CASES[$index]}
  define=${DEFINES[$index]}
  scratch="${SCRATCH_ROOT}/${case_id}"
  binary=$(build_product "${scratch}" CFWAdversarialProbe -Xswiftc -D"${define}")
  identity=${CFW_RELEASE_SIGNING_IDENTITY}
  identifier=${PRODUCT_HOST_SIGNING_ID}
  entitlements=${PRODUCT_ENTITLEMENTS}
  case "${case_id}" in
    wrong-team-id)
      identity=${CFW_ADVERSARIAL_NON_PRODUCT_SIGNING_IDENTITY:--}
      ;;
    wrong-bundle-identifier)
      identifier="com.bill.clashformac.wrong-bundle"
      ;;
    wrong-designated-requirement)
      identity=${CFW_ADVERSARIAL_SAME_TEAM_NON_DEVELOPER_IDENTITY}
      ;;
    wrong-entitlement)
      entitlements=${EMPTY_ENTITLEMENTS}
      ;;
    same-team-unknown-bundle)
      identifier="com.bill.clashformac.unknown-role"
      ;;
  esac
  destination="${INSTALL_ROOT}/IdentityVariants/${case_id}/CFWAdversarialProbe"
  sign_product \
    "${binary}" \
    "${destination}" \
    "${identity}" \
    "${identifier}" \
    "${entitlements}"
  if [[ ${case_id} == wrong-designated-requirement ]]; then
    verify_wrong_designated_requirement_isolated "${destination}"
  fi
  "${SHASUM}" -a 256 "${destination}" | /usr/bin/awk '{print $1}' >>"${DIGEST_FILE}"
done

if [[ $(/usr/bin/sort -u "${DIGEST_FILE}" | /usr/bin/wc -l | /usr/bin/tr -d ' ') -ne ${#CASES[@]} ]]; then
  echo "error: identity variants reused a signed executable byte digest" >&2
  exit 1
fi
echo "installed one controller and ${#CASES[@]} independent identity variants"

readonly EXTERNAL_FIXTURE_IDS=(
  authority-operation-replay-controller
  bounded-authority-load-controller
  fast-user-switch-controller
  isolated-audit-session-controller
  isolated-console-session-controller
  pid-reuse-window-controller
  root-owned-authority-journal-snapshot
  root-owned-secret-canary-scanner
  root-owned-uid-launcher
  signed-owner-liveness-controller
)
readonly EXTERNAL_TARGETS=(
  CFWAdversarialAuthorityOperationReplayController
  CFWAdversarialBoundedAuthorityLoadController
  CFWAdversarialFastUserSwitchController
  CFWAdversarialIsolatedAuditSessionController
  CFWAdversarialIsolatedConsoleSessionController
  CFWAdversarialPidReuseWindowController
  CFWAdversarialRootOwnedAuthorityJournalSnapshot
  CFWAdversarialRootOwnedSecretCanaryScanner
  CFWAdversarialRootOwnedUidLauncher
  CFWAdversarialSignedOwnerLivenessController
)
readonly EXTERNAL_SOURCE_PATHS=(
  PhysicalFixtures/CFWAdversarialAuthorityOperationReplayController
  PhysicalFixtures/CFWAdversarialBoundedAuthorityLoadController
  PhysicalFixtures/CFWAdversarialFastUserSwitchController
  PhysicalFixtures/CFWAdversarialIsolatedAuditSessionController
  PhysicalFixtures/CFWAdversarialIsolatedConsoleSessionController
  PhysicalFixtures/CFWAdversarialPidReuseWindowController
  PhysicalFixtures/CFWAdversarialRootOwnedAuthorityJournalSnapshot
  PhysicalFixtures/CFWAdversarialRootOwnedSecretCanaryScanner
  PhysicalFixtures/CFWAdversarialRootOwnedUidLauncher
  PhysicalFixtures/CFWAdversarialSignedOwnerLivenessController
)
readonly EXTERNAL_CASE_GROUPS=(
  "replayed-operation replayed-start-ticket duplicate-redemption"
  "request-flood in-flight-saturation event-queue-saturation"
  "fast-user-switching-race"
  "wrong-audit-session stale-audit-evidence"
  "inactive-console-user"
  "stale-pid-evidence"
  "replay-cursor-rollback authority-journal-truncation authority-journal-tamper authority-journal-symlink"
  "secret-extraction-logs secret-extraction-preferences secret-extraction-journal secret-extraction-crash-records secret-extraction-snapshots secret-extraction-evidence"
  "wrong-uid"
  "heartbeat-loss late-callback"
)

"${SWIFT}" package --package-path "${PACKAGE}" dump-package >"${PACKAGE_DOCUMENT}"
/usr/bin/python3 - "${PACKAGE_DOCUMENT}" \
  "${EXTERNAL_TARGETS[0]}" "${EXTERNAL_SOURCE_PATHS[0]}" \
  "${EXTERNAL_TARGETS[1]}" "${EXTERNAL_SOURCE_PATHS[1]}" \
  "${EXTERNAL_TARGETS[2]}" "${EXTERNAL_SOURCE_PATHS[2]}" \
  "${EXTERNAL_TARGETS[3]}" "${EXTERNAL_SOURCE_PATHS[3]}" \
  "${EXTERNAL_TARGETS[4]}" "${EXTERNAL_SOURCE_PATHS[4]}" \
  "${EXTERNAL_TARGETS[5]}" "${EXTERNAL_SOURCE_PATHS[5]}" \
  "${EXTERNAL_TARGETS[6]}" "${EXTERNAL_SOURCE_PATHS[6]}" \
  "${EXTERNAL_TARGETS[7]}" "${EXTERNAL_SOURCE_PATHS[7]}" \
  "${EXTERNAL_TARGETS[8]}" "${EXTERNAL_SOURCE_PATHS[8]}" \
  "${EXTERNAL_TARGETS[9]}" "${EXTERNAL_SOURCE_PATHS[9]}" <<'PY'
import json
from pathlib import Path
import sys

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
names = sys.argv[2::2]
paths = sys.argv[3::2]
if len(names) != len(paths) or len(names) != 10:
    raise SystemExit("error: external fixture verification arguments are incomplete")
expected = dict(zip(names, paths))
products = {value["name"]: value for value in document.get("products", [])}
targets = {value["name"]: value for value in document.get("targets", [])}
for target_name, source_path in expected.items():
    product = products.get(target_name)
    target = targets.get(target_name)
    if (
        not isinstance(product, dict)
        or product.get("targets") != [target_name]
        or product.get("type") != {"executable": None}
        or not isinstance(target, dict)
        or target.get("type") != "executable"
        or target.get("path") != source_path
    ):
        raise SystemExit(
            f"error: external fixture SwiftPM binding drifted for {target_name}"
        )
PY

/usr/bin/touch "${EXTERNAL_DIGEST_FILE}"
external_case_count=0
for index in "${!EXTERNAL_FIXTURE_IDS[@]}"; do
  fixture_id=${EXTERNAL_FIXTURE_IDS[$index]}
  target=${EXTERNAL_TARGETS[$index]}
  source_path="${PACKAGE}/${EXTERNAL_SOURCE_PATHS[$index]}/main.swift"
  if [[ ! -f ${source_path} || -L ${source_path} ]]; then
    echo "error: external fixture source is unavailable: ${source_path}" >&2
    exit 1
  fi
  for case_id in ${EXTERNAL_CASE_GROUPS[$index]}; do
    define="CFW_ADVERSARIAL_CASE_$(echo "${case_id}" | /usr/bin/tr '[:lower:]-' '[:upper:]_')"
    scratch="${SCRATCH_ROOT}/external-${case_id}"
    binary=$(build_product "${scratch}" "${target}" -Xswiftc -D"${define}")
    destination="${INSTALL_ROOT}/PhysicalFixtures/${fixture_id}/${case_id}/CFWAdversarialFixture"
    sign_product \
      "${binary}" \
      "${destination}" \
      "${CFW_RELEASE_SIGNING_IDENTITY}" \
      "${PRODUCT_HOST_SIGNING_ID}" \
      "${PRODUCT_ENTITLEMENTS}"
    "${CODESIGN}" --verify --strict -R="${HOST_REQUIREMENT}" "${destination}"
    require_safe_existing_directory "${INSTALL_ROOT}/PhysicalFixtures"
    require_safe_existing_directory "${INSTALL_ROOT}/PhysicalFixtures/${fixture_id}"
    require_safe_existing_directory "${INSTALL_ROOT}/PhysicalFixtures/${fixture_id}/${case_id}"
    owner=$(/usr/bin/stat -f '%u' "${destination}")
    group=$(/usr/bin/stat -f '%g' "${destination}")
    mode=$(/usr/bin/stat -f '%Lp' "${destination}")
    links=$(/usr/bin/stat -f '%l' "${destination}")
    if [[ ${owner} -ne 0 || ${group} -ne 0 || ${mode} != 755 || ${links} -ne 1 ]]; then
      echo "error: external fixture is not a unique root-owned immutable executable" >&2
      exit 1
    fi
    "${SHASUM}" -a 256 "${destination}" | /usr/bin/awk '{print $1}' >>"${EXTERNAL_DIGEST_FILE}"
    external_case_count=$((external_case_count + 1))
  done
done

if [[ ${external_case_count} -ne 24 ]]; then
  echo "error: external adversarial case installation is not the exact 24-case closure" >&2
  exit 1
fi
if [[ $(/usr/bin/sort -u "${EXTERNAL_DIGEST_FILE}" | /usr/bin/wc -l | /usr/bin/tr -d ' ') -ne ${external_case_count} ]]; then
  echo "error: external fixtures reused a signed executable byte digest" >&2
  exit 1
fi
if [[ $(/usr/bin/sort -u "${DIGEST_FILE}" "${EXTERNAL_DIGEST_FILE}" | /usr/bin/wc -l | /usr/bin/tr -d ' ') -ne $((external_case_count + ${#CASES[@]})) ]]; then
  echo "error: external and identity fixtures reused a signed executable byte digest" >&2
  exit 1
fi

echo "installed one controller, ${#CASES[@]} identity variants, and ${external_case_count} source-fixed external fixtures"
