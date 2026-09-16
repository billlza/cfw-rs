#!/bin/bash -p
# Adopt only an explicitly unsigned CI selection in this shell's effective
# build settings. The production dependency-pins file is never modified.

cfw_apply_validation_apple_toolchain() {
  local policy_repository="$1"
  local observed_identity observed_version observed_build unexpected
  if [[ -z "${CFW_UNSIGNED_VALIDATION_XCODE_VERSION+x}" && \
    -z "${CFW_UNSIGNED_VALIDATION_XCODE_BUILD_VERSION+x}" ]]; then
    return 0
  fi
  if [[ -z "${CFW_UNSIGNED_VALIDATION_PYTHON:-}" || \
    ! -x "${CFW_RELEASE_PYTHON_EXECUTABLE:-}" ]]; then
    echo "error: unsigned-validation Xcode requires the closed validation role" >&2
    return 1
  fi
  observed_identity="$(
    cfw_run_release_python_script "$policy_repository" \
      "$policy_repository/scripts/apple_validation_policy.py" \
      --repository "$policy_repository"
  )" || return 1
  read -r observed_version observed_build unexpected <<<"$observed_identity" || return 1
  if [[ -z "$observed_version" || -z "$observed_build" || -n "${unexpected:-}" ]]; then
    echo "error: unsigned-validation Xcode identity is incomplete" >&2
    return 1
  fi
  XCODE_VERSION="$observed_version"
  XCODE_BUILD_VERSION="$observed_build"
  # Effective shell settings stay local; child processes receive only the
  # explicitly admitted CFW_UNSIGNED_VALIDATION_* identity fields.
  export -n XCODE_VERSION XCODE_BUILD_VERSION
}
