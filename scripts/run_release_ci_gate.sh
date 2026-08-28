#!/bin/bash -p
# Execute release-critical hosted CI gates with the same closed tool identity
# used by local evidence collection. Each gate is explicit and fail closed.
set -euo pipefail
unset CDPATH

repo_root="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
cd "$repo_root"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_tool_environment.sh
source "$repo_root/scripts/release_tool_environment.sh"
# shellcheck source=scripts/release_policy_tool_directory.sh
source "$repo_root/scripts/release_policy_tool_directory.sh"

die() {
  echo "error: $*" >&2
  exit 1
}

ci_release_role="production"
if [[ $# -ge 3 && "$1" == "--validation-python-executable" && "$2" == /* ]]; then
  export CFW_UNSIGNED_VALIDATION_PYTHON="$2"
  ci_release_role="unsigned-validation"
  shift 2
fi
[[ $# -ge 1 ]] ||
  die "usage: scripts/run_release_ci_gate.sh [--validation-python-executable ABSOLUTE_PATH] GATE [GATE_ARGUMENTS]"
gate="$1"
shift
readonly gate ci_release_role

# The sealed release environment deliberately stops exporting ambient TMPDIR.
# Capture only the workflow-bound Tauri staging parent before sealing, then
# pass it explicitly to the installer after validating it at the dispatch
# boundary. Other gates do not inherit this ambient path.
tauri_temporary_parent_input=""
if [[ "$gate" == "install-tauri-cli" ]]; then
  tauri_temporary_parent_input="${TMPDIR:-}"
  while [[ "$tauri_temporary_parent_input" != "/" && \
    "$tauri_temporary_parent_input" == */ ]]; do
    tauri_temporary_parent_input="${tauri_temporary_parent_input%/}"
  done
  [[ -n "$tauri_temporary_parent_input" ]] ||
    die "install-tauri-cli requires an explicit temporary directory"
  export -n TMPDIR
fi
readonly tauri_temporary_parent_input

if [[ "$gate" == "bootstrap-policy-tools" ]]; then
  [[ $# -eq 0 ]] || die "bootstrap-policy-tools accepts no arguments"
  cfw_seal_release_tool_environment tool-bootstrap
  cfw_select_release_apple_toolchain
  export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"
  umask 077
  cfw_require_private_policy_directory "$HOME/.cfm-release-tooling"
  cfw_require_private_policy_directory "$CFW_RELEASE_POLICY_TOOL_ROOT"
  cfw_require_private_policy_directory "$CFW_RELEASE_POLICY_TOOL_ROOT/bin"
  cfw_release_cargo_inputs_identity "$repo_root" "$HOME" >/dev/null ||
    die "prepare-cargo-workspace-inputs must pass before policy-tool bootstrap"
  policy_bootstrap_root="$(/usr/bin/mktemp -d \
    "$HOME/.cfm-release-tooling/policy-bootstrap.XXXXXX")"
  /bin/chmod 0700 "$policy_bootstrap_root"
  /bin/mkdir -m 0700 \
    "$policy_bootstrap_root/home" \
    "$policy_bootstrap_root/cargo-home" \
    "$policy_bootstrap_root/target"
  cleanup_policy_bootstrap() {
    if [[ -n "${policy_bootstrap_root:-}" && \
      "$policy_bootstrap_root" == "$HOME/.cfm-release-tooling/policy-bootstrap."* && \
      -d "$policy_bootstrap_root" && ! -L "$policy_bootstrap_root" ]]; then
      /bin/rm -rf -- "$policy_bootstrap_root"
    fi
  }
  trap cleanup_policy_bootstrap EXIT
  policy_bootstrap_environment=(
    /usr/bin/env -i
    "HOME=$policy_bootstrap_root/home"
    "CARGO_HOME=$policy_bootstrap_root/cargo-home"
    "CARGO_TARGET_DIR=$policy_bootstrap_root/target"
    "PATH=$PATH"
    "LANG=C"
    "LC_ALL=C"
    "MACOSX_DEPLOYMENT_TARGET=$MACOS_DEPLOYMENT_TARGET"
  )
  cfw_run_warning_free_policy_install \
    "cargo-audit installation" \
    "$CFW_RELEASE_POLICY_TOOL_ROOT/.cargo-audit-install.log" \
    "${policy_bootstrap_environment[@]}" \
    "$CFW_RELEASE_CARGO_EXECUTABLE" install \
    cargo-audit --version "$CARGO_AUDIT_VERSION" --locked --force \
    --root "$CFW_RELEASE_POLICY_TOOL_ROOT"
  cfw_run_warning_free_policy_install \
    "cargo-deny installation" \
    "$CFW_RELEASE_POLICY_TOOL_ROOT/.cargo-deny-install.log" \
    "${policy_bootstrap_environment[@]}" \
    "$CFW_RELEASE_CARGO_EXECUTABLE" install \
    cargo-deny --version "$CARGO_DENY_VERSION" --locked --force \
    --root "$CFW_RELEASE_POLICY_TOOL_ROOT"
  /bin/chmod 0700 \
    "$CFW_RELEASE_POLICY_TOOL_ROOT" \
    "$CFW_RELEASE_POLICY_TOOL_ROOT/bin" \
    "$CFW_RELEASE_POLICY_TOOL_ROOT/bin/cargo-audit" \
    "$CFW_RELEASE_POLICY_TOOL_ROOT/bin/cargo-deny"
  cfw_seal_release_tool_environment "$ci_release_role"
  cfw_select_release_apple_toolchain
  [[ "$($CFW_RELEASE_CARGO_AUDIT_EXECUTABLE --version)" == \
    "cargo-audit $CARGO_AUDIT_VERSION" ]] ||
    die "installed cargo-audit identity differs from the release pin"
  [[ "$($CFW_RELEASE_CARGO_DENY_EXECUTABLE --version)" == \
    "cargo-deny $CARGO_DENY_VERSION" ]] ||
    die "installed cargo-deny identity differs from the release pin"
  cleanup_policy_bootstrap
  policy_bootstrap_root=""
  trap - EXIT
  exit 0
fi

if [[ "$gate" == "prepare-cargo-workspace-inputs" ]]; then
  [[ $# -eq 0 ]] || die "prepare-cargo-workspace-inputs accepts no arguments"
  cfw_seal_release_tool_environment tool-bootstrap
  cfw_select_release_apple_toolchain
  umask 077
  cfw_require_private_policy_directory "$HOME/.cfm-release-tooling"
  cargo_workspace_root="$(cfw_run_release_python_script \
    "$repo_root" "$repo_root/scripts/release_cargo_inputs.py" \
    locate --repository "$repo_root" --release-home "$HOME")"
  [[ "$cargo_workspace_root" == "$HOME/.cfm-release-tooling/cargo-workspace-"* ]] ||
    die "Cargo workspace input root is malformed"
  if [[ -e "$cargo_workspace_root" || -L "$cargo_workspace_root" ]]; then
    cfw_release_cargo_inputs_identity "$repo_root" "$HOME" >/dev/null
    exit 0
  fi
  cargo_fetch_root="$(/usr/bin/mktemp -d \
    "$HOME/.cfm-release-tooling/cargo-fetch.XXXXXX")"
  /bin/chmod 0700 "$cargo_fetch_root"
  /bin/mkdir -m 0700 \
    "$cargo_fetch_root/home" \
    "$cargo_fetch_root/cargo-home" \
    "$cargo_fetch_root/target"
  cleanup_cargo_fetch() {
    if [[ -n "${cargo_fetch_root:-}" && \
      "$cargo_fetch_root" == "$HOME/.cfm-release-tooling/cargo-fetch."* && \
      -d "$cargo_fetch_root" && ! -L "$cargo_fetch_root" ]]; then
      /bin/rm -rf -- "$cargo_fetch_root"
    fi
  }
  trap cleanup_cargo_fetch EXIT
  cfw_run_warning_free_policy_install \
    "Cargo workspace archive fetch" \
    "$cargo_fetch_root/fetch.log" \
    /usr/bin/env -i \
    "HOME=$cargo_fetch_root/home" \
    "CARGO_HOME=$cargo_fetch_root/cargo-home" \
    "CARGO_TARGET_DIR=$cargo_fetch_root/target" \
    "PATH=$PATH" \
    "LANG=C" \
    "LC_ALL=C" \
    "$CFW_RELEASE_CARGO_EXECUTABLE" fetch --locked
  cfw_run_release_python_script \
    "$repo_root" "$repo_root/scripts/release_cargo_inputs.py" \
    prepare \
    --repository "$repo_root" \
    --release-home "$HOME" \
    --source-cargo-home "$cargo_fetch_root/cargo-home" >/dev/null
  cfw_release_cargo_inputs_identity "$repo_root" "$HOME" >/dev/null
  cleanup_cargo_fetch
  cargo_fetch_root=""
  trap - EXIT
  exit 0
fi

cfw_seal_release_tool_environment "$ci_release_role"
cfw_select_release_apple_toolchain
export MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET"

case "$gate" in
  build-script-boundary)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/verify_build_boundaries.sh"
    ;;
  ci-no-masking)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    cfw_run_release_python_script \
      "$repo_root" "$repo_root/scripts/verify_ci_no_masking.py"
    ;;
  evidence-manifest-lane)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/verify_evidence_manifest_lane.sh"
    ;;
  version-contract)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    cfw_run_release_python_script \
      "$repo_root" "$repo_root/scripts/verify_version_contract.py"
    ;;
  rust-fmt)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    cfw_run_with_release_cargo_runtime \
      "$repo_root" "$CFW_RELEASE_CARGO_EXECUTABLE" fmt --all -- --check
    ;;
  rust-metadata)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    cfw_run_with_release_cargo_runtime \
      "$repo_root" "$CFW_RELEASE_CARGO_EXECUTABLE" metadata \
      --locked --filter-platform aarch64-apple-darwin --format-version 1 >/dev/null
    ;;
  rust-clippy)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    cfw_run_with_fresh_release_cargo_target \
      "$repo_root" "$CFW_RELEASE_CARGO_EXECUTABLE" clippy \
      --locked --workspace --all-targets --all-features -- -D warnings
    ;;
  rust-test)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    cfw_run_with_fresh_release_cargo_target \
      "$repo_root" "$CFW_RELEASE_CARGO_EXECUTABLE" test \
      --locked --workspace --all-targets --all-features
    ;;
  rust-target-audit)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    cfw_run_with_release_cargo_runtime \
      "$repo_root" cfw_run_release_python_script \
      "$repo_root" "$repo_root/scripts/audit_rust_target.py"
    ;;
  cargo-deny)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    cfw_run_with_release_cargo_runtime \
      "$repo_root" cfw_run_release_python_script \
      "$repo_root" "$repo_root/scripts/audit_cargo_policy.py"
    ;;
  packet-lan-peer)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/verify_packet_lan_peer.sh"
    cfw_run_release_python_script \
      "$repo_root" "$repo_root/scripts/verify_pinned_build_inputs.py"
    ;;
  bootstrap-node-toolchain)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/bootstrap_release_toolchain.sh" --node-only
    ;;
  bootstrap-release-toolchain)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/bootstrap_release_toolchain.sh"
    ;;
  prepare-ui-dependencies)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/prepare_ui_dependencies.sh"
    ;;
  ui-test)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/build_ui_with_pinned_node.sh" \
      --test
    ;;
  ui-build)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/build_ui_with_pinned_node.sh"
    ;;
  ui-audit)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/build_ui_with_pinned_node.sh" \
      --audit
    ;;
  swift-format-lint)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /usr/bin/swift format lint --recursive --strict \
      native/macos/Sources native/macos/SystemExtension native/macos/Tests
    ;;
  swift-package-test)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    # The current Swift test harness has synchronous semaphore recorders whose
    # callbacks run on cooperative Tasks. Cross-suite parallelism can starve
    # those callbacks; remove this only after every blocking recorder is async.
    /usr/bin/swift test --package-path native/macos \
      --no-parallel \
      -Xswiftc -warnings-as-errors
    ;;
  xcode-unsigned-test)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /usr/bin/xcodebuild test \
      -project native/macos/CFWNative.xcodeproj \
      -scheme CFWNativeTests \
      -destination 'platform=macOS,arch=arm64' \
      CODE_SIGNING_ALLOWED=NO
    ;;
  xcode-analyze)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    for scheme in \
      CFWNativeTests CFWPacketTunnelExtension CFWProxyAgent CFWNativeBridge; do
      /usr/bin/xcodebuild analyze \
        -project native/macos/CFWNative.xcodeproj \
        -scheme "$scheme" \
        -destination 'platform=macOS,arch=arm64' \
        CODE_SIGNING_ALLOWED=NO
    done
    ;;
  verify-xcode-project)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/verify_xcode_project.sh"
    ;;
  fetch-libbox-upstream)
    [[ $# -eq 1 && "$1" == /* ]] ||
      die "$gate requires one absolute empty output path"
    upstream_output="$1"
    [[ ! -e "$upstream_output" && ! -L "$upstream_output" ]] ||
      die "$gate refuses to replace its upstream output"
    /bin/mkdir -m 0700 "$upstream_output"
    empty_git_template="$upstream_output/.empty-git-template"
    /bin/mkdir -m 0700 "$empty_git_template"
    git_command=(
      /usr/bin/env -i
      "HOME=/var/empty"
      "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
      "LANG=C"
      "LC_ALL=C"
      "GIT_ASKPASS=/usr/bin/false"
      "GIT_ATTR_NOSYSTEM=1"
      "GIT_CONFIG_GLOBAL=/dev/null"
      "GIT_CONFIG_NOSYSTEM=1"
      "GIT_CONFIG_SYSTEM=/dev/null"
      "GIT_TERMINAL_PROMPT=0"
      /usr/bin/git
      -c core.attributesFile=/dev/null
      -c core.hooksPath=/dev/null
      -c core.fsmonitor=false
      -c core.untrackedCache=false
    )
    "${git_command[@]}" -C "$upstream_output" init -q \
      --template="$empty_git_template"
    /bin/rmdir "$empty_git_template"
    "${git_command[@]}" -C "$upstream_output" remote add origin \
      https://github.com/SagerNet/sing-box.git
    "${git_command[@]}" -C "$upstream_output" fetch --depth=1 \
      origin "$SING_BOX_COMMIT"
    "${git_command[@]}" -C "$upstream_output" checkout --detach FETCH_HEAD
    [[ "$("${git_command[@]}" -C "$upstream_output" rev-parse HEAD)" == \
      "$SING_BOX_COMMIT" ]] || die "fetched libbox source has the wrong commit"
    ;;
  install-tauri-cli)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    [[ "$tauri_temporary_parent_input" == /* && \
      -d "$tauri_temporary_parent_input" && \
      ! -L "$tauri_temporary_parent_input" ]] ||
      die "the Tauri CLI temporary directory must be an absolute real directory"
    tauri_temporary_parent="$(
      cd "$tauri_temporary_parent_input" && /bin/pwd -P
    )" || die "the Tauri CLI temporary directory cannot be resolved"
    readonly tauri_temporary_parent
    [[ "$tauri_temporary_parent" == /* && \
      -d "$tauri_temporary_parent" && ! -L "$tauri_temporary_parent" ]] ||
      die "the resolved Tauri CLI temporary directory is unsafe"
    [[ "$tauri_temporary_parent" != *:* ]] ||
      die "the Tauri CLI temporary directory must not contain ':'"
    [[ "$(/usr/bin/stat -f '%u' "$tauri_temporary_parent")" == \
      "$(/usr/bin/id -u)" ]] ||
      die "the Tauri CLI temporary directory must belong to the release account"
    tauri_temporary_mode="$(/usr/bin/stat -f '%Lp' "$tauri_temporary_parent")"
    readonly tauri_temporary_mode
    [[ "$tauri_temporary_mode" =~ ^[0-7]{3,4}$ ]] ||
      die "the Tauri CLI temporary directory mode is malformed"
    (( (8#$tauri_temporary_mode & 8#22) == 0 )) ||
      die "the Tauri CLI temporary directory must not be group- or other-writable"
    TMPDIR="$tauri_temporary_parent" \
      /bin/bash -p "$repo_root/scripts/install_pinned_tauri_cli.sh"
    ;;
  materialize-libbox-source)
    [[ $# -eq 2 && "$1" == /* && "$2" == /* ]] ||
      die "$gate requires absolute UPSTREAM_SOURCE and PATCHED_OUTPUT"
    SING_BOX_SOURCE="$1" LIBBOX_PATCHED_SOURCE_OUTPUT="$2" \
      /bin/bash -p "$repo_root/scripts/materialize_libbox_source.sh"
    ;;
  prepare-libbox-modules | libbox-source-tests | libbox-vulnerability-scan)
    [[ $# -eq 1 && "$1" == /* ]] ||
      die "$gate requires one absolute PATCHED_SOURCE"
    libbox_script="prepare_libbox_modules.sh"
    if [[ "$gate" == "libbox-source-tests" ]]; then
      libbox_script="test_libbox_source.sh"
    elif [[ "$gate" == "libbox-vulnerability-scan" ]]; then
      libbox_script="scan_libbox_vulnerabilities.sh"
    fi
    SING_BOX_SOURCE="$1" /bin/bash -p "$repo_root/scripts/$libbox_script"
    ;;
  build-libbox)
    [[ $# -ge 1 && $# -le 2 && "$1" == /* ]] ||
      die "$gate requires absolute PATCHED_SOURCE and optional absolute OUTPUT"
    if [[ $# -eq 2 && "$2" != /* ]]; then
      die "$gate output must be absolute"
    fi
    if [[ $# -eq 2 ]]; then
      SING_BOX_SOURCE="$1" LIBBOX_OUTPUT="$2" \
        /bin/bash -p "$repo_root/scripts/build_libbox.sh"
    else
      SING_BOX_SOURCE="$1" /bin/bash -p "$repo_root/scripts/build_libbox.sh"
    fi
    ;;
  build-native-products-unsigned)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    /bin/bash -p "$repo_root/scripts/build_native_products.sh" --unsigned
    ;;
  release-tool-tests)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    cfw_run_release_python_script \
      "$repo_root" "$repo_root/scripts/run_release_python_tests.py"
    while IFS= read -r test_script; do
      /bin/bash -p "$test_script"
    done < <(/usr/bin/find "$repo_root/scripts/tests" -type f -name '*_test.sh' | /usr/bin/sort)
    ;;
  updater-signer-integration)
    [[ $# -eq 0 ]] || die "$gate accepts no arguments"
    CFW_REQUIRE_PINNED_SIGNER_INTEGRATION=1 \
      cfw_run_release_python_script \
      "$repo_root" "$repo_root/scripts/run_release_python_tests.py" \
      --pattern test_updater_signing_launcher.py
    ;;
  *)
    die "unknown release CI gate: $gate"
    ;;
esac
