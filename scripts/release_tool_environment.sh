#!/bin/bash -p
# Shared fail-closed release tool selection. Consumers bind tool identity and
# actual execution to this same environment instead of inheriting caller PATH.

release_environment_directory="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && /bin/pwd -P)"
# shellcheck source=scripts/release_python_launcher.sh
source "$release_environment_directory/release_python_launcher.sh"
# shellcheck source=scripts/release_cargo_inputs.sh
source "$release_environment_directory/release_cargo_inputs.sh"
unset release_environment_directory

cfw_seal_release_tool_environment() {
  local release_role="${1:-production}"
  local validation_python_input="${CFW_UNSIGNED_VALIDATION_PYTHON:-}"
  local rust_toolchain_selection="${CFW_RELEASE_RUST_TOOLCHAIN-global}"
  local use_validation_python=0
  if [[ $# -gt 1 || \
    "$release_role" != "production" && \
    "$release_role" != "unsigned-validation" && \
    "$release_role" != "tool-bootstrap" ]]; then
    echo "error: release environment role must be production, unsigned-validation, or tool-bootstrap" >&2
    return 1
  fi
  if [[ "$release_role" == "production" && -n "$validation_python_input" ]]; then
    echo "error: release tooling refuses an unsigned-validation Python selection for this role" >&2
    return 1
  fi
  if [[ "$release_role" == "unsigned-validation" && \
    "$validation_python_input" != /* ]]; then
    echo "error: unsigned validation requires one absolute Python executable" >&2
    return 1
  fi
  if [[ "$release_role" == "tool-bootstrap" && \
    -n "$validation_python_input" && "$validation_python_input" != /* ]]; then
    echo "error: tool bootstrap Python selection must be absolute" >&2
    return 1
  fi
  if [[ "$release_role" == "unsigned-validation" || \
    "$release_role" == "tool-bootstrap" && -n "$validation_python_input" ]]; then
    use_validation_python=1
  fi
  if [[ ! "${RUST_VERSION:-}" =~ ^[1-9][0-9]*\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: the pinned Rust version must be loaded before sealing the release environment" >&2
    return 1
  fi
  if [[ ! "${PYTHON_VERSION:-}" =~ ^3\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: the pinned Python version must be loaded before sealing the release environment" >&2
    return 1
  fi
  if [[ -n "${POSIXLY_CORRECT:-}" || -n "${BASH_COMPAT:-}" ]]; then
    echo "error: alternate Bash compatibility modes are forbidden for release tooling" >&2
    return 1
  fi

  # Clear loader and shell-startup injection before invoking even fixed-path
  # account-discovery commands. The complete environment is closed below.
  unset \
    BASH_ENV CDPATH DYLD_FRAMEWORK_PATH DYLD_FALLBACK_FRAMEWORK_PATH \
    DYLD_FALLBACK_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH ENV \
    GLOBIGNORE LD_PRELOAD RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER \
    RUSTFLAGS RUSTUP_HOME RUSTUP_TOOLCHAIN SDKROOT SWIFT_EXEC \
    PYTHONHOME PYTHONINSPECT PYTHONPATH PYTHONSAFEPATH PYTHONSTARTUP \
    PYTHONUSERBASE PYTHONWARNINGS \
    SWIFT_DRIVER_CLANG_EXEC SWIFT_DRIVER_SWIFT_EXEC \
    SWIFT_DRIVER_SWIFT_FRONTEND_EXEC SWIFT_DRIVER_TOOLCHAIN_PATH \
    SWIFT_DRIVER_USE_FRONTEND_PATH TOOLCHAINS XCODE_XCCONFIG_FILE

  local effective_uid release_home account_home_line
  effective_uid="$(/usr/bin/id -u)" || {
    echo "error: cannot resolve the effective release account" >&2
    return 1
  }
  account_home_line="$({
    /usr/bin/dscacheutil -q user -a uid "$effective_uid" || exit 1
  } | /usr/bin/awk '
    $1 == "dir:" {
      count += 1
      $1 = ""
      sub(/^ /, "")
      home = $0
    }
    END {
      if (count != 1 || home !~ /^\//) exit 1
      print home
    }
  ')" || {
    echo "error: cannot resolve the release account home directory" >&2
    return 1
  }
  release_home="$(cd "$account_home_line" && /bin/pwd -P)" || {
    echo "error: cannot resolve the release account home directory" >&2
    return 1
  }
  if [[ "$(/usr/bin/stat -f '%u' "$release_home")" != "$effective_uid" ]]; then
    echo "error: the release account home directory has the wrong owner" >&2
    return 1
  fi

  local rust_toolchain_root rust_bin policy_tool_root cargo_aux_bin
  local python_series python_root
  local python_bin_dir python_bin python_executable python_runtime python_stdlib
  local release_repository tool_path
  local cargo_input_identity cargo_input_root cargo_vendor_root
  local cargo_lock_sha256 cargo_vendor_sha256 unexpected_cargo_input
  local validation_python_dir validation_python_launcher validation_python_executable
  policy_tool_root="$release_home/.cfm-release-tooling/policy-$CARGO_AUDIT_VERSION-$CARGO_DENY_VERSION"
  cargo_aux_bin="$policy_tool_root/bin"
  python_series="${PYTHON_VERSION%.*}"
  if [[ $use_validation_python -eq 0 ]]; then
    python_root="/opt/homebrew/Cellar/python@$python_series/$PYTHON_VERSION/Frameworks/Python.framework/Versions/$python_series"
    python_bin_dir="$python_root/bin"
    validation_python_launcher=""
  else
    validation_python_dir="$(cd "$(/usr/bin/dirname "$validation_python_input")" && /bin/pwd -P)" || {
      echo "error: cannot resolve the unsigned-validation Python directory" >&2
      return 1
    }
    validation_python_launcher="$validation_python_dir/$(/usr/bin/basename "$validation_python_input")"
    [[ -x "$validation_python_launcher" ]] || {
      echo "error: unsigned-validation Python executable is unavailable" >&2
      return 1
    }
    python_root="$(cd "$validation_python_dir/.." && /bin/pwd -P)" || {
      echo "error: cannot resolve the unsigned-validation Python root" >&2
      return 1
    }
    python_bin_dir="$validation_python_dir"
    validation_python_input="$validation_python_launcher"
  fi
  python_bin="$python_bin_dir/python3"
  if [[ ! -L "$python_bin" || ! -x "$python_bin" ]]; then
    echo "error: the pinned Python launcher is unavailable or is not a symlink" >&2
    return 1
  fi
  python_executable="$("$python_bin" -I -S -B -c \
    'import os, sys; print(os.path.realpath(sys.executable))')" || {
    echo "error: cannot resolve the pinned Python executable" >&2
    return 1
  }
  python_runtime="$("$python_bin" -I -S -B -c \
    'import os, sys; print(os.path.realpath(os.path.join(sys.base_prefix, "Python")))')" || {
    echo "error: cannot resolve the pinned Python runtime" >&2
    return 1
  }
  python_stdlib="$("$python_bin" -I -S -B -c \
    'import os, sysconfig; print(os.path.realpath(sysconfig.get_path("stdlib")))')" || {
    echo "error: cannot resolve the pinned Python standard library" >&2
    return 1
  }
  if [[ "$python_stdlib" != "$python_root/lib/python$python_series" || \
    ! -d "$python_stdlib" || -L "$python_stdlib" ]]; then
    echo "error: the pinned Python standard library escaped its runtime root" >&2
    return 1
  fi
  if [[ $use_validation_python -eq 0 && \
    "$python_executable" != "$python_root/bin/python$python_series" ]]; then
    echo "error: the production Python launcher escaped its fixed Cellar root" >&2
    return 1
  fi
  if [[ $use_validation_python -ne 0 ]]; then
    validation_python_executable="$("$validation_python_launcher" -I -S -B -c \
      'import os, sys; print(os.path.realpath(sys.executable))')" || {
      echo "error: cannot resolve the unsigned-validation Python executable" >&2
      return 1
    }
    if [[ "$validation_python_executable" != "$python_executable" ]]; then
      echo "error: unsigned-validation Python selectors resolve to different runtimes" >&2
      return 1
    fi
  fi
  release_repository="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)" || {
    echo "error: cannot resolve the release repository from the environment contract" >&2
    return 1
  }
  rust_toolchain_root="$(
    "$python_bin" -I -S -B -W error \
      "$release_repository/scripts/release_rust_toolchain.py" verify-selected \
      --repository "$release_repository" \
      --release-home "$release_home" \
      --selection "$rust_toolchain_selection"
  )" || return 1
  if [[ "$rust_toolchain_root" != /* || \
    "$rust_toolchain_root" == *$'\n'* || "$rust_toolchain_root" == *$'\r'* ]]; then
    echo "error: verified Rust toolchain root output is malformed" >&2
    return 1
  fi
  rust_bin="$rust_toolchain_root/bin"
  for tool_path in \
    "$rust_bin/rustc" \
    "$rust_bin/cargo" \
    "$python_executable" \
    "$python_runtime"; do
    if [[ ! -f "$tool_path" || -L "$tool_path" || ! -x "$tool_path" || \
      "$(/usr/bin/stat -f '%l' "$tool_path")" != "1" ]]; then
      echo "error: trusted release tool is unavailable or unsafe: $tool_path" >&2
      return 1
    fi
  done
  if [[ "$release_role" != "tool-bootstrap" ]]; then
    local private_directory
    for private_directory in \
      "$release_home/.cfm-release-tooling" \
      "$policy_tool_root" \
      "$cargo_aux_bin"; do
      if [[ ! -d "$private_directory" || -L "$private_directory" || \
        "$(/usr/bin/stat -f '%u' "$private_directory")" != "$effective_uid" || \
        "$(/usr/bin/stat -f '%Lp' "$private_directory")" != "700" || \
        "$(cd "$private_directory" && /bin/pwd -P)" != "$private_directory" ]]; then
        echo "error: release policy-tool directory is unavailable or unsafe: $private_directory" >&2
        return 1
      fi
    done
    for tool_path in \
      "$cargo_aux_bin/cargo-audit" \
      "$cargo_aux_bin/cargo-deny"; do
      if [[ ! -f "$tool_path" || -L "$tool_path" || ! -x "$tool_path" || \
        "$(/usr/bin/stat -f '%l' "$tool_path")" != "1" || \
        "$(/usr/bin/stat -f '%u' "$tool_path")" != "$effective_uid" || \
        "$(/usr/bin/stat -f '%Lp' "$tool_path")" != "700" ]]; then
        echo "error: trusted release tool is unavailable or unsafe: $tool_path" >&2
        return 1
      fi
    done
  fi
  if [[ "$release_role" == "tool-bootstrap" ]]; then
    CFW_RELEASE_PYTHON_EXECUTABLE="$python_executable" \
      cfw_run_release_python_script \
      "$release_repository" "$release_repository/scripts/release_cargo_inputs.py" \
      reject-ambient \
      --repository "$release_repository" \
      --release-home "$release_home" || return 1
  else
    cargo_input_identity="$(
      CFW_RELEASE_PYTHON_EXECUTABLE="$python_executable" \
        cfw_release_cargo_inputs_identity "$release_repository" "$release_home"
    )" ||
      return 1
    IFS=$'\t' read -r \
      cargo_input_root cargo_vendor_root cargo_lock_sha256 cargo_vendor_sha256 \
      unexpected_cargo_input <<<"$cargo_input_identity"
    if [[ "$cargo_input_root" != /* || "$cargo_vendor_root" != /* || \
      ! "$cargo_lock_sha256" =~ ^[0-9a-f]{64}$ || \
      ! "$cargo_vendor_sha256" =~ ^[0-9a-f]{64}$ || \
      -n "${unexpected_cargo_input:-}" ]]; then
      echo "error: verified Cargo workspace input identity is malformed" >&2
      return 1
    fi
  fi
  local variable_name
  while IFS='=' read -r -d '' variable_name _; do
    case "$variable_name" in
      BASH_FUNC_*)
        echo "error: exported shell functions are forbidden in the release environment" >&2
        return 1
        ;;
      DEVELOPER_DIR | CFW_BUILD_NUMBER | CFW_GO_MODULE_CACHE_TREE_SHA256 | \
        CFW_GO_TOOLCHAIN_TREE_SHA256 | CFW_GO_TOOLS_TREE_SHA256 | \
        CFW_NATIVE_DERIVED_DATA | CFW_NATIVE_PRODUCTS_OUTPUT | \
        CFW_RELEASE_CARGO_AUDIT_EXECUTABLE | \
        CFW_RELEASE_CARGO_DENY_EXECUTABLE | CFW_RELEASE_CARGO_EXECUTABLE | \
        CFW_RELEASE_CARGO_INPUT_ROOT | CFW_RELEASE_CARGO_LOCK_SHA256 | \
        CFW_RELEASE_CARGO_VENDOR_ROOT | CFW_RELEASE_CARGO_VENDOR_SHA256 | \
        CFW_RELEASE_POLICY_TOOL_ROOT | \
        CFW_RELEASE_PYTHON_EXECUTABLE | CFW_RELEASE_PYTHON_RUNTIME | \
        CFW_RELEASE_PYTHON_STDLIB | \
        CFW_RELEASE_RUSTC_EXECUTABLE | CFW_RELEASE_RUST_TOOLCHAIN | \
        CFW_RELEASE_SOURCE_SHA256 | CFW_REPOSITORY_COMMIT | CFW_TOOLCHAIN_ROOT | \
        CFW_UNSIGNED_VALIDATION_PYTHON | \
        HOST_PROVISIONING_PROFILE_PATH | MACOS_SIGN_IDENTITY | NOTARY_PROFILE | \
        PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER | \
        PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER)
        ;;
      *) export -n "${variable_name?}" ;;
    esac
  done < <(/usr/bin/env -0)

  unset \
    AR BASH_ENV BASH_COMPAT CARGO CARGO_BUILD_RUSTC \
    CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER \
    CARGO_BUILD_RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_HOME \
    CARGO_NET_OFFLINE CARGO_TARGET_DIR CC CDPATH CFLAGS \
    CMAKE_PREFIX_PATH CONFIG_SHELL CPATH CPPFLAGS CPLUS_INCLUDE_PATH CXX \
    DYLD_FRAMEWORK_PATH DYLD_FALLBACK_FRAMEWORK_PATH \
    DYLD_FALLBACK_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
    ENV GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_DIR \
    GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_WORK_TREE GLOBIGNORE GOENV \
    GOFLAGS GOMODCACHE GONOPROXY GONOSUMDB GOPATH GOPRIVATE GOPROXY \
    GOROOT GOTOOLCHAIN GOWORK LD LDFLAGS LD_PRELOAD LIBRARY_PATH \
    MACOSX_DEPLOYMENT_TARGET MAKEFLAGS MFLAGS NODE_OPTIONS NODE_PATH \
    NPM_CONFIG_USERCONFIG OBJC_INCLUDE_PATH PKG_CONFIG_PATH \
    POSIXLY_CORRECT PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE \
    RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS RUSTUP_HOME \
    RUSTDOC RUSTDOCFLAGS RUSTUP_TOOLCHAIN SDKROOT SWIFT_EXEC \
    SWIFT_DRIVER_CLANG_EXEC SWIFT_DRIVER_SWIFT_EXEC \
    SWIFT_DRIVER_SWIFT_FRONTEND_EXEC SWIFT_DRIVER_TOOLCHAIN_PATH \
    SWIFT_DRIVER_USE_FRONTEND_PATH TOOLCHAINS XCODE_XCCONFIG_FILE

  unset CFW_RELEASE_CARGO_AUDIT_EXECUTABLE \
    CFW_RELEASE_CARGO_DENY_EXECUTABLE CFW_RELEASE_CARGO_EXECUTABLE \
    CFW_RELEASE_CARGO_INPUT_ROOT CFW_RELEASE_CARGO_LOCK_SHA256 \
    CFW_RELEASE_CARGO_VENDOR_ROOT CFW_RELEASE_CARGO_VENDOR_SHA256 \
    CFW_RELEASE_POLICY_TOOL_ROOT \
    CFW_RELEASE_PYTHON_EXECUTABLE CFW_RELEASE_PYTHON_RUNTIME \
    CFW_RELEASE_PYTHON_STDLIB CFW_RELEASE_RUSTC_EXECUTABLE
  if [[ $use_validation_python -eq 0 ]]; then
    unset CFW_UNSIGNED_VALIDATION_PYTHON
  else
    export CFW_UNSIGNED_VALIDATION_PYTHON="$validation_python_input"
  fi

  if [[ -n "${CFW_TOOLCHAIN_ROOT:-}" && "$CFW_TOOLCHAIN_ROOT" != /* ]]; then
    echo "error: CFW_TOOLCHAIN_ROOT must be absolute when explicitly selected" >&2
    return 1
  fi
  export HOME="$release_home"
  export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$rust_bin:$cargo_aux_bin"
  export CFW_RELEASE_RUST_TOOLCHAIN="$rust_toolchain_selection"
  export CFW_RELEASE_RUSTC_EXECUTABLE="$rust_bin/rustc"
  export CFW_RELEASE_CARGO_EXECUTABLE="$rust_bin/cargo"
  export CFW_RELEASE_POLICY_TOOL_ROOT="$policy_tool_root"
  if [[ "$release_role" != "tool-bootstrap" ]]; then
    export CFW_RELEASE_CARGO_AUDIT_EXECUTABLE="$cargo_aux_bin/cargo-audit"
    export CFW_RELEASE_CARGO_DENY_EXECUTABLE="$cargo_aux_bin/cargo-deny"
    export CFW_RELEASE_CARGO_INPUT_ROOT="$cargo_input_root"
    export CFW_RELEASE_CARGO_LOCK_SHA256="$cargo_lock_sha256"
    export CFW_RELEASE_CARGO_VENDOR_ROOT="$cargo_vendor_root"
    export CFW_RELEASE_CARGO_VENDOR_SHA256="$cargo_vendor_sha256"
  fi
  export CFW_RELEASE_PYTHON_EXECUTABLE="$python_executable"
  export CFW_RELEASE_PYTHON_RUNTIME="$python_runtime"
  export CFW_RELEASE_PYTHON_STDLIB="$python_stdlib"
  export PYTHONDONTWRITEBYTECODE=1
  export LANG=C
  export LC_ALL=C
  local resolved_command expected_command
  for resolved_command in git bash zsh shasum awk mkdir stat tar ln rustc cargo; do
    case "$resolved_command" in
      git) expected_command="/usr/bin/git" ;;
      bash) expected_command="/bin/bash" ;;
      zsh) expected_command="/bin/zsh" ;;
      shasum) expected_command="/usr/bin/shasum" ;;
      awk) expected_command="/usr/bin/awk" ;;
      mkdir) expected_command="/bin/mkdir" ;;
      stat) expected_command="/usr/bin/stat" ;;
      tar) expected_command="/usr/bin/tar" ;;
      ln) expected_command="/bin/ln" ;;
      rustc) expected_command="$rust_bin/rustc" ;;
      cargo) expected_command="$rust_bin/cargo" ;;
    esac
    if [[ "$(command -v "$resolved_command")" != "$expected_command" ]]; then
      echo "error: release command resolution is shadowed: $resolved_command" >&2
      return 1
    fi
  done
  if [[ "$release_role" != "tool-bootstrap" ]]; then
    for resolved_command in cargo-audit cargo-deny; do
      expected_command="$cargo_aux_bin/$resolved_command"
      if [[ "$(command -v "$resolved_command")" != "$expected_command" ]]; then
        echo "error: release command resolution is shadowed: $resolved_command" >&2
        return 1
      fi
    done
  fi
  if [[ "$("$rust_bin/rustc" --version | /usr/bin/awk '{print $2}')" != "$RUST_VERSION" || \
    "$("$rust_bin/cargo" --version | /usr/bin/awk '{print $2}')" != "$RUST_VERSION" ]]; then
    echo "error: the fixed Rust compiler and Cargo do not match the release pin" >&2
    return 1
  fi
  if [[ "$("$python_bin" --version 2>&1)" != "Python $PYTHON_VERSION" ]]; then
    echo "error: the fixed Python interpreter does not match the release pin" >&2
    return 1
  fi
}

cfw_select_release_apple_toolchain() {
  local requested_developer_dir selected_developer_dir
  local xcode_identity swift_bin xcodebuild_bin
  requested_developer_dir="${DEVELOPER_DIR:-}"
  if [[ -z "$requested_developer_dir" ]]; then
    requested_developer_dir="$(/usr/bin/xcode-select -p)" || {
      echo "error: cannot query the selected Xcode Developer directory" >&2
      return 1
    }
  fi
  if [[ "$requested_developer_dir" != /* || ! -d "$requested_developer_dir" ]]; then
    echo "error: selected Xcode Developer directory must be an absolute directory" >&2
    return 1
  fi
  selected_developer_dir="$(cd "$requested_developer_dir" && pwd -P)" || {
    echo "error: cannot resolve the selected Xcode Developer directory" >&2
    return 1
  }
  if [[ "$selected_developer_dir" != */Contents/Developer ]]; then
    echo "error: selected Xcode Developer directory is not an Xcode Developer tree" >&2
    return 1
  fi

  xcode_identity="$(DEVELOPER_DIR="$selected_developer_dir" \
    /usr/bin/xcodebuild -version)" || {
    echo "error: cannot query Xcode identity" >&2
    return 1
  }
  if [[ "$xcode_identity" != \
    "Xcode $XCODE_VERSION"$'\n'"Build version $XCODE_BUILD_VERSION" ]]; then
    echo "error: Xcode $XCODE_VERSION ($XCODE_BUILD_VERSION) is required" >&2
    return 1
  fi

  swift_bin="$(DEVELOPER_DIR="$selected_developer_dir" \
    /usr/bin/xcrun --find swift)" || {
    echo "error: cannot resolve Swift from the selected Xcode" >&2
    return 1
  }
  xcodebuild_bin="$(DEVELOPER_DIR="$selected_developer_dir" \
    /usr/bin/xcrun --find xcodebuild)" || {
    echo "error: cannot resolve xcodebuild from the selected Xcode" >&2
    return 1
  }
  case "$swift_bin" in
    "$selected_developer_dir"/*) ;;
    *)
      echo "error: selected Swift executable escaped the Xcode Developer tree" >&2
      return 1
      ;;
  esac
  case "$xcodebuild_bin" in
    "$selected_developer_dir"/*) ;;
    *)
      echo "error: selected xcodebuild executable escaped the Xcode Developer tree" >&2
      return 1
      ;;
  esac
  if [[ ! -x "$swift_bin" || ! -x "$xcodebuild_bin" ]]; then
    echo "error: selected Apple build tools are not executable" >&2
    return 1
  fi

  export DEVELOPER_DIR="$selected_developer_dir"
}
