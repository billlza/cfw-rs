#!/bin/bash -p
# Source from the sealed CI dispatcher. Swift preparation is explicit and
# finishes before Cargo; each check receives one new repository-owned target.
cfw_run_native_ui_development_check() (
  set -euo pipefail
  if [[ $# -ne 2 || "$1" != /* || ( "$2" != clippy && "$2" != test ) ]]; then
    echo "error: native UI development check requires REPOSITORY clippy|test" >&2
    return 2
  fi
  local repository="$1"
  local operation="$2"
  local parent target products
  [[ -d "$repository" && ! -L "$repository" && "$(cd "$repository" && /bin/pwd -P)" == "$repository" ]] || {
    echo "error: native UI check repository must be canonical" >&2
    return 1
  }
  for parent in "$repository/target" "$repository/target/development"; do
    [[ ! -L "$parent" ]] || { echo "error: development target parent is a symlink" >&2; return 1; }
    /bin/mkdir -p "$parent"
    [[ "$(cd "$parent" && /bin/pwd -P)" == "$parent" ]] || return 1
  done
  target="$(/usr/bin/mktemp -d "$repository/target/development/ci-${operation}_XXXXXXXX")"
  # The producer accepts canonical alphanumeric/hyphen/underscore target names.
  # mktemp's separator is an underscore to remain inside that exact contract.
  # No caller-provided existing target or native artifact can replace this one.
  products="$(cfw_run_release_python_script "$repository" \
    "$repository/scripts/prepare_development_native_ui.py" --cargo-target-dir "$target")"
  printf '%s\n' "$products" > "$target/native-ui-products.txt"
  export CARGO_TARGET_DIR="$target"
  export CFW_DEVELOPMENT_NATIVE_UI_PRODUCTS="$products"
  if [[ "$operation" == clippy ]]; then
    cfw_run_with_release_cargo_runtime "$repository" "$CFW_RELEASE_CARGO_EXECUTABLE" clippy \
      --locked --workspace --all-targets --all-features -- -D warnings
  else
    cfw_run_with_release_cargo_runtime "$repository" "$CFW_RELEASE_CARGO_EXECUTABLE" test \
      --locked --workspace --all-targets --all-features
  fi
)
