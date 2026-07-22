#!/usr/bin/env bash
# Scan exactly the macOS/arm64 libbox source graph with the pinned Go scanner.
# Module resolution stays offline; only the explicit official vulnerability DB
# is networked during this release-preparation gate.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/go_release_environment.sh
source "$repo_root/scripts/go_release_environment.sh"
# shellcheck source=scripts/libbox_source_contract.sh
source "$repo_root/scripts/libbox_source_contract.sh"

source_input="${SING_BOX_SOURCE:-}"
if [[ -z "$source_input" ]]; then
  echo "error: set SING_BOX_SOURCE to the materialized patched sing-box checkout" >&2
  exit 1
fi
if [[ ! -d "$source_input" || -L "$source_input" ]]; then
  echo "error: SING_BOX_SOURCE must be a real directory, not a symlink" >&2
  exit 1
fi
source_root="$(cd "$source_input" && pwd -P)"
toolchain_root="${CFW_TOOLCHAIN_ROOT:-$repo_root/target/toolchains}"
go_bin="$toolchain_root/go-$GO_VERSION/bin/go"
scanner="$toolchain_root/go-workspace/bin/govulncheck"

libbox_validate_patched_source "$repo_root" "$source_root"
if [[ "$($go_bin version)" != "go version go$GO_VERSION darwin/arm64" ]]; then
  echo "error: pinned Go toolchain identity mismatch" >&2
  exit 1
fi
if [[ ! -x "$scanner" ]]; then
  echo "error: missing pinned govulncheck; run scripts/bootstrap_release_toolchain.sh" >&2
  exit 1
fi
"$go_bin" version -m "$scanner" | awk \
  -v version="$GOVULNCHECK_VERSION" \
  -v module_sum="$GOVULNCHECK_MODULE_SUM" \
  '$1 == "mod" && $2 == "golang.org/x/vuln" && $3 == version && $4 == module_sum { found = 1 } END { exit !found }'

gopath="$toolchain_root/go-workspace"
export GOBIN="$gopath/bin"
export GOPATH="$gopath"
export GOMODCACHE="$gopath/pkg/mod"
export GOCACHE="$toolchain_root/go-build-cache"
export PATH="$toolchain_root/go-$GO_VERSION/bin:/usr/bin:/bin:/usr/sbin:/sbin"
configure_offline_go_environment

"$scanner" \
  -C "$source_root" \
  -db https://vuln.go.dev \
  -mode source \
  -scan symbol \
  -show verbose \
  -tags "$LIBBOX_BUILD_TAGS" \
  ./experimental/libbox
