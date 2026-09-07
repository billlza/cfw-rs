#!/usr/bin/env bash
# Fail closed unless the Android LAN peer source, tests, and artifact retain the
# fixed minimal contract.
set -euo pipefail

if [[ $# -ne 0 ]]; then
  echo "error: usage: scripts/verify_packet_lan_peer.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "error: packet LAN peer verification requires arm64 macOS" >&2
  exit 1
fi

toolchain_root="$repo_root/target/toolchains"
go_root="$toolchain_root/go-$GO_VERSION"
go_bin="$go_root/bin/go"
gofmt_bin="$go_root/bin/gofmt"
source_root="$repo_root/tools/packet-lan-peer"
artifact="$repo_root/target/packet-lan-peer-linux-arm64"
expected_artifact_sha256=268699e59caff2ea3ddf73e2a22b556364724a6bae985d012f1df7e2b089085c
expected_artifact_size=2359422
expected_artifact_mode=555
cache_parent="$repo_root/target/release-build-cache"
module_path=github.com/billziss-gh/cfw-rs/tools/packet-lan-peer

if [[ ! -x "$go_bin" || -L "$go_bin" || ! -x "$gofmt_bin" || -L "$gofmt_bin" ]]; then
  echo "error: the pinned Go tools are unavailable" >&2
  exit 1
fi
cfw_verify_go_toolchain_tree "$repo_root" "$toolchain_root" >/dev/null
if [[ "$("$go_bin" version)" != "go version go$GO_VERSION darwin/arm64" ]]; then
  echo "error: pinned Go toolchain identity mismatch" >&2
  exit 1
fi
if [[ ! -d "$source_root" || -L "$source_root" ]]; then
  echo "error: packet LAN peer source root is unavailable or unsafe" >&2
  exit 1
fi

entry_count=0
while IFS= read -r entry; do
  entry_count=$((entry_count + 1))
  if [[ ! -f "$entry" || -L "$entry" ]]; then
    echo "error: packet LAN peer source contains a non-regular entry: $entry" >&2
    exit 1
  fi
  case "$(basename "$entry")" in
    README.md | go.mod | main.go | main_test.go) ;;
    *)
      echo "error: packet LAN peer source contains an unreviewed file: $entry" >&2
      exit 1
      ;;
  esac
done < <(/usr/bin/find "$source_root" -mindepth 1 -maxdepth 1 -print)
if [[ "$entry_count" -ne 4 ]]; then
  echo "error: packet LAN peer source file set is incomplete" >&2
  exit 1
fi
for required in README.md go.mod main.go main_test.go; do
  if [[ ! -f "$source_root/$required" || -L "$source_root/$required" ]]; then
    echo "error: packet LAN peer source file is missing or unsafe: $required" >&2
    exit 1
  fi
done

format_diff="$("$gofmt_bin" -d "$source_root/main.go" "$source_root/main_test.go")"
if [[ -n "$format_diff" ]]; then
  echo "error: packet LAN peer Go source is not gofmt-clean" >&2
  printf '%s\n' "$format_diff" >&2
  exit 1
fi
if /usr/bin/grep -En \
  'os\.(Args|Environ|ExpandEnv|Getenv|LookupEnv)|flag\.|exec\.(Command|CommandContext)|net\.(ListenPacket|ListenUDP)|syscall\.(Exec|ForkExec)|os\.(Open|OpenFile|ReadFile)' \
  "$source_root/main.go"; then
  echo "error: packet LAN peer exposes forbidden runtime configuration, file, UDP, or execution behavior" >&2
  exit 1
fi

mkdir -p "$cache_parent"
workspace="$(mktemp -d "$cache_parent/packet-lan-peer-verify.XXXXXX")"
cleanup() {
  /bin/rm -rf -- "$workspace"
}
trap cleanup EXIT

run_go() {
  local lane="$1"
  shift
  local home="$workspace/$lane-home"
  local temporary="$workspace/$lane-tmp"
  local build_cache="$workspace/$lane-build-cache"
  local module_cache="$workspace/$lane-module-cache"
  local go_path="$workspace/$lane-gopath"
  mkdir -p "$home" "$temporary" "$build_cache" "$module_cache" "$go_path"
  /usr/bin/env -i \
    HOME="$home" \
    TMPDIR="$temporary" \
    LANG=C \
    LC_ALL=C \
    PATH="$go_root/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    GOENV=off \
    GOFLAGS=-mod=readonly \
    GOCACHE="$build_cache" \
    GOMODCACHE="$module_cache" \
    GOPATH="$go_path" \
    GOPROXY=off \
    GOSUMDB=sum.golang.org \
    GOTELEMETRY=off \
    GOTOOLCHAIN=local \
    GOWORK=off \
    GOVCS='*:off' \
    "$@"
}

imports="$(
  run_go imports \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    "$go_bin" -C "$source_root" list -f '{{range .Imports}}{{println .}}{{end}}' . |
    LC_ALL=C /usr/bin/sort
)"
expected_imports="$(printf '%s\n' \
  context errors fmt io net os os/signal sync syscall time |
  LC_ALL=C /usr/bin/sort)"
if [[ "$imports" != "$expected_imports" ]]; then
  echo "error: packet LAN peer imports differ from the reviewed standard-library set" >&2
  exit 1
fi
nonstandard="$(
  run_go dependencies \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    "$go_bin" -C "$source_root" list -deps \
      -f '{{if and (not .Standard) (ne .ImportPath "'"$module_path"'")}}{{println .ImportPath}}{{end}}' \
      .
)"
if [[ -n "$nonstandard" ]]; then
  echo "error: packet LAN peer has non-standard-library dependencies" >&2
  printf '%s\n' "$nonstandard" >&2
  exit 1
fi
cgo_files="$(
  run_go cgo-check \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    "$go_bin" -C "$source_root" list -deps \
      -f '{{if .CgoFiles}}{{println .ImportPath .CgoFiles}}{{end}}' \
      .
)"
if [[ -n "$cgo_files" ]]; then
  echo "error: packet LAN peer target graph contains cgo files" >&2
  printf '%s\n' "$cgo_files" >&2
  exit 1
fi

run_go test \
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  "$go_bin" -C "$source_root" test -count=1 ./...
run_go vet \
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  "$go_bin" -C "$source_root" vet ./...
run_go race \
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC=/usr/bin/clang \
  "$go_bin" -C "$source_root" test -race -count=1 ./...

"$repo_root/scripts/build_packet_lan_peer.sh"
if [[ ! -f "$artifact" || -L "$artifact" || ! -x "$artifact" ]]; then
  echo "error: packet LAN peer artifact is missing, unsafe, or not executable" >&2
  exit 1
fi
artifact_mode="$(/usr/bin/stat -f '%Lp' "$artifact")"
artifact_size="$(/usr/bin/stat -f '%z' "$artifact")"
artifact_sha256="$(/usr/bin/shasum -a 256 "$artifact" | /usr/bin/awk '{print $1}')"
if [[ "$artifact_mode" != "$expected_artifact_mode" ]]; then
  echo "error: packet LAN peer artifact mode is not 0555" >&2
  exit 1
fi
if [[ "$artifact_size" != "$expected_artifact_size" ]]; then
  echo "error: packet LAN peer artifact size differs from the pin" >&2
  exit 1
fi
if [[ "$artifact_sha256" != "$expected_artifact_sha256" ]]; then
  echo "error: packet LAN peer artifact SHA-256 differs from the pin" >&2
  exit 1
fi
build_metadata="$("$go_bin" version -m "$artifact")"
if [[ "${build_metadata%%$'\n'*}" != "$artifact: go$GO_VERSION" ]]; then
  echo "error: packet LAN peer artifact Go version differs from the pin" >&2
  exit 1
fi
for setting in \
  $'\tbuild\t-buildmode=exe' \
  $'\tbuild\t-trimpath=true' \
  $'\tbuild\tCGO_ENABLED=0' \
  $'\tbuild\tGOARCH=arm64' \
  $'\tbuild\tGOOS=linux' \
  $'\tbuild\tGOARM64=v8.0'; do
  if [[ "$build_metadata" != *"$setting"* ]]; then
    echo "error: packet LAN peer artifact is missing build setting: $setting" >&2
    exit 1
  fi
done
if [[ "$build_metadata" != *$'\tpath\t'"$module_path"* ]]; then
  echo "error: packet LAN peer artifact module path differs" >&2
  exit 1
fi
if [[ -n "$("$go_bin" tool buildid "$artifact")" ]]; then
  echo "error: packet LAN peer artifact retains a Go build ID" >&2
  exit 1
fi

printf 'packet LAN peer verification passed\nartifact sha256: %s\n' "$artifact_sha256"
