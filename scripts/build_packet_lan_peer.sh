#!/usr/bin/env bash
# Reproducibly build the fixed Linux/arm64 peer used by the physical LAN test.
set -euo pipefail

if [[ $# -ne 0 ]]; then
  echo "error: usage: scripts/build_packet_lan_peer.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/release_toolchain_contract.sh
source "$repo_root/scripts/release_toolchain_contract.sh"

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "error: the packet LAN peer build requires arm64 macOS" >&2
  exit 1
fi

toolchain_root="$repo_root/target/toolchains"
go_root="$toolchain_root/go-$GO_VERSION"
go_bin="$go_root/bin/go"
source_root="$repo_root/tools/packet-lan-peer"
artifact="$repo_root/target/packet-lan-peer-linux-arm64"
cache_parent="$repo_root/target/release-build-cache"

if [[ ! -x "$go_bin" || -L "$go_bin" ]]; then
  echo "error: the pinned Go executable is unavailable" >&2
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
source_entry_count=0
while IFS= read -r entry; do
  source_entry_count=$((source_entry_count + 1))
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
if [[ "$source_entry_count" -ne 4 ]]; then
  echo "error: packet LAN peer source file set is incomplete" >&2
  exit 1
fi
for required in README.md go.mod main.go main_test.go; do
  if [[ ! -f "$source_root/$required" || -L "$source_root/$required" ]]; then
    echo "error: packet LAN peer source file is missing or unsafe: $required" >&2
    exit 1
  fi
done
if [[ -e "$artifact" || -L "$artifact" ]]; then
  if [[ ! -f "$artifact" || -L "$artifact" ]]; then
    echo "error: refusing to replace a non-regular packet LAN peer artifact" >&2
    exit 1
  fi
fi

mkdir -p "$cache_parent"
workspace="$(mktemp -d "$cache_parent/packet-lan-peer.XXXXXX")"
artifact_staging="$workspace/packet-lan-peer-linux-arm64.publish"
cleanup() {
  /bin/rm -rf -- "$workspace"
  /bin/rm -f -- "$artifact_staging"
}
trap cleanup EXIT

build_once() {
  local name="$1"
  local build_source="$2"
  local output="$3"
  local home="$workspace/$name-home"
  local temporary="$workspace/$name-tmp"
  local build_cache="$workspace/$name-build-cache"
  local module_cache="$workspace/$name-module-cache"
  local go_path="$workspace/$name-gopath"
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
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=arm64 \
    "$go_bin" \
      -C "$build_source" \
      build \
      -buildvcs=false \
      -trimpath \
      -ldflags='-s -w -buildid=' \
      -o "$output" \
      .
}

first_source="$workspace/first-source"
second_source="$workspace/second-source"
mkdir -p "$first_source" "$second_source"
COPYFILE_DISABLE=1 /bin/cp -R "$source_root/." "$first_source/"
COPYFILE_DISABLE=1 /bin/cp -R "$source_root/." "$second_source/"
first="$workspace/packet-lan-peer-linux-arm64.first"
second="$workspace/packet-lan-peer-linux-arm64.second"
build_once first "$first_source" "$first"
build_once second "$second_source" "$second"
if ! /usr/bin/cmp -s "$first" "$second"; then
  echo "error: isolated packet LAN peer builds are not byte-identical" >&2
  exit 1
fi
if [[ ! -s "$first" || -L "$first" ]]; then
  echo "error: packet LAN peer build did not produce a regular non-empty artifact" >&2
  exit 1
fi

/bin/cp "$first" "$artifact_staging"
/bin/chmod 0555 "$artifact_staging"
/bin/mv -fh "$artifact_staging" "$artifact"
if [[ ! -f "$artifact" || -L "$artifact" || "$(/usr/bin/stat -f '%Lp' "$artifact")" != 555 ]]; then
  echo "error: packet LAN peer artifact publication did not preserve a regular 0555 file" >&2
  exit 1
fi
artifact_sha256="$(/usr/bin/shasum -a 256 "$artifact" | /usr/bin/awk '{print $1}')"
printf 'packet LAN peer: %s\nsha256: %s\n' "$artifact" "$artifact_sha256"
