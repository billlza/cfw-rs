#!/usr/bin/env bash
# Create an isolated libbox source tree from the immutable upstream tag and the
# repository-owned, digest-pinned security, packet-flow, and DNS patches.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/dependency_pins.env
source "$repo_root/scripts/dependency_pins.env"
# shellcheck source=scripts/libbox_source_contract.sh
source "$repo_root/scripts/libbox_source_contract.sh"

source_input="${SING_BOX_SOURCE:-}"
if [[ -z "$source_input" ]]; then
  echo "error: set SING_BOX_SOURCE to the clean upstream sing-box checkout" >&2
  exit 1
fi
if [[ ! -d "$source_input" || -L "$source_input" ]]; then
  echo "error: SING_BOX_SOURCE must be a real directory, not a symlink" >&2
  exit 1
fi
source_root="$(cd "$source_input" && pwd -P)"
libbox_validate_upstream_source "$repo_root" "$source_root"
if [[ ! -d "$source_root/.git" || -L "$source_root/.git" ]]; then
  echo "error: upstream source must be a standalone checkout with a real .git directory" >&2
  exit 1
fi
actual_gitlinks="$(
  git -C "$source_root" ls-files --stage |
    awk '$1 == "160000" { print $2 " " $4 }'
)"
expected_gitlinks="$SING_BOX_ANDROID_REFERENCE_COMMIT clients/android
$SING_BOX_APPLE_REFERENCE_COMMIT clients/apple"
if [[ "$actual_gitlinks" != "$expected_gitlinks" ]]; then
  echo "error: sing-box reference gitlinks differ from the pinned commits" >&2
  exit 1
fi
for gitlink in clients/android clients/apple; do
  gitlink_path="$source_root/$gitlink"
  if [[ ! -d "$gitlink_path" || -L "$gitlink_path" ]] ||
    [[ -n "$(find "$gitlink_path" -mindepth 1 -print -quit)" ]]; then
    echo "error: reference gitlink must remain an uninitialized real directory: $gitlink" >&2
    exit 1
  fi
done

output_input="${LIBBOX_PATCHED_SOURCE_OUTPUT:-$repo_root/target/sources/sing-box-$SING_BOX_VERSION-patched}"
if [[ -e "$output_input" || -L "$output_input" ]]; then
  echo "error: refusing to replace existing patched source: $output_input" >&2
  exit 1
fi
output_parent="$(dirname "$output_input")"
output_name="$(basename "$output_input")"
if [[ "$output_name" == "." || "$output_name" == ".." || ! -d "$output_parent" || -L "$output_parent" ]]; then
  echo "error: patched source parent must be an existing real directory" >&2
  exit 1
fi
output_parent="$(cd "$output_parent" && pwd -P)"
output_root="$output_parent/$output_name"
if [[ "$output_root" == "$source_root" || "$output_root" == "$source_root/"* ]]; then
  echo "error: patched source must not be created inside the upstream checkout" >&2
  exit 1
fi

staging="$(mktemp -d "$output_parent/.libbox-source.XXXXXX")"
cleanup() {
  if [[ -n "${staging:-}" && -d "$staging" && "$staging" == "$output_parent/.libbox-source."* ]]; then
    /bin/rm -r "$staging"
  fi
}
trap cleanup EXIT

mkdir "$staging/checkout"
COPYFILE_DISABLE=1 /bin/cp -R "$source_root/.git" "$staging/checkout/.git"
(
  cd "$source_root"
  git ls-files -z | COPYFILE_DISABLE=1 tar --null -cf - -T -
) | (
  cd "$staging/checkout"
  COPYFILE_DISABLE=1 tar -xf -
)
security_patch_path="$(libbox_security_patch_path "$repo_root")"
raw_packet_patch_path="$(libbox_raw_packet_patch_path "$repo_root")"
dns_failover_patch_path="$(libbox_dns_failover_patch_path "$repo_root")"
git -C "$staging/checkout" apply --check \
  "$security_patch_path" \
  "$raw_packet_patch_path" \
  "$dns_failover_patch_path"
git -C "$staging/checkout" apply \
  "$security_patch_path" \
  "$raw_packet_patch_path" \
  "$dns_failover_patch_path"
libbox_validate_patched_source "$repo_root" "$staging/checkout"

/bin/mv "$staging/checkout" "$output_root"
rmdir "$staging"
staging=""
trap - EXIT

echo "patched libbox source: $output_root"
echo "upstream commit: $SING_BOX_COMMIT"
echo "security patch: $SING_BOX_SECURITY_PATCH_SHA256"
echo "raw packet patch: $SING_BOX_RAW_PACKET_PATCH_SHA256"
echo "DNS failover patch: $SING_BOX_DNS_FAILOVER_PATCH_SHA256"
