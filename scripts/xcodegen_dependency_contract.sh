#!/usr/bin/env bash
# Apply the source-pinned AEXML manifest update only in an isolated checkout.
# dependency_pins.env must be sourced by the caller.

cfw_patch_xcodegen_aexml() {
  local repository="$1" checkouts="$2"
  local checkout="$checkouts/AEXML"
  local manifest="$checkout/Package.swift"
  local patch_file="$repository/$XCODEGEN_AEXML_PATCH_PATH"
  [[ -d "$checkouts" && ! -L "$checkouts" &&
    -d "$checkout" && ! -L "$checkout" &&
    -f "$manifest" && ! -L "$manifest" &&
    -f "$patch_file" && ! -L "$patch_file" ]] || {
    echo "error: isolated AEXML source or pinned manifest patch is unavailable" >&2
    return 1
  }
  [[ "$(/usr/bin/git -C "$checkout" rev-parse HEAD)" == "$XCODEGEN_AEXML_COMMIT" &&
    -z "$(/usr/bin/git -C "$checkout" status --porcelain --untracked-files=all)" ]] || {
    echo "error: AEXML checkout is not the pristine locked revision" >&2
    return 1
  }
  printf '%s  %s\n' \
    "$XCODEGEN_AEXML_UPSTREAM_MANIFEST_SHA256" "$manifest" \
    "$XCODEGEN_AEXML_PATCH_SHA256" "$patch_file" |
    /usr/bin/shasum -a 256 --check >/dev/null || return 1
  /usr/bin/git -C "$checkout" apply --check "$patch_file" || return 1
  /usr/bin/git -C "$checkout" apply "$patch_file" || return 1
  /usr/bin/git -C "$checkout" apply --reverse --check "$patch_file" || return 1
  printf '%s  %s\n' "$XCODEGEN_AEXML_PATCHED_MANIFEST_SHA256" "$manifest" |
    /usr/bin/shasum -a 256 --check >/dev/null || return 1
}
