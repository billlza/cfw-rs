#!/usr/bin/env bash
# Checks of the isolated XcodeGen build's SwiftPM phases.
# dependency_pins.env must be sourced by the caller.

# The AEXML checkout SwiftPM resolved must be the pinned revision, unmodified,
# with the reviewed upstream manifest. AEXML 4.7.1's own manifest declares
# supported platforms, so no checkout is edited and SwiftPM never evaluates a
# manifest that would need a local patch. This only reads the checkout.
cfw_verify_xcodegen_aexml() {
  local checkouts="$1"
  local checkout="$checkouts/AEXML"
  local manifest="$checkout/Package.swift"
  [[ -d "$checkouts" && ! -L "$checkouts" &&
    -d "$checkout" && ! -L "$checkout" &&
    -f "$manifest" && ! -L "$manifest" ]] || {
    echo "error: isolated AEXML checkout or its manifest is unavailable" >&2
    return 1
  }
  [[ "$(/usr/bin/git -C "$checkout" rev-parse HEAD)" == "$XCODEGEN_AEXML_COMMIT" &&
    -z "$(/usr/bin/git -C "$checkout" status --porcelain --untracked-files=all)" ]] || {
    echo "error: AEXML checkout is not the pristine locked revision" >&2
    return 1
  }
  printf '%s  %s\n' "$XCODEGEN_AEXML_UPSTREAM_MANIFEST_SHA256" "$manifest" |
    /usr/bin/shasum -a 256 --check >/dev/null || {
    echo "error: AEXML manifest is not the reviewed upstream manifest" >&2
    return 1
  }
}

# Fails when the SwiftPM log of a phase (dependency resolution, build) holds a
# warning, or cannot be read: warnings fail the bootstrap in every phase.
cfw_reject_swiftpm_warnings() {
  local log="$1" phase="$2" status=0
  [[ -f "$log" && ! -L "$log" ]] || {
    echo "error: isolated XcodeGen $phase log is unavailable" >&2
    return 1
  }
  /usr/bin/grep -Eiq '(^|[[:space:]])warning([[:space:]]|:)' "$log" || status=$?
  case "$status" in
    0)
      echo "error: isolated XcodeGen $phase emitted a warning" >&2
      return 1
      ;;
    1) ;;
    *)
      echo "error: isolated XcodeGen $phase log could not be read" >&2
      return 1
      ;;
  esac
}
