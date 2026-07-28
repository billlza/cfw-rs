#!/usr/bin/env bash
# Build the Host application skeleton without allowing Tauri to select a
# signing identity. The resulting linker signature is verified separately by
# verify_candidate_bundle.py before any release manifest or manual signature.

cfw_build_tauri_host_skeleton() {
  if [[ $# -ne 3 ]]; then
    echo "error: cfw_build_tauri_host_skeleton requires APP_DIR TAURI_BIN CONFIG_OVERRIDE" >&2
    return 1
  fi

  local contract_tauri_host_app_dir="$1"
  local contract_tauri_host_bin="$2"
  local contract_tauri_host_config_override="$3"
  local contract_tauri_host_signing_variable

  [[ "$contract_tauri_host_app_dir" == /* && \
    -d "$contract_tauri_host_app_dir" && ! -L "$contract_tauri_host_app_dir" ]] || {
    echo "error: Tauri application root must be an absolute real directory" >&2
    return 1
  }
  [[ "$contract_tauri_host_bin" == /* && -f "$contract_tauri_host_bin" && \
    ! -L "$contract_tauri_host_bin" && -x "$contract_tauri_host_bin" ]] || {
    echo "error: pinned Tauri CLI must be an absolute executable regular file" >&2
    return 1
  }

  for contract_tauri_host_signing_variable in \
    APPLE_CERTIFICATE \
    APPLE_CERTIFICATE_PASSWORD \
    APPLE_SIGNING_IDENTITY; do
    if /usr/bin/printenv "$contract_tauri_host_signing_variable" >/dev/null 2>&1; then
      echo "error: $contract_tauri_host_signing_variable must be unset while Tauri builds the unsigned Host skeleton" >&2
      return 1
    fi
  done

  PYTHONDONTWRITEBYTECODE=1 python3 -B - \
    "$contract_tauri_host_app_dir" \
    "$contract_tauri_host_config_override" <<'PY' || return 1
import json
import os
import stat
import sys
from pathlib import Path


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def parse_json(text: str, source: str) -> dict[str, object]:
    try:
        value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"error: invalid Tauri configuration {source}: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"error: Tauri configuration {source} must be a JSON object")
    return value


def require_no_signing_identity(value: dict[str, object], source: str) -> None:
    bundle = value.get("bundle")
    if not isinstance(bundle, dict):
        raise SystemExit(f"error: Tauri configuration {source} has no bundle object")
    macos = bundle.get("macOS")
    if not isinstance(macos, dict):
        raise SystemExit(f"error: Tauri configuration {source} has no bundle.macOS object")
    if "signingIdentity" in macos:
        raise SystemExit(
            f"error: Tauri configuration {source} must not define bundle.macOS.signingIdentity"
        )


app_dir = Path(sys.argv[1])
config_path = app_dir / "tauri.conf.json"
try:
    config_metadata = config_path.lstat()
except OSError as error:
    raise SystemExit(f"error: cannot inspect Tauri configuration: {error}") from error
if (
    not stat.S_ISREG(config_metadata.st_mode)
    or config_path.is_symlink()
    or config_metadata.st_nlink != 1
):
    raise SystemExit("error: tauri.conf.json must be a regular non-linked file")
try:
    base_config = parse_json(config_path.read_text(encoding="utf-8"), str(config_path))
except OSError as error:
    raise SystemExit(f"error: cannot read Tauri configuration: {error}") from error
require_no_signing_identity(base_config, str(config_path))

for platform_name in (
    "tauri.macos.conf.json",
    "tauri.macos.conf.json5",
    "Tauri.macos.toml",
):
    platform_path = app_dir / platform_name
    if os.path.lexists(platform_path):
        raise SystemExit(
            "error: platform-specific Tauri configuration is forbidden for the unsigned "
            f"Host skeleton: {platform_path}"
        )

override = parse_json(sys.argv[2], "inline override")
require_no_signing_identity(override, "inline override")
PY

  (
    cd "$contract_tauri_host_app_dir" || {
      echo "error: cannot enter Tauri application root" >&2
      return 1
    }
    /usr/bin/env \
      -u APPLE_CERTIFICATE \
      -u APPLE_CERTIFICATE_PASSWORD \
      -u APPLE_SIGNING_IDENTITY \
      "$contract_tauri_host_bin" build --bundles app --ci --config \
      "$contract_tauri_host_config_override"
  )
}
