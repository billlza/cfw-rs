#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
trusted_python="${CFW_RELEASE_PYTHON_EXECUTABLE:-}"
[[ -x "$trusted_python" ]] || {
  echo "error: updater-secret fixture requires closed Python" >&2
  exit 1
}

run_clean_environment() {
  /usr/bin/env -i \
    "HOME=$HOME" \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    LANG=C \
    LC_ALL=C \
    "$@"
}

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/cfw-updater-secret.XXXXXX")"
trap '/bin/rm -rf "$temporary_root"' EXIT

trace_log="$temporary_root/xtrace.log"
if run_clean_environment \
  TAURI_PRIVATE_KEY_PATH=/outside/updater.key \
  TAURI_PRIVATE_KEY_PASSWORD=trace-secret-must-not-appear \
  /bin/bash -p -x "$repo_root/scripts/make_updater_manifest.sh" \
  >"$trace_log" 2>&1; then
  echo "error: xtrace entry unexpectedly passed updater release creation" >&2
  exit 1
fi
/usr/bin/grep -Fq "refuses shell xtrace" "$trace_log"
if /usr/bin/grep -Fq "trace-secret-must-not-appear" "$trace_log"; then
  echo "error: updater password was expanded into xtrace output" >&2
  exit 1
fi

for secret_name in \
  TAURI_PRIVATE_KEY \
  TAURI_PRIVATE_KEY_PATH \
  TAURI_PRIVATE_KEY_PASSWORD \
  TAURI_SIGNING_PRIVATE_KEY \
  TAURI_SIGNING_PRIVATE_KEY_PATH \
  TAURI_SIGNING_PRIVATE_KEY_PASSWORD
do
  secret_value="forbidden-${secret_name}"
  secret_log="$temporary_root/${secret_name}.log"
  if run_clean_environment "$secret_name=$secret_value" \
    "$repo_root/scripts/make_updater_manifest.sh" \
    >"$secret_log" 2>&1; then
    echo "error: $secret_name unexpectedly passed updater release creation" >&2
    exit 1
  fi
  /usr/bin/grep -Fq "caller-supplied Tauri signing secrets are forbidden" \
    "$secret_log"
  if /usr/bin/grep -Fq "$secret_value" "$secret_log"; then
    echo "error: $secret_name value appeared in updater release output" >&2
    exit 1
  fi
done

startup_hook="$temporary_root/startup-hook.sh"
startup_marker="$temporary_root/startup-hook-ran"
printf '%s\n' "printf '%s\\n' ran >'$startup_marker'; unset BASH_ENV ENV" \
  >"$startup_hook"
for hook_name in BASH_ENV ENV; do
  hook_log="$temporary_root/${hook_name}.log"
  if run_clean_environment "$hook_name=$startup_hook" \
    "$repo_root/scripts/make_updater_manifest.sh" \
    >"$hook_log" 2>&1; then
    echo "error: $hook_name unexpectedly passed updater release creation" >&2
    exit 1
  fi
  /usr/bin/grep -Fq "refuses shell startup hooks" "$hook_log"
  [[ ! -e "$startup_marker" ]] || {
    echo "error: privileged updater entrypoint executed $hook_name" >&2
    exit 1
  }
done

ordinary_bash_log="$temporary_root/ordinary-bash.log"
if run_clean_environment \
  /bin/bash "$repo_root/scripts/make_updater_manifest.sh" \
  >"$ordinary_bash_log" 2>&1; then
  echo "error: ordinary bash bypassed the privileged updater entrypoint" >&2
  exit 1
fi
/usr/bin/grep -Fq "requires its /bin/bash -p entrypoint" "$ordinary_bash_log"

exported_options_log="$temporary_root/exported-options.log"
if run_clean_environment BASHOPTS=extdebug \
  "$repo_root/scripts/make_updater_manifest.sh" \
  >"$exported_options_log" 2>&1; then
  echo "error: exported BASHOPTS unexpectedly passed updater creation" >&2
  exit 1
fi
/usr/bin/grep -Fq "refuses exported shell option state" "$exported_options_log"

hijack_bin="$temporary_root/hijack-bin"
hijack_marker="$temporary_root/hijacked-python-ran"
mkdir -p "$hijack_bin"
cat >"$hijack_bin/python3" <<SH
#!/bin/bash
printf '%s\n' ran >"$hijack_marker"
exec "$trusted_python" "\$@"
SH
chmod 755 "$hijack_bin/python3"
hijack_log="$temporary_root/path-hijack.log"
if run_clean_environment PATH="$hijack_bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  "$repo_root/scripts/make_updater_manifest.sh" /nonexistent \
  >"$hijack_log" 2>&1; then
  echo "error: PATH-hijack fixture unexpectedly passed updater creation" >&2
  exit 1
fi
[[ ! -e "$hijack_marker" ]] || {
  echo "error: caller-controlled PATH executed a fake Python interpreter" >&2
  exit 1
}

python_injection="$temporary_root/python-injection"
python_injection_marker="$temporary_root/python-injection-ran"
mkdir -p "$python_injection"
cat >"$python_injection/sitecustomize.py" <<PY
from pathlib import Path
Path("$python_injection_marker").write_text("ran\n", encoding="utf-8")
PY
unsafe_environment_log="$temporary_root/unsafe-environment.log"
if run_clean_environment PYTHONPATH="$python_injection" \
  "$repo_root/scripts/make_updater_manifest.sh" /nonexistent \
  >"$unsafe_environment_log" 2>&1; then
  echo "error: unsafe Python environment unexpectedly passed" >&2
  exit 1
fi
/usr/bin/grep -Fq "refuses unsafe exported environment state" \
  "$unsafe_environment_log"
[[ ! -e "$python_injection_marker" ]] || {
  echo "error: caller Python import path executed before custody checks" >&2
  exit 1
}

python_bytecode_log="$temporary_root/python-bytecode.log"
if run_clean_environment PYTHONDONTWRITEBYTECODE=1 \
  "$repo_root/scripts/make_updater_manifest.sh" /nonexistent \
  >"$python_bytecode_log" 2>&1; then
  echo "error: caller PYTHONDONTWRITEBYTECODE unexpectedly passed" >&2
  exit 1
fi
/usr/bin/grep -Fq "refuses unsafe exported environment state" \
  "$python_bytecode_log"

python_userbase="$temporary_root/python-userbase"
python_userbase_marker="$temporary_root/python-userbase-ran"
python_version="$(PYTHONDONTWRITEBYTECODE=1 "$trusted_python" -I -S -B -W error -c \
  'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')"
python_user_site="$python_userbase/lib/$python_version/site-packages"
mkdir -p "$python_user_site"
cat >"$python_user_site/usercustomize.py" <<PY
from pathlib import Path
Path("$python_userbase_marker").write_text("ran\n", encoding="utf-8")
PY
python_userbase_log="$temporary_root/python-userbase.log"
if run_clean_environment PYTHONUSERBASE="$python_userbase" \
  "$repo_root/scripts/make_updater_manifest.sh" /nonexistent \
  >"$python_userbase_log" 2>&1; then
  echo "error: PYTHONUSERBASE unexpectedly passed updater creation" >&2
  exit 1
fi
/usr/bin/grep -Fq "refuses unsafe exported environment state" \
  "$python_userbase_log"
[[ ! -e "$python_userbase_marker" ]] || {
  echo "error: caller usercustomize executed before custody checks" >&2
  exit 1
}

fixture_repo="$temporary_root/repository"
ga_root="$fixture_repo/target/candidates/0.4.0/ga/40034"
app_path="$ga_root/signed/Clash for Mac.app"
native_products="$ga_root/signing-output/signed-native-products"
mkdir -p "$fixture_repo/scripts" "$native_products" \
  "$app_path/Contents"
/bin/cp "$repo_root/scripts/make_updater_manifest.sh" "$fixture_repo/scripts/"

cat >"$fixture_repo/scripts/dependency_pins.env" <<'SH'
TAURI_CLI_VERSION=2.11.4
SH

cat >"$fixture_repo/scripts/release_toolchain_contract.sh" <<'SH'
cfw_require_supported_python() {
  "$1" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'
}

cfw_verify_tauri_toolchain_tree() {
  [[ "$1" == /* && "$2" == /* ]]
}
SH

cat >"$fixture_repo/scripts/release_publication_gate.sh" <<SH
CFW_RELEASE_PYTHON_EXECUTABLE="$trusted_python"
export CFW_RELEASE_PYTHON_EXECUTABLE

cfw_run_release_python_script() {
  local repository="\$1"
  local script="\$2"
  shift 2
  PYTHONDONTWRITEBYTECODE=1 "\$CFW_RELEASE_PYTHON_EXECUTABLE" \
    -I -S -B -W error "\$script" "\$@"
}

release_native_products_root_for_app() {
  [[ "\$1" == "\${BASH_SOURCE[0]%/scripts/release_publication_gate.sh}/target/candidates/0.4.0/ga/40034/signed/Clash for Mac.app" ]]
  printf '%s\n' "\${BASH_SOURCE[0]%/scripts/release_publication_gate.sh}/target/candidates/0.4.0/ga/40034/signing-output/signed-native-products"
}

verify_release_prepackage_evidence() {
  [[ "\$#" -eq 1 && "\$1" == "\${BASH_SOURCE[0]%/scripts/release_publication_gate.sh}/target/candidates/0.4.0/ga/40034/signed/Clash for Mac.app" ]]
}
SH

cat >"$fixture_repo/scripts/verify_release_app.sh" <<'SH'
#!/bin/bash
set -euo pipefail
repo_root="${BASH_SOURCE[0]%/scripts/verify_release_app.sh}"
[[ "$#" -eq 4 ]]
[[ "$1" == "$repo_root/target/candidates/0.4.0/ga/40034/signed/Clash for Mac.app" ]]
[[ "$2" == "$repo_root/target/candidates/0.4.0/ga/40034/signing-output/signed-native-products" ]]
[[ "$3" == "--context" ]]
[[ "$4" == "canonical-native-content" ]]
SH
chmod 755 "$fixture_repo/scripts/verify_release_app.sh"

cat >"$fixture_repo/scripts/validate_updater_archive.py" <<'PY'
from __future__ import annotations

import os
from pathlib import Path
import sys

if sys.flags.no_site != 1:
    raise SystemExit("archive validator loaded Python site customization")
if len(sys.argv) != 3 or not Path(sys.argv[1]).is_absolute():
    raise SystemExit("unexpected archive validator invocation")
if any(
    name.startswith("TAURI_PRIVATE_KEY")
    or name.startswith("TAURI_SIGNING_PRIVATE_KEY")
    for name in os.environ
):
    raise SystemExit("caller signing secret reached archive validation")
PY

cat >"$fixture_repo/scripts/updater_signing_launcher.py" <<'PY'
from __future__ import annotations

import os
from pathlib import Path
import sys

if sys.flags.no_site != 1 or sys.flags.isolated != 1:
    raise SystemExit("updater launcher loaded Python site customization")
if len(sys.argv) != 2:
    raise SystemExit("updater launcher must receive only one archive path")
if any(
    name.startswith("TAURI_PRIVATE_KEY")
    or name.startswith("TAURI_SIGNING_PRIVATE_KEY")
    for name in os.environ
):
    raise SystemExit("caller signing secret reached source-pinned launcher")
archive = Path(sys.argv[1])
if not archive.is_absolute() or not archive.is_file():
    raise SystemExit("updater archive is unavailable")
if Path(__file__).with_name("fail-signing").exists():
    raise SystemExit("synthetic signer failure")
archive.with_name(f"{archive.name}.sig").write_text(
    "fixture-signature\n",
    encoding="utf-8",
)
PY

cat >"$fixture_repo/scripts/release_artifact_set_cli.py" <<'PY'
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys

if sys.flags.no_site != 1:
    raise SystemExit("release-set sealer loaded Python site customization")
if any(
    name.startswith("TAURI_PRIVATE_KEY")
    or name.startswith("TAURI_SIGNING_PRIVATE_KEY")
    for name in os.environ
):
    raise SystemExit("caller signing secret reached release-set sealing")
arguments = sys.argv[1:]
if not arguments or arguments[0] != "seal-updater":
    raise SystemExit("unexpected release-artifact-set invocation")
staging = Path(arguments[arguments.index("--staging") + 1])
destination = Path(arguments[arguments.index("--destination") + 1])
shutil.copytree(staging, destination)
(destination / "updater-set.seal.json").write_text("{}\n", encoding="utf-8")
PY

cat >"$app_path/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleShortVersionString</key>
  <string>0.4.0</string>
  <key>CFBundleVersion</key>
  <string>40034</string>
</dict>
</plist>
PLIST
printf '%s\n' "fixture app" >"$app_path/Contents/fixture.txt"

run_fixture() {
  run_clean_environment \
    CFW_TOOLCHAIN_ROOT="$fixture_repo/target/toolchains" \
    "$fixture_repo/scripts/make_updater_manifest.sh"
}

positive_log="$temporary_root/positive.log"
if ! run_fixture >"$positive_log" 2>&1; then
  /bin/cat "$positive_log" >&2
  echo "error: updater custody positive fixture failed" >&2
  exit 1
fi
final_set="$ga_root/packages/updater/v0.4.0"
for required in \
  "Clash.for.Mac_0.4.0_aarch64.app.tar.gz" \
  "Clash.for.Mac_0.4.0_aarch64.app.tar.gz.sig" \
  latest.json \
  updater-set.seal.json
do
  [[ -f "$final_set/$required" ]] || {
    echo "error: positive fixture omitted $required" >&2
    exit 1
  }
done

/bin/rm -rf "$final_set"
touch "$fixture_repo/scripts/fail-signing"
failure_log="$temporary_root/failure.log"
if run_fixture >"$failure_log" 2>&1; then
  echo "error: synthetic signer failure unexpectedly passed" >&2
  exit 1
fi
if find "$ga_root/packages/updater" -name 'updater-stage.*' -print -quit 2>/dev/null | \
  /usr/bin/grep -q .; then
  echo "error: failed signer left updater staging material" >&2
  exit 1
fi
[[ ! -e "$final_set" ]] || {
  echo "error: failed signer published a final updater set" >&2
  exit 1
}

echo "updater signing secret custody fails closed"
