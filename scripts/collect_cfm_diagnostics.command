#!/bin/bash
# Local, read-only product diagnostics. No profile, Keychain item, controller
# secret, subscription URL, browser history, or automatic upload is collected.
set -euo pipefail
umask 077

cfm_app_path="${1:-/Applications/Clash for Mac.app}"
case "$cfm_app_path" in
  /*.app) ;;
  *) printf '%s\n' 'Usage: collect_cfm_diagnostics.command [/absolute/path/Clash for Mac.app]' >&2; exit 64 ;;
esac
cfm_info="$cfm_app_path/Contents/Info.plist"
if [ ! -f "$cfm_info" ]; then
  printf '%s\n' 'Clash for Mac Info.plist was not found.' >&2
  exit 66
fi
cfm_bundle_id=$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$cfm_info")
if [ "$cfm_bundle_id" != 'com.bill.clashformac' ]; then
  printf '%s\n' 'The selected app is not Clash for Mac.' >&2
  exit 65
fi
cfm_stamp=$(/bin/date '+%Y%m%d-%H%M%S')
cfm_output=$(/usr/bin/mktemp -d "$HOME/Desktop/CFM-Diagnostics-$cfm_stamp.XXXXXX")
cfm_failures=0

capture() {
  cfm_label=$1
  shift
  if "$@" > "$cfm_output/$cfm_label.txt" 2>&1; then
    printf '%s exit=0\n' "$cfm_label" >> "$cfm_output/collection-status.txt"
  else
    cfm_exit=$?
    printf '%s exit=%s\n' "$cfm_label" "$cfm_exit" >> "$cfm_output/collection-status.txt"
    cfm_failures=$((cfm_failures + 1))
  fi
}

capture system-version /usr/bin/sw_vers
capture architecture /usr/bin/uname -m
capture hardware-model /usr/sbin/sysctl -n hw.model
capture application-version /usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$cfm_info"
capture application-build /usr/bin/plutil -extract CFBundleVersion raw -o - "$cfm_info"
capture application-minimum-os /usr/bin/plutil -extract LSMinimumSystemVersion raw -o - "$cfm_info"
capture executable-architecture /usr/bin/file "$cfm_app_path/Contents/MacOS/clash-for-mac"
capture signature /usr/bin/codesign --verify --deep --strict "$cfm_app_path"

cfm_logs="$HOME/Library/Application Support/Clash for Mac/logs/diagnostics"
for cfm_log_name in startup.json network-errors.json network-warnings.json; do
  cfm_source="$cfm_logs/$cfm_log_name"
  if [ ! -e "$cfm_source" ] && [ ! -L "$cfm_source" ]; then
    printf '%s unavailable (older builds may not create this journal)\n' "$cfm_log_name" >> "$cfm_output/collection-status.txt"
    continue
  fi
  if [ -L "$cfm_logs" ] || [ -L "$cfm_source" ] || [ ! -f "$cfm_source" ]; then
    printf '%s refused: not a regular local journal\n' "$cfm_log_name" >> "$cfm_output/collection-status.txt"
    cfm_failures=$((cfm_failures + 1))
    continue
  fi
  cfm_size=$(/usr/bin/stat -f '%z' "$cfm_source")
  cfm_owner=$(/usr/bin/stat -f '%u' "$cfm_source")
  cfm_links=$(/usr/bin/stat -f '%l' "$cfm_source")
  if [ "$cfm_size" -gt 1048576 ] || [ "$cfm_owner" -ne "$UID" ] || [ "$cfm_links" -ne 1 ]; then
    printf '%s refused: size or ownership check failed\n' "$cfm_log_name" >> "$cfm_output/collection-status.txt"
    cfm_failures=$((cfm_failures + 1))
    continue
  fi
  if /usr/bin/plutil -lint "$cfm_source" > /dev/null 2>&1; then
    /bin/cp "$cfm_source" "$cfm_output/$cfm_log_name"
  else
    printf '%s refused: invalid journal\n' "$cfm_log_name" >> "$cfm_output/collection-status.txt"
    cfm_failures=$((cfm_failures + 1))
  fi
done

# Sample only the exact installed GUI executable. The Packet Tunnel, proxy
# service and other applications are not sampled or stopped.
if cfm_pids=$(/usr/bin/pgrep -x clash-for-mac); then
  :
else
  cfm_pgrep_exit=$?
  if [ "$cfm_pgrep_exit" -ne 1 ]; then
    printf 'dashboard-process-search exit=%s\n' "$cfm_pgrep_exit" >> "$cfm_output/collection-status.txt"
    cfm_failures=$((cfm_failures + 1))
  fi
  cfm_pids=''
fi
cfm_sampled=0
for cfm_pid in $cfm_pids; do
  if cfm_command=$(/bin/ps -p "$cfm_pid" -o comm=); then
    :
  else
    printf 'dashboard-process-%s became unavailable during collection\n' "$cfm_pid" >> "$cfm_output/collection-status.txt"
    cfm_failures=$((cfm_failures + 1))
    continue
  fi
  if [ "$cfm_command" = "$cfm_app_path/Contents/MacOS/clash-for-mac" ]; then
    capture "dashboard-sample-$cfm_sampled" /usr/bin/sample "$cfm_pid" 2 5 -file "$cfm_output/dashboard-stacks-$cfm_sampled.txt"
    cfm_sampled=$((cfm_sampled + 1))
    if [ "$cfm_sampled" -ge 2 ]; then break; fi
  fi
done
if [ "$cfm_sampled" -eq 0 ]; then
  printf '%s\n' 'No matching running dashboard process was available for sampling.' >> "$cfm_output/collection-status.txt"
fi
cat > "$cfm_output/README.txt" <<'TEXT'
This folder contains local CFM startup/network diagnostics and, when permitted,
a two-second sample of the dashboard's call stacks. Network settings, running
cores and application configuration were not modified.

Review these files before sharing. Journals may include destination hostnames,
node labels and connection errors; stack samples may include local file paths.
No profile documents, Keychain items, controller tokens, subscription files or
browser history were requested. No files are uploaded automatically.

Please describe whether the menu-bar icon still worked, whether this was the
first launch or a later blank window, and roughly when the failure occurred.
collection-status.txt retains missing or failed collection steps.
TEXT
/usr/bin/ditto -c -k --keepParent "$cfm_output" "$cfm_output.zip"
printf 'Local diagnostics: %s.zip\n' "$cfm_output"
printf 'Incomplete collection steps: %s\n' "$cfm_failures"
printf '%s\n' 'Review the files before sharing. Nothing was uploaded; network settings were not changed.'
