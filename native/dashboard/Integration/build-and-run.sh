#!/bin/bash
set -euo pipefail
integration_mode="${1:-launch}"
if [[ "$integration_mode" != "launch" && "$integration_mode" != "--build-only" ]]; then
  printf 'Usage: %s [--build-only]\n' "$0" >&2
  exit 2
fi
integration_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "$integration_dir/../../.." && pwd)"
run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$repo_dir/target/050-completion/component-integration-$run_stamp"
app_dir="$run_dir/CFM Component Integration Test.app"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Frameworks" "$app_dir/Contents/Resources"
printf '%s\n' "$run_dir"
xcrun swift build --package-path "$repo_dir/native/dashboard" --scratch-path "$run_dir/swift-build" -Xswiftc -warnings-as-errors > "$run_dir/swift-library-build.log" 2>&1
products_dir="$(xcrun swift build --package-path "$repo_dir/native/dashboard" --scratch-path "$run_dir/swift-build" --show-bin-path)"
cp "$products_dir/libCFMNativeDashboard.dylib" "$app_dir/Contents/Frameworks/"
cp -R "$products_dir/CFMNativeDashboard_CFMNativeDashboard.bundle" "$app_dir/Contents/Resources/"
cp -R "$repo_dir/apps/cfw-tauri-shell/ui/dist" "$app_dir/Contents/Resources/ui"
cp "$integration_dir/fixtures.json" "$integration_dir/bridge.js" "$app_dir/Contents/Resources/"
xcrun swiftc -swift-version 6 -warnings-as-errors -parse-as-library -target arm64-apple-macos15.0 \
  -import-objc-header "$integration_dir/Bridge.h" "$integration_dir/Main.swift" \
  -L "$products_dir" -lCFMNativeDashboard -Xlinker -rpath -Xlinker @executable_path/../Frameworks \
  -o "$app_dir/Contents/MacOS/CFMComponentIntegrationTest" > "$run_dir/host-build.log" 2>&1
/usr/libexec/PlistBuddy -c 'Clear dict' -c 'Add :CFBundleExecutable string CFMComponentIntegrationTest' \
  -c 'Add :CFBundleIdentifier string com.bill.cfm.component-integration-test' \
  -c 'Add :CFBundleName string CFM Component Integration Test' -c 'Add :CFBundlePackageType string APPL' \
  -c 'Add :CFBundleVersion string 1' -c 'Add :CFBundleShortVersionString string 0.0-test' \
  -c 'Add :LSMinimumSystemVersion string 15.0' -c 'Add :NSHighResolutionCapable bool true' "$app_dir/Contents/Info.plist" > "$run_dir/plist.log" 2>&1
python3 - "$repo_dir" "$app_dir" "$run_dir" <<'PY'
import hashlib, json, pathlib, subprocess, sys
repo, app, output = map(pathlib.Path, sys.argv[1:])
files = {}
for path in sorted((app/'Contents/Resources/ui').rglob('*')):
    if path.is_file(): files[str(path.relative_to(app))] = hashlib.sha256(path.read_bytes()).hexdigest()
receipt = {'test_data':True, 'production_host':False, 'network_acceptance':False,
           'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
           'bundle':str(app), 'frontend_files':files}
(output/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY
/usr/bin/codesign --force --deep --sign - "$app_dir" > "$run_dir/adhoc-sign.log" 2>&1
if [[ "$integration_mode" == "--build-only" ]]; then
  printf 'Built only; not launched: %s\n' "$app_dir"
  exit 0
fi
/usr/bin/open -n "$app_dir"
for attempt in {1..40}; do
  if [[ -f "$run_dir/running.json" ]]; then
    printf 'TEST DATA bundle: %s\n' "$app_dir"
    cat "$run_dir/running.json"
    exit 0
  fi
  if [[ -f "$run_dir/intents.jsonl" ]] && rg -q '"event":"startup_failure"' "$run_dir/intents.jsonl"; then
    cat "$run_dir/intents.jsonl"
    exit 1
  fi
  sleep 0.25
done
printf 'No startup receipt yet; inspect the process and %s before another launch.\n' "$run_dir" >&2
exit 1
