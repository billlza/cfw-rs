#!/bin/bash
set -euo pipefail
preview_sources="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
preview_package="$(cd -- "$preview_sources/.." && pwd)"
preview_repository="$(cd -- "$preview_package/../.." && pwd)"
preview_output="${1:?Usage: build-preview.sh NEW_OUTPUT_DIRECTORY}"
if [[ -e "$preview_output" ]]; then
  echo 'Refusing to replace an existing preview output directory.' >&2
  exit 1
fi
mkdir -p -- "$preview_output"
preview_output="$(cd -- "$preview_output" && pwd)"
preview_scratch="$preview_output/swift-build"
/usr/bin/xcrun swift build --package-path "$preview_package" --scratch-path "$preview_scratch" \
  --configuration debug --product CFMNativeDashboard -Xswiftc -warnings-as-errors
preview_products="$(/usr/bin/xcrun swift build --package-path "$preview_package" --scratch-path "$preview_scratch" --configuration debug --show-bin-path)"
preview_app="$preview_output/Clash for Mac 0.5 Preview.app"
mkdir -p "$preview_app/Contents/MacOS" "$preview_app/Contents/Frameworks" "$preview_app/Contents/Resources"
/usr/bin/ditto "$preview_products/CFMNativeDashboard_CFMNativeDashboard.bundle" "$preview_app/Contents/Resources/CFMNativeDashboard_CFMNativeDashboard.bundle"
/bin/cp "$preview_products/libCFMNativeDashboard.dylib" "$preview_app/Contents/Frameworks/"
/bin/cp "$preview_repository/apps/cfw-tauri-shell/icons/icon.icns" "$preview_app/Contents/Resources/icon.icns"
cat > "$preview_app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Clash for Mac 0.5 Preview</string>
<key>CFBundleDisplayName</key><string>Clash for Mac 0.5 Preview</string>
<key>CFBundleIdentifier</key><string>com.bill.clashformac.ui-preview</string>
<key>CFBundleExecutable</key><string>CFMNativePreview</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.5.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleIconFile</key><string>icon.icns</string>
<key>CFBundleDevelopmentRegion</key><string>zh-Hans</string>
<key>CFBundleLocalizations</key><array><string>en</string><string>zh-Hans</string><string>zh-Hant</string><string>ja</string></array>
<key>LSMinimumSystemVersion</key><string>15.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSHumanReadableCopyright</key><string>UI preview only. No network services.</string>
</dict></plist>
PLIST
/usr/bin/xcrun swiftc -parse-as-library -swift-version 6 -warnings-as-errors -target arm64-apple-macos15.0 \
  -import-objc-header "$preview_package/include/cfm_native_dashboard.h" \
  -L "$preview_app/Contents/Frameworks" -lCFMNativeDashboard \
  -Xlinker -rpath -Xlinker '@executable_path/../Frameworks' \
  "$preview_sources/PreviewHost.swift" -o "$preview_app/Contents/MacOS/CFMNativePreview"
/usr/bin/codesign --force --sign - --timestamp=none "$preview_app/Contents/Frameworks/libCFMNativeDashboard.dylib"
/usr/bin/codesign --force --sign - --timestamp=none "$preview_app"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$preview_app"
"$preview_app/Contents/MacOS/CFMNativePreview" --self-check
printf '%s\n' "$preview_app"
