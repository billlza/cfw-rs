#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo build -p cfw-helper --release
mkdir -p apps/cfw-tauri-shell/resources/helpers
cp target/release/cfw-helper apps/cfw-tauri-shell/resources/helpers/cfw-helper
chmod 755 apps/cfw-tauri-shell/resources/helpers/cfw-helper
