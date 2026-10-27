#![cfg(windows)]

// Exercise the actual user-selected-file importer without Tauri or a private
// ACL requirement. Full application/GUI admission remains a separate gate.
#[path = "../../../apps/cfw-tauri-shell/src/commands/subscriptions/local_file.rs"]
mod local_file;
