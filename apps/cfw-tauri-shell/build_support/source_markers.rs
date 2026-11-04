//! The release build's source gates: a placeholder that stands in for a
//! native component during development must not be named by the sources the
//! release is built from.

use std::fs;
use std::path::Path;

/// Every placeholder the release refuses, and where: anywhere in the shell's
/// Rust sources for the native bridge, which its platform runtime composes,
/// and in the Swift sources that compose the native engines. `watch` receives
/// each checked path, so a build reruns the gate when one of them changes.
pub(crate) fn verify_release_source_markers(
    repository_root: &Path,
    mut watch: impl FnMut(&Path),
) -> Result<(), String> {
    let shell_sources = repository_root.join("apps/cfw-tauri-shell/src");
    watch(&shell_sources);
    reject_marker_in_rust_tree(&shell_sources, "MissingNativeBridge")?;
    for (relative, marker) in [
        (
            "native/macos/Sources/CFWProxyAgent/ProxyAgentExecutable.swift",
            "MissingLibboxProxyEngineFactory",
        ),
        (
            "native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift",
            "MissingLibboxEngineFactory",
        ),
        (
            "native/macos/Sources/CFWAppleNetwork/HostBridge.swift",
            "MissingSystemExtensionStateTransport",
        ),
        (
            "native/macos/Sources/CFWAppleNetwork/NetworkExtensionHostBridge.swift",
            "MissingSystemExtensionStateTransport",
        ),
        (
            "native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift",
            "systemExtensionStateTransportNotLinked",
        ),
    ] {
        let path = repository_root.join(relative);
        watch(&path);
        reject_source_marker(&path, marker)?;
    }
    Ok(())
}

pub(crate) fn reject_source_marker(path: &Path, marker: &str) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("read release source gate {}: {error}", path.display()))?;
    if text.contains(marker) {
        return Err(format!(
            "release source gate is still wired to {marker}: {}",
            path.display()
        ));
    }
    Ok(())
}

/// Fails when any Rust source under `root` names `marker`, wherever a later
/// change composes the component. The walk follows no symbolic link and fails
/// closed on an entry it cannot read or classify.
pub(crate) fn reject_marker_in_rust_tree(root: &Path, marker: &str) -> Result<(), String> {
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory).map_err(|error| {
            format!(
                "read release source directory {}: {error}",
                directory.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "read release source directory {}: {error}",
                    directory.display()
                )
            })?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| format!("inspect release source {}: {error}", path.display()))?;
            if kind.is_dir() {
                directories.push(path);
            } else if !kind.is_file() {
                return Err(format!(
                    "release source {} is neither a file nor a directory",
                    path.display()
                ));
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                reject_source_marker(&path, marker)?;
            }
        }
    }
    Ok(())
}
