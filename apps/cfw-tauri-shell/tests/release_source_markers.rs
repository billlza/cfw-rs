#![cfg(target_os = "macos")]
// The release build's source gates, run on this repository in every test run,
// so a placeholder wired in anywhere fails here before a release build, and on
// small trees that do or do not name a placeholder.
#[path = "../build_support/source_markers.rs"]
mod source_markers;

use std::fs;
use std::path::{Path, PathBuf};

use source_markers::{
    reject_marker_in_rust_tree, reject_source_marker, verify_release_source_markers,
};

const PLACEHOLDER: &str = "MissingNativeBridge";

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("source directory");
    fs::write(path, text).expect("source file");
}

#[test]
fn the_repository_passes_every_release_source_gate() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository root");
    let mut watched: Vec<PathBuf> = Vec::new();
    verify_release_source_markers(repository, |path| watched.push(path.to_path_buf()))
        .expect("the release source gates pass on this repository");
    // The bridge gate covers the whole shell tree, not one file of it.
    assert_eq!(watched[0], repository.join("apps/cfw-tauri-shell/src"));
    assert_eq!(watched.len(), 5, "{watched:?}");
}

#[test]
fn a_placeholder_named_anywhere_in_the_tree_fails_the_gate() {
    let root = tempfile::tempdir().expect("tree");
    write(&root.path().join("main.rs"), "fn main() {}\n");
    write(
        &root.path().join("platform/nested/runtime.rs"),
        "let backend = AppleNetworkBackend::new(MissingNativeBridge);\n",
    );
    let error =
        reject_marker_in_rust_tree(root.path(), PLACEHOLDER).expect_err("wired placeholder");
    assert!(
        error.starts_with("release source gate is still wired to MissingNativeBridge:")
            && error.ends_with("platform/nested/runtime.rs"),
        "{error}"
    );
}

#[test]
fn a_tree_without_the_placeholder_passes_and_only_rust_sources_are_read() {
    let root = tempfile::tempdir().expect("tree");
    write(
        &root.path().join("platform/runtime.rs"),
        "let bridge = NativeFrameworkBridge::load();\n",
    );
    write(
        &root.path().join("notes/README.md"),
        "MissingNativeBridge is the development placeholder.\n",
    );
    write(
        &root.path().join("observation.c"),
        "/* MissingNativeBridge */\n",
    );
    reject_marker_in_rust_tree(root.path(), PLACEHOLDER).expect("no Rust source names it");
}

#[test]
fn a_symbolic_link_or_a_missing_tree_fails_closed() {
    let root = tempfile::tempdir().expect("tree");
    write(&root.path().join("main.rs"), "fn main() {}\n");
    std::os::unix::fs::symlink(root.path().join("main.rs"), root.path().join("linked.rs"))
        .expect("symbolic link");
    let error = reject_marker_in_rust_tree(root.path(), PLACEHOLDER).expect_err("symbolic link");
    assert!(
        error.ends_with("linked.rs is neither a file nor a directory"),
        "{error}"
    );

    let missing = root.path().join("absent");
    let error = reject_marker_in_rust_tree(&missing, PLACEHOLDER).expect_err("missing tree");
    assert!(
        error.starts_with("read release source directory"),
        "{error}"
    );
}

#[test]
fn a_single_source_names_or_omits_its_marker() {
    let root = tempfile::tempdir().expect("tree");
    let source = root.path().join("ProxyAgentExecutable.swift");
    write(&source, "let factory = LibboxProxyEngineFactory()\n");
    reject_source_marker(&source, "MissingLibboxProxyEngineFactory").expect("real factory");
    write(&source, "let factory = MissingLibboxProxyEngineFactory()\n");
    let error = reject_source_marker(&source, "MissingLibboxProxyEngineFactory")
        .expect_err("placeholder factory");
    assert!(
        error.starts_with("release source gate is still wired to MissingLibboxProxyEngineFactory:"),
        "{error}"
    );
    let error = reject_source_marker(&root.path().join("absent.swift"), "Missing")
        .expect_err("missing source");
    assert!(error.starts_with("read release source gate"), "{error}");
}
