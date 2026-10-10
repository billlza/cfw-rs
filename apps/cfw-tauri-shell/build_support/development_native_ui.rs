//! Admission of explicitly prepared development products. This module performs
//! filesystem validation only; Cargo never invokes Swift or copies resources.
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const OUTPUT_ENV: &str = "CFW_DEVELOPMENT_NATIVE_UI_PRODUCTS";
pub const LIBRARY: &str = "libCFMNativeDashboard.dylib";
pub const RESOURCES: &str = "CFMNativeDashboard_CFMNativeDashboard.bundle";
pub const SOURCE_PATHS: &[&str] = &[
    "native/dashboard/Package.swift",
    "native/dashboard/Sources",
    "native/dashboard/include",
    "scripts/prepare_development_native_ui.py",
    "scripts/hash_artifact.py",
    "scripts/publication/bounded_process.py",
    "scripts/publication/__init__.py",
    "apps/cfw-tauri-shell/build.rs",
    "apps/cfw-tauri-shell/build_support/development_native_ui.rs",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u32,
    artifact_kind: String,
    configuration: String,
    target: String,
    repository: PathBuf,
    cargo_target_dir: PathBuf,
    profile_relative: String,
    source_sha256: String,
    sources: BTreeMap<String, Value>,
    products: BTreeMap<String, Value>,
}

pub struct VerifiedProducts {
    pub library_root: PathBuf,
    pub watched_paths: Vec<PathBuf>,
}

fn canonical_directory(path: &Path) -> Result<(), String> {
    let text = path.to_str().ok_or("development path must be UTF-8")?;
    if !path.is_absolute()
        || text.contains(['\n', '\r'])
        || path.canonicalize().map_err(|error| error.to_string())? != path
        || !fs::symlink_metadata(path)
            .map_err(|error| error.to_string())?
            .is_dir()
    {
        return Err(format!(
            "development directory is not canonical: {}",
            path.display()
        ));
    }
    Ok(())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Only the normal repository target directory or an explicitly named,
/// isolated development target is writable by the external preparation step.
fn require_target_directory(repository: &Path, target: &Path) -> Result<(), String> {
    canonical_directory(target)?;
    let base = repository.join("target");
    if target == base {
        return Ok(());
    }
    let relative = target
        .strip_prefix(base.join("development"))
        .map_err(|_| "development Cargo target must be target or target/development/<name>")?;
    let parts: Vec<_> = relative.components().collect();
    let name = relative
        .to_str()
        .ok_or("development target name must be UTF-8")?;
    if parts.len() != 1
        || !matches!(parts[0], Component::Normal(_))
        || name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("development Cargo target name is invalid".into());
    }
    Ok(())
}

/// The callback is the same tree-manifest verifier used by release build.rs.
/// No development receipt can replace that verifier or override its hashes.
pub fn verify(
    repository: &Path,
    products: &Path,
    cargo_profile: &Path,
    mut verify_manifest: impl FnMut(&Path, &Value) -> Result<(), String>,
) -> Result<VerifiedProducts, String> {
    canonical_directory(repository)?;
    canonical_directory(products)?;
    canonical_directory(cargo_profile)?;
    let base = repository.join("target/native-ui-development");
    let relative = products
        .strip_prefix(&base)
        .map_err(|_| "development UI products must be below target/native-ui-development")?;
    let parts: Vec<_> = relative.iter().map(|part| part.to_str()).collect();
    if parts.len() != 3
        || parts[2] != Some("products")
        || !parts[0].is_some_and(|part| lower_hex(part, 64))
        || !parts[1].is_some_and(|part| lower_hex(part, 32))
    {
        return Err(
            "development UI products must identify one source digest and fresh attempt".into(),
        );
    }
    let receipt_path = products.join("receipt.json");
    let metadata = fs::symlink_metadata(&receipt_path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 2 * 1024 * 1024 {
        return Err("development UI receipt is not a bounded single-link regular file".into());
    }
    let receipt: Receipt =
        serde_json::from_slice(&fs::read(&receipt_path).map_err(|error| error.to_string())?)
            .map_err(|error| format!("invalid development UI receipt: {error}"))?;
    if receipt.schema_version != 1
        || receipt.artifact_kind != "development-native-ui-v1"
        || receipt.configuration != "debug"
        || receipt.target != "aarch64-apple-darwin"
        || receipt.repository != repository
        || Some(receipt.source_sha256.as_str()) != parts[0]
    {
        return Err(
            "development UI receipt has a different source, repository or development identity"
                .into(),
        );
    }
    require_target_directory(repository, &receipt.cargo_target_dir)?;
    if !matches!(
        receipt.profile_relative.as_str(),
        "debug" | "aarch64-apple-darwin/debug"
    ) || receipt.cargo_target_dir.join(&receipt.profile_relative) != cargo_profile
    {
        return Err(
            "development UI resources were prepared for a different Cargo output directory".into(),
        );
    }
    if receipt.sources.len() != SOURCE_PATHS.len()
        || SOURCE_PATHS
            .iter()
            .any(|path| !receipt.sources.contains_key(*path))
        || receipt.products.len() != 2
        || !receipt.products.contains_key(LIBRARY)
        || !receipt.products.contains_key(RESOURCES)
    {
        return Err("development UI receipt has an incomplete source or product closure".into());
    }
    let mut digest = Sha256::new();
    let mut watched_paths = vec![receipt_path, products.to_path_buf()];
    for (relative, manifest) in &receipt.sources {
        let path = repository.join(relative);
        verify_manifest(&path, manifest)?;
        let tree = manifest
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|value| lower_hex(value, 64))
            .ok_or("source tree digest is invalid")?;
        // Compose already verified sha256-tree-v1 manifests; do not invent a
        // second file/tree hashing algorithm for the development path.
        digest.update(relative.as_bytes());
        digest.update(b" ");
        digest.update(tree.as_bytes());
        digest.update(b"\n");
        watched_paths.push(path);
    }
    if digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        != receipt.source_sha256
    {
        return Err("development UI source manifests do not match the attempt identity".into());
    }
    for (name, manifest) in &receipt.products {
        verify_manifest(&products.join(name), manifest)?;
    }
    let resources = &receipt.products[RESOURCES];
    for directory in [cargo_profile.to_path_buf(), cargo_profile.join("deps")] {
        canonical_directory(&directory)?;
        let path = directory.join(RESOURCES);
        verify_manifest(&path, resources)?;
        watched_paths.push(path);
    }
    Ok(VerifiedProducts {
        library_root: products.to_path_buf(),
        watched_paths,
    })
}
