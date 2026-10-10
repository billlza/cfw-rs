#[path = "../build_support/development_native_ui.rs"]
mod development_native_ui;

use development_native_ui::{LIBRARY, RESOURCES, SOURCE_PATHS, verify};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct Fixture {
    _temporary: TempDir,
    repository: PathBuf,
    products: PathBuf,
    profile: PathBuf,
    receipt: Value,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap();
        let repository = temporary.path().canonicalize().unwrap();
        let target = repository.join("target");
        let profile = target.join("debug");
        fs::create_dir_all(profile.join("deps")).unwrap();
        let sources: BTreeMap<_, _> = SOURCE_PATHS
            .iter()
            .map(|path| ((*path).to_owned(), json!({"sha256": "0".repeat(64)})))
            .collect();
        let mut digest = Sha256::new();
        for (path, manifest) in &sources {
            digest.update(format!("{path} {}\n", manifest["sha256"].as_str().unwrap()).as_bytes());
        }
        let digest = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let products = target
            .join("native-ui-development")
            .join(&digest)
            .join("1".repeat(32))
            .join("products");
        fs::create_dir_all(&products).unwrap();
        let receipt = json!({
            "schema_version": 1, "artifact_kind": "development-native-ui-v1", "configuration": "debug",
            "target": "aarch64-apple-darwin", "repository": repository, "cargo_target_dir": target,
            "profile_relative": "debug", "source_sha256": digest, "sources": sources,
            "products": {LIBRARY: {}, RESOURCES: {}}
        });
        let fixture = Self {
            _temporary: temporary,
            repository,
            products,
            profile,
            receipt,
        };
        fixture.save();
        fixture
    }
    fn save(&self) {
        fs::write(
            self.products.join("receipt.json"),
            serde_json::to_vec(&self.receipt).unwrap(),
        )
        .unwrap();
    }
    fn run(&self, checker: impl FnMut(&Path, &Value) -> Result<(), String>) -> Result<(), String> {
        verify(&self.repository, &self.products, &self.profile, checker).map(|verified| {
            assert_eq!(verified.library_root, self.products);
            assert!(
                verified
                    .watched_paths
                    .contains(&self.profile.join(RESOURCES))
            );
            assert!(
                verified
                    .watched_paths
                    .contains(&self.products.join("receipt.json"))
            );
        })
    }
}

#[test]
fn delegates_the_complete_source_product_and_runtime_resource_closure_to_existing_verifier() {
    assert_eq!(
        development_native_ui::OUTPUT_ENV,
        "CFW_DEVELOPMENT_NATIVE_UI_PRODUCTS"
    );
    let fixture = Fixture::new();
    let mut paths = Vec::new();
    fixture
        .run(|path, _| {
            paths.push(path.to_path_buf());
            Ok(())
        })
        .unwrap();
    assert_eq!(paths.len(), SOURCE_PATHS.len() + 4);
    for source in SOURCE_PATHS {
        assert!(paths.contains(&fixture.repository.join(source)));
    }
    for name in [LIBRARY, RESOURCES] {
        assert!(paths.contains(&fixture.products.join(name)));
    }
    assert!(paths.contains(&fixture.profile.join(RESOURCES)));
    assert!(paths.contains(&fixture.profile.join("deps").join(RESOURCES)));
}

#[test]
fn any_source_product_or_runtime_copy_verifier_failure_rejects_the_inputs() {
    let fixture = Fixture::new();
    for rejected in [
        fixture.repository.join(SOURCE_PATHS[0]),
        fixture.products.join(LIBRARY),
        fixture.products.join(RESOURCES),
        fixture.profile.join(RESOURCES),
        fixture.profile.join("deps").join(RESOURCES),
    ] {
        assert_eq!(
            fixture.run(|path, _| if path == rejected {
                Err("hash mismatch".into())
            } else {
                Ok(())
            }),
            Err("hash mismatch".into())
        );
    }
}

#[test]
fn rejects_release_identity_foreign_target_and_missing_source_before_manifest_admission() {
    let mut fixture = Fixture::new();
    let original = fixture.receipt.clone();
    for (key, value) in [
        ("configuration", json!("release")),
        ("artifact_kind", json!("native-host-bridge-v1")),
        ("target", json!("x86_64-apple-darwin")),
        ("repository", json!("/Applications/Clash for Mac.app")),
        (
            "cargo_target_dir",
            json!(fixture.repository.join("target/candidates")),
        ),
        ("profile_relative", json!("release")),
        ("sources", json!({})),
    ] {
        fixture.receipt = original.clone();
        fixture.receipt[key] = value;
        fixture.save();
        assert!(
            fixture
                .run(|_, _| panic!("incomplete receipt reached artifact admission"))
                .is_err(),
            "{key}"
        );
    }
}

#[test]
fn refuses_candidate_or_symlink_product_roots() {
    let fixture = Fixture::new();
    let alias = fixture.repository.join("alias");
    std::os::unix::fs::symlink(&fixture.products, &alias).unwrap();
    let candidate = fixture
        .repository
        .join("target/candidates/0.5.0/native-products");
    fs::create_dir_all(&candidate).unwrap();
    for products in [alias, candidate] {
        assert!(
            verify(
                &fixture.repository,
                &products,
                &fixture.profile,
                |_, _| panic!("foreign path admitted")
            )
            .is_err()
        );
    }
}

#[test]
fn changed_source_manifest_fingerprint_cannot_reuse_an_old_attempt_identity() {
    let mut fixture = Fixture::new();
    fixture.receipt["sources"][SOURCE_PATHS[0]]["sha256"] = json!("f".repeat(64));
    fixture.save();
    assert!(
        fixture
            .run(|_, _| Ok(()))
            .unwrap_err()
            .contains("attempt identity")
    );
}
