use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The candidate build lanes (`scripts/build_unsigned_candidate.sh` and
/// `scripts/build_signed_candidate.sh`) export the immutable, candidate-scoped
/// native product root and the native build scripts refuse any other layout.
/// A release build of this crate reads the root from this variable only: there
/// is no shared directory, no implicit default, and no stale-directory recovery.
const NATIVE_PRODUCTS_OUTPUT_ENV: &str = "CFW_NATIVE_PRODUCTS_OUTPUT";
const REPOSITORY_COMMIT_ENV: &str = "CFW_REPOSITORY_COMMIT";
const RELEASE_SOURCE_SHA256_ENV: &str = "CFW_RELEASE_SOURCE_SHA256";
const GO_TOOLCHAIN_TREE_SHA256_ENV: &str = "CFW_GO_TOOLCHAIN_TREE_SHA256";
const GO_TOOLS_TREE_SHA256_ENV: &str = "CFW_GO_TOOLS_TREE_SHA256";
const GO_MODULE_CACHE_TREE_SHA256_ENV: &str = "CFW_GO_MODULE_CACHE_TREE_SHA256";

const LIBBOX_METADATA_KEYS: [&str; 24] = [
    "sourceTag",
    "sourceCommit",
    "goVersion",
    "goToolchainTreeSha256",
    "goToolsTreeSha256",
    "goModuleCacheTreeSha256",
    "gomobileVersion",
    "gomobileCommit",
    "gomobileModuleSum",
    "archiveDeterminism",
    "headerNormalization",
    "platform",
    "buildTags",
    "nonMacOsTags",
    "upstreamGoModSha256",
    "upstreamGoSumSha256",
    "securityPatchSha256",
    "rawPacketPatchSha256",
    "dnsFailoverPatchSha256",
    "endpointConflictPatchSha256",
    "patchedDiffSha256",
    "combinedDiffSha256",
    "patchedGoModSha256",
    "patchedGoSumSha256",
];

/// Every native product the release bundle embeds, with its required artifact
/// kind. The full set must be present in the candidate root; a partial set is a
/// hard failure.
const NATIVE_PRODUCTS: [(&str, &str); 4] = [
    ("CFWGlobalAuthority", "native-global-authority-v1"),
    ("CFWNativeBridge.framework", "native-host-bridge-v1"),
    ("CFWProxyAgent.app", "native-proxy-agent-v1"),
    (
        "com.bill.clashformac.packet-tunnel.systemextension",
        "native-packet-tunnel-v1",
    ),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifest {
    algorithm: String,
    root: String,
    sha256: String,
    entries: Vec<ArtifactEntry>,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum ArtifactEntry {
    Directory {
        path: String,
    },
    File {
        path: String,
        size: u64,
        sha256: String,
    },
    Symlink {
        path: String,
        target: String,
    },
}

impl ArtifactEntry {
    fn path(&self) -> &str {
        match self {
            Self::Directory { path } | Self::File { path, .. } | Self::Symlink { path, .. } => path,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeDependencyLock {
    go: String,
    gomobile: String,
    sing_box: SingBoxLock,
    sing_box_for_apple_reference: AppleReferenceLock,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SingBoxLock {
    commit: String,
    tag: String,
    android_reference_commit: String,
    security_patch: SingBoxSecurityPatchLock,
    raw_packet_patch: SingBoxSourcePatchLock,
    dns_failover_patch: SingBoxSourcePatchLock,
    endpoint_conflict_patch: SingBoxSourcePatchLock,
    combined_diff_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SingBoxSecurityPatchLock {
    path: String,
    sha256: String,
    patched_diff_sha256: String,
    patched_go_mod_sha256: String,
    patched_go_sum_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SingBoxSourcePatchLock {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppleReferenceLock {
    commit: String,
}

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os != "macos" || target_arch != "aarch64" {
        panic!("cfw-tauri-shell supports only aarch64-apple-darwin");
    }

    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required"),
    );
    let repository_root = manifest_dir
        .ancestors()
        .nth(2)
        .expect("Tauri manifest must remain under apps/cfw-tauri-shell");
    println!(
        "cargo:rerun-if-changed={}",
        repository_root
            .join("native/macos/Dependencies.lock.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repository_root
            .join("scripts/dependency_pins.env")
            .display()
    );
    println!("cargo:rerun-if-env-changed={NATIVE_PRODUCTS_OUTPUT_ENV}");
    println!("cargo:rerun-if-env-changed={REPOSITORY_COMMIT_ENV}");
    println!("cargo:rerun-if-env-changed={RELEASE_SOURCE_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed={GO_TOOLCHAIN_TREE_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed={GO_TOOLS_TREE_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed={GO_MODULE_CACHE_TREE_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-changed=/var/db/xcode_select_link");
    let release_observation_log = manifest_dir.join("src/release_observation_log.c");
    println!(
        "cargo:rerun-if-changed={}",
        release_observation_log.display()
    );
    let macos_sdk = macos_sdk_root();
    let macos_sdk = macos_sdk
        .to_str()
        .expect("selected macOS SDK path must be valid UTF-8");
    let mut release_log = cc::Build::new();
    release_log
        .file(release_observation_log)
        .flag("-isysroot")
        .flag(macos_sdk)
        .warnings_into_errors(true)
        .compile("cfw_release_observation_log");

    if std::env::var("PROFILE").as_deref() == Ok("release") {
        verify_release_native_artifacts(repository_root)
            .unwrap_or_else(|error| panic!("native release artifact validation failed: {error}"));
    }
    tauri_build::build()
}

fn macos_sdk_root() -> PathBuf {
    let path = if let Some(sdk_root) = std::env::var_os("SDKROOT") {
        PathBuf::from(sdk_root)
    } else {
        let developer = if let Some(developer_dir) = std::env::var_os("DEVELOPER_DIR") {
            PathBuf::from(developer_dir)
        } else {
            fs::read_link("/var/db/xcode_select_link")
                .expect("xcode-select must identify an Xcode Developer directory")
        };
        developer.join("Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk")
    };
    let canonical = path
        .canonicalize()
        .expect("selected macOS SDK path must resolve without ambiguity");
    if !path.is_absolute()
        || !canonical.is_dir()
        || !canonical.join("usr/include/os/log.h").is_file()
        || !canonical.join("System/Library/Frameworks").is_dir()
    {
        panic!("selected macOS SDK is incomplete or noncanonical");
    }
    canonical
}

fn verify_release_native_artifacts(repository_root: &Path) -> Result<(), String> {
    reject_source_marker(
        &repository_root.join("apps/cfw-tauri-shell/src/engine.rs"),
        "MissingNativeBridge",
    )?;
    reject_source_marker(
        &repository_root.join("native/macos/Sources/CFWProxyAgent/ProxyAgentExecutable.swift"),
        "MissingLibboxProxyEngineFactory",
    )?;
    reject_source_marker(
        &repository_root.join("native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift"),
        "MissingLibboxEngineFactory",
    )?;
    reject_source_marker(
        &repository_root.join("native/macos/Sources/CFWAppleNetwork/HostBridge.swift"),
        "MissingSystemExtensionStateTransport",
    )?;
    reject_source_marker(
        &repository_root.join("native/macos/Sources/CFWPacketTunnel/PacketTunnelProvider.swift"),
        "systemExtensionStateTransportNotLinked",
    )?;
    require_real_directory(&repository_root.join("native/macos/Sources/CFWNativeBridge"))?;

    let dependency_lock_path = repository_root.join("native/macos/Dependencies.lock.json");
    let dependency_lock: NativeDependencyLock = read_json(&dependency_lock_path)?;
    let pins = read_pins(&repository_root.join("scripts/dependency_pins.env"))?;
    require_pin(&pins, "GO_VERSION", &dependency_lock.go)?;
    require_pin(&pins, "GOMOBILE_VERSION", &dependency_lock.gomobile)?;
    require_pin(&pins, "SING_BOX_VERSION", &dependency_lock.sing_box.tag)?;
    require_pin(&pins, "SING_BOX_COMMIT", &dependency_lock.sing_box.commit)?;
    require_pin(
        &pins,
        "SING_BOX_ANDROID_REFERENCE_COMMIT",
        &dependency_lock.sing_box.android_reference_commit,
    )?;
    require_pin(
        &pins,
        "SING_BOX_SECURITY_PATCH_PATH",
        &dependency_lock.sing_box.security_patch.path,
    )?;
    require_pin(
        &pins,
        "SING_BOX_SECURITY_PATCH_SHA256",
        &dependency_lock.sing_box.security_patch.sha256,
    )?;
    require_pin(
        &pins,
        "SING_BOX_RAW_PACKET_PATCH_PATH",
        &dependency_lock.sing_box.raw_packet_patch.path,
    )?;
    require_pin(
        &pins,
        "SING_BOX_RAW_PACKET_PATCH_SHA256",
        &dependency_lock.sing_box.raw_packet_patch.sha256,
    )?;
    require_pin(
        &pins,
        "SING_BOX_DNS_FAILOVER_PATCH_PATH",
        &dependency_lock.sing_box.dns_failover_patch.path,
    )?;
    require_pin(
        &pins,
        "SING_BOX_DNS_FAILOVER_PATCH_SHA256",
        &dependency_lock.sing_box.dns_failover_patch.sha256,
    )?;
    require_pin(
        &pins,
        "SING_BOX_ENDPOINT_CONFLICT_PATCH_PATH",
        &dependency_lock.sing_box.endpoint_conflict_patch.path,
    )?;
    require_pin(
        &pins,
        "SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
        &dependency_lock.sing_box.endpoint_conflict_patch.sha256,
    )?;
    require_pin(
        &pins,
        "SING_BOX_PATCHED_DIFF_SHA256",
        &dependency_lock.sing_box.security_patch.patched_diff_sha256,
    )?;
    require_pin(
        &pins,
        "SING_BOX_COMBINED_DIFF_SHA256",
        &dependency_lock.sing_box.combined_diff_sha256,
    )?;
    require_pin(
        &pins,
        "SING_BOX_PATCHED_GO_MOD_SHA256",
        &dependency_lock
            .sing_box
            .security_patch
            .patched_go_mod_sha256,
    )?;
    require_pin(
        &pins,
        "SING_BOX_PATCHED_GO_SUM_SHA256",
        &dependency_lock
            .sing_box
            .security_patch
            .patched_go_sum_sha256,
    )?;
    require_pin(
        &pins,
        "SING_BOX_APPLE_REFERENCE_COMMIT",
        &dependency_lock.sing_box_for_apple_reference.commit,
    )?;
    let security_patch_path = repository_root.join(safe_relative_path(
        &dependency_lock.sing_box.security_patch.path,
    )?);
    println!("cargo:rerun-if-changed={}", security_patch_path.display());
    require_regular_file(&security_patch_path)?;
    let security_patch = fs::read(&security_patch_path).map_err(|error| {
        format!(
            "read sing-box security patch {}: {error}",
            security_patch_path.display()
        )
    })?;
    if sha256_hex(&security_patch) != dependency_lock.sing_box.security_patch.sha256.as_str() {
        return Err("sing-box security patch digest differs from dependency lock".into());
    }
    let raw_packet_patch_path = repository_root.join(safe_relative_path(
        &dependency_lock.sing_box.raw_packet_patch.path,
    )?);
    println!("cargo:rerun-if-changed={}", raw_packet_patch_path.display());
    require_regular_file(&raw_packet_patch_path)?;
    let raw_packet_patch = fs::read(&raw_packet_patch_path).map_err(|error| {
        format!(
            "read sing-box raw packet patch {}: {error}",
            raw_packet_patch_path.display()
        )
    })?;
    if sha256_hex(&raw_packet_patch) != dependency_lock.sing_box.raw_packet_patch.sha256.as_str() {
        return Err("sing-box raw packet patch digest differs from dependency lock".into());
    }
    let dns_failover_patch_path = repository_root.join(safe_relative_path(
        &dependency_lock.sing_box.dns_failover_patch.path,
    )?);
    println!(
        "cargo:rerun-if-changed={}",
        dns_failover_patch_path.display()
    );
    require_regular_file(&dns_failover_patch_path)?;
    let dns_failover_patch = fs::read(&dns_failover_patch_path).map_err(|error| {
        format!(
            "read sing-box DNS failover patch {}: {error}",
            dns_failover_patch_path.display()
        )
    })?;
    if sha256_hex(&dns_failover_patch)
        != dependency_lock.sing_box.dns_failover_patch.sha256.as_str()
    {
        return Err("sing-box DNS failover patch digest differs from dependency lock".into());
    }
    let endpoint_conflict_patch_path = repository_root.join(safe_relative_path(
        &dependency_lock.sing_box.endpoint_conflict_patch.path,
    )?);
    println!(
        "cargo:rerun-if-changed={}",
        endpoint_conflict_patch_path.display()
    );
    require_regular_file(&endpoint_conflict_patch_path)?;
    let endpoint_conflict_patch = fs::read(&endpoint_conflict_patch_path).map_err(|error| {
        format!(
            "read sing-box endpoint conflict patch {}: {error}",
            endpoint_conflict_patch_path.display()
        )
    })?;
    if sha256_hex(&endpoint_conflict_patch)
        != dependency_lock
            .sing_box
            .endpoint_conflict_patch
            .sha256
            .as_str()
    {
        return Err("sing-box endpoint conflict patch digest differs from dependency lock".into());
    }

    let dependency_root = repository_root.join("target/native-dependencies");
    let framework = dependency_root.join("Libbox.xcframework");
    let manifest_path = dependency_root.join("Libbox.xcframework.manifest.json");
    let manifest: ArtifactManifest = read_json(&manifest_path)?;
    verify_manifest(&framework, &manifest)?;
    let libbox_manifest_sha256 = sha256_hex(
        &fs::read(&manifest_path)
            .map_err(|error| format!("read {}: {error}", manifest_path.display()))?,
    );
    require_metadata(&manifest, "sourceTag", &dependency_lock.sing_box.tag)?;
    require_metadata(&manifest, "sourceCommit", &dependency_lock.sing_box.commit)?;
    require_metadata(&manifest, "goVersion", &dependency_lock.go)?;
    require_metadata(&manifest, "gomobileVersion", &dependency_lock.gomobile)?;
    require_metadata(&manifest, "archiveDeterminism", "zeroArDate-v1")?;
    require_metadata(
        &manifest,
        "headerNormalization",
        "angleBracketFrameworkImports-v1",
    )?;
    for (metadata_key, pin_key) in [
        ("gomobileCommit", "GOMOBILE_COMMIT"),
        ("gomobileModuleSum", "GOMOBILE_MODULE_SUM"),
    ] {
        let expected = pins
            .get(pin_key)
            .ok_or_else(|| format!("required pin {pin_key} is missing"))?;
        require_metadata(&manifest, metadata_key, expected)?;
    }
    for (metadata_key, pin_key) in [
        ("platform", "LIBBOX_APPLE_PLATFORM"),
        ("buildTags", "LIBBOX_BUILD_TAGS"),
        ("nonMacOsTags", "LIBBOX_NON_MACOS_TAGS"),
        ("upstreamGoModSha256", "SING_BOX_UPSTREAM_GO_MOD_SHA256"),
        ("upstreamGoSumSha256", "SING_BOX_UPSTREAM_GO_SUM_SHA256"),
        ("securityPatchSha256", "SING_BOX_SECURITY_PATCH_SHA256"),
        ("rawPacketPatchSha256", "SING_BOX_RAW_PACKET_PATCH_SHA256"),
        (
            "dnsFailoverPatchSha256",
            "SING_BOX_DNS_FAILOVER_PATCH_SHA256",
        ),
        (
            "endpointConflictPatchSha256",
            "SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256",
        ),
        ("patchedDiffSha256", "SING_BOX_PATCHED_DIFF_SHA256"),
        ("combinedDiffSha256", "SING_BOX_COMBINED_DIFF_SHA256"),
        ("patchedGoModSha256", "SING_BOX_PATCHED_GO_MOD_SHA256"),
        ("patchedGoSumSha256", "SING_BOX_PATCHED_GO_SUM_SHA256"),
    ] {
        let expected = pins
            .get(pin_key)
            .ok_or_else(|| format!("required pin {pin_key} is missing"))?;
        require_metadata(&manifest, metadata_key, expected)?;
    }
    for (metadata_key, environment_key) in [
        ("goToolchainTreeSha256", GO_TOOLCHAIN_TREE_SHA256_ENV),
        ("goToolsTreeSha256", GO_TOOLS_TREE_SHA256_ENV),
        ("goModuleCacheTreeSha256", GO_MODULE_CACHE_TREE_SHA256_ENV),
    ] {
        let expected = required_lower_hex_environment(environment_key, 64)?;
        require_metadata(&manifest, metadata_key, &expected)?;
    }
    let expected_metadata_keys: BTreeSet<&str> = LIBBOX_METADATA_KEYS.into_iter().collect();
    let actual_metadata_keys: BTreeSet<&str> =
        manifest.metadata.keys().map(String::as_str).collect();
    if actual_metadata_keys != expected_metadata_keys {
        return Err("Libbox artifact metadata field set differs from the release contract".into());
    }

    let native_source_sha256 = native_build_inputs_digest(repository_root)?;
    let repository_commit = required_lower_hex_environment(REPOSITORY_COMMIT_ENV, 40)?;
    let release_source_sha256 = required_lower_hex_environment(RELEASE_SOURCE_SHA256_ENV, 64)?;
    let xcode_version = pins
        .get("XCODE_VERSION")
        .ok_or_else(|| "required pin XCODE_VERSION is missing".to_string())?;
    let xcode_build = pins
        .get("XCODE_BUILD_VERSION")
        .ok_or_else(|| "required pin XCODE_BUILD_VERSION is missing".to_string())?;
    let deployment_target = pins
        .get("MACOS_DEPLOYMENT_TARGET")
        .ok_or_else(|| "required pin MACOS_DEPLOYMENT_TARGET is missing".to_string())?;
    let products = candidate_native_products_root(repository_root)?;
    for (product, artifact_kind) in NATIVE_PRODUCTS {
        let product_path = products.join(product);
        let product_manifest_path = products.join(format!("{product}.manifest.json"));
        let product_manifest: ArtifactManifest = read_json(&product_manifest_path)?;
        verify_manifest(&product_path, &product_manifest)?;
        require_metadata(&product_manifest, "artifactKind", artifact_kind)?;
        require_metadata(
            &product_manifest,
            "singBoxCommit",
            &dependency_lock.sing_box.commit,
        )?;
        require_metadata(&product_manifest, "architecture", "arm64")?;
        require_metadata(&product_manifest, "configuration", "Release")?;
        require_metadata(&product_manifest, "deploymentTarget", deployment_target)?;
        require_metadata(
            &product_manifest,
            "libboxManifestSha256",
            &libbox_manifest_sha256,
        )?;
        require_metadata(&product_manifest, "libboxTreeSha256", &manifest.sha256)?;
        require_metadata(
            &product_manifest,
            "nativeSourceSha256",
            &native_source_sha256,
        )?;
        require_metadata(
            &product_manifest,
            "releaseSourceSha256",
            &release_source_sha256,
        )?;
        require_metadata(&product_manifest, "repositoryCommit", &repository_commit)?;
        require_metadata(&product_manifest, "xcodeVersion", xcode_version)?;
        require_metadata(&product_manifest, "xcodeBuild", xcode_build)?;
        match product_manifest
            .metadata
            .get("signingMode")
            .map(String::as_str)
        {
            Some("unsigned-validation" | "developer-id") => {}
            Some(value) => {
                return Err(format!("unsupported native product signing mode: {value}"));
            }
            None => return Err("native product signingMode metadata is missing".into()),
        }
    }
    let bridge_header = products.join("CFWNativeBridge.framework/Headers/CFWNativeBridge.h");
    require_regular_file(&bridge_header)?;
    let tombstone_root = products.join("CFWLegacyTombstone");
    let tombstone_manifest_path = products.join("CFWLegacyTombstone.manifest.json");
    let tombstone_manifest: ArtifactManifest = read_json(&tombstone_manifest_path)?;
    verify_manifest(&tombstone_root, &tombstone_manifest)?;
    require_metadata(
        &tombstone_manifest,
        "artifactKind",
        "legacy-service-tombstone-v1",
    )?;
    let rust_version = pins
        .get("RUST_VERSION")
        .ok_or_else(|| "required pin RUST_VERSION is missing".to_string())?;
    require_metadata(&tombstone_manifest, "rustVersion", rust_version)?;
    require_file_digest_metadata(
        &tombstone_manifest,
        "sourceSha256",
        &repository_root.join("crates/cfw-legacy-tombstone/src/main.rs"),
    )?;
    require_file_digest_metadata(
        &tombstone_manifest,
        "cargoManifestSha256",
        &repository_root.join("crates/cfw-legacy-tombstone/Cargo.toml"),
    )?;
    require_file_digest_metadata(
        &tombstone_manifest,
        "cargoLockSha256",
        &repository_root.join("Cargo.lock"),
    )?;
    let tombstone = tombstone_root.join("cfw-helper-tombstone");
    require_regular_file(&tombstone)?;
    reject_retired_helper_markers(&tombstone)?;
    require_regular_file(
        &repository_root
            .join("apps/cfw-tauri-shell/macos/legacy-tombstone/com.bill.clashformac.helper.plist"),
    )?;

    println!("cargo:rustc-link-search=framework={}", products.display());
    println!("cargo:rustc-link-lib=framework=CFWNativeBridge");
    // The host executable loads the bridge from the bundle it ships in
    // (Contents/Frameworks), never from the candidate build directory.
    println!("cargo:rustc-link-arg-bins=-Wl,-rpath,@executable_path/../Frameworks");
    Ok(())
}

/// Resolve the candidate-scoped native product root that the release build must
/// consume. The lane-exported `CFW_NATIVE_PRODUCTS_OUTPUT` is the only accepted
/// input: it must be an absolute path to a real directory named
/// `native-products` under `target/candidates/<version>/<lane>/`, and every
/// native product manifest must already be published there. A missing variable,
/// a non-candidate layout, or an incomplete product set fails the build.
fn candidate_native_products_root(repository_root: &Path) -> Result<PathBuf, String> {
    let version = std::env::var("CARGO_PKG_VERSION")
        .map_err(|error| format!("CARGO_PKG_VERSION is unavailable: {error}"))?;
    let candidate_root = repository_root.join(format!("target/candidates/{version}"));
    let declared = std::env::var_os(NATIVE_PRODUCTS_OUTPUT_ENV).ok_or_else(|| {
        format!(
            "{NATIVE_PRODUCTS_OUTPUT_ENV} is unset: a release build must be driven by \
             scripts/build_unsigned_candidate.sh or scripts/build_signed_candidate.sh, which \
             publish and export the immutable candidate native product root \
             {}/<lane>/native-products",
            candidate_root.display()
        )
    })?;
    let declared = PathBuf::from(declared);
    if !declared.is_absolute() {
        return Err(format!(
            "{NATIVE_PRODUCTS_OUTPUT_ENV} must be an absolute path, found {}",
            declared.display()
        ));
    }
    require_real_directory(&declared)?;
    let products = fs::canonicalize(&declared).map_err(|error| {
        format!(
            "resolve {NATIVE_PRODUCTS_OUTPUT_ENV} {}: {error}",
            declared.display()
        )
    })?;
    let candidate_root = fs::canonicalize(&candidate_root).map_err(|error| {
        format!(
            "resolve candidate root {}: {error}",
            candidate_root.display()
        )
    })?;
    let relative = products.strip_prefix(&candidate_root).map_err(|_| {
        format!(
            "{NATIVE_PRODUCTS_OUTPUT_ENV} must be candidate-scoped under {}, found {}",
            candidate_root.display(),
            products.display()
        )
    })?;
    let lane = relative.components().collect::<Vec<_>>();
    if lane.len() < 2
        || lane
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        || relative.file_name().and_then(|name| name.to_str()) != Some("native-products")
    {
        return Err(format!(
            "{NATIVE_PRODUCTS_OUTPUT_ENV} must name <lane>/native-products under {}, found {}",
            candidate_root.display(),
            products.display()
        ));
    }
    for (product, _) in NATIVE_PRODUCTS {
        let manifest_path = products.join(format!("{product}.manifest.json"));
        require_regular_file(&manifest_path).map_err(|error| {
            format!(
                "candidate native product root {} is incomplete: {error}",
                products.display()
            )
        })?;
    }
    Ok(products)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn read_pins(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let mut pins = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid pin at {}:{}", path.display(), index + 1))?;
        if key.is_empty() || value.is_empty() || pins.insert(key.into(), value.into()).is_some() {
            return Err(format!(
                "invalid or duplicate pin at {}:{}",
                path.display(),
                index + 1
            ));
        }
    }
    Ok(pins)
}

fn require_pin(pins: &BTreeMap<String, String>, key: &str, expected: &str) -> Result<(), String> {
    match pins.get(key).map(String::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("pin {key} is {actual}, expected {expected}")),
        None => Err(format!("required pin {key} is missing")),
    }
}

fn require_metadata(manifest: &ArtifactManifest, key: &str, expected: &str) -> Result<(), String> {
    match manifest.metadata.get(key).map(String::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!(
            "artifact metadata {key} is {actual}, expected {expected}"
        )),
        None => Err(format!("artifact metadata {key} is missing")),
    }
}

fn required_lower_hex_environment(name: &str, length: usize) -> Result<String, String> {
    let value =
        std::env::var(name).map_err(|_| format!("required release identity {name} is missing"))?;
    if value.len() != length
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(format!(
            "release identity {name} is not canonical lower hex"
        ));
    }
    Ok(value)
}

fn require_file_digest_metadata(
    manifest: &ArtifactManifest,
    key: &str,
    path: &Path,
) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    require_metadata(manifest, key, &sha256_hex(&bytes))
}

fn reject_retired_helper_markers(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    for marker in [
        b"mihomo".as_slice(),
        b"clash-rs".as_slice(),
        b"clash-darwin".as_slice(),
        b"CFW_CORE_KIND".as_slice(),
        b"core install".as_slice(),
        b"want_core".as_slice(),
    ] {
        if bytes.windows(marker.len()).any(|window| window == marker) {
            return Err(format!(
                "legacy tombstone contains retired supervisor marker: {}",
                String::from_utf8_lossy(marker)
            ));
        }
    }
    Ok(())
}

fn native_build_inputs_digest(repository_root: &Path) -> Result<String, String> {
    let mut relative_files = BTreeSet::new();
    for relative in [
        "native/macos/Config",
        "native/macos/Headers",
        "native/macos/Sources",
        "native/macos/SystemExtension",
        "native/macos/Dependencies.lock.json",
        "native/macos/Package.swift",
        "native/macos/project.yml",
    ] {
        collect_native_build_inputs(
            repository_root,
            &repository_root.join(relative),
            &mut relative_files,
        )?;
    }

    let mut digest = Sha256::new();
    for relative in relative_files {
        let path = repository_root.join(&relative);
        let bytes = fs::read(&path)
            .map_err(|error| format!("read native build input {}: {error}", path.display()))?;
        let mut entry = BTreeMap::new();
        entry.insert("path", serde_json::Value::String(relative));
        entry.insert("sha256", serde_json::Value::String(sha256_hex(&bytes)));
        entry.insert("size", serde_json::Value::from(bytes.len() as u64));
        let encoded = serde_json::to_string(&entry).map_err(|error| error.to_string())?;
        digest.update(encoded.as_bytes());
        digest.update(b"\n");
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn collect_native_build_inputs(
    repository_root: &Path,
    path: &Path,
    output: &mut BTreeSet<String>,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect native build input {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "native build input must not be a symlink: {}",
            path.display()
        ));
    }
    if metadata.file_type().is_file() {
        let relative = path
            .strip_prefix(repository_root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        if !output.insert(relative.clone()) {
            return Err(format!("duplicate native build input: {relative}"));
        }
        return Ok(());
    }
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "unsupported native build input: {}",
            path.display()
        ));
    }
    for entry in fs::read_dir(path)
        .map_err(|error| format!("enumerate native build input {}: {error}", path.display()))?
    {
        let entry = entry.map_err(|error| format!("enumerate native build input: {error}"))?;
        collect_native_build_inputs(repository_root, &entry.path(), output)?;
    }
    Ok(())
}

fn reject_source_marker(path: &Path, marker: &str) -> Result<(), String> {
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

fn verify_manifest(root: &Path, manifest: &ArtifactManifest) -> Result<(), String> {
    if manifest.algorithm != "sha256-tree-v1" {
        return Err(format!(
            "unsupported artifact algorithm: {}",
            manifest.algorithm
        ));
    }
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("artifact path has no name: {}", root.display()))?;
    if name != manifest.root.as_str() {
        return Err("artifact manifest root name mismatch".into());
    }
    let file_type = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect artifact {}: {error}", root.display()))?
        .file_type();

    // A bundle artifact hashes its tree relative to the bundle root. A bare
    // executable product, such as the launchd Global Authority daemon, is a
    // single-file artifact whose only entry is its own file name, so its entries
    // resolve against the containing directory.
    let (base, actual_paths) = if file_type.is_dir() && !file_type.is_symlink() {
        let mut paths = BTreeSet::new();
        collect_paths(root, root, &mut paths)?;
        (root.to_path_buf(), paths)
    } else if file_type.is_file() {
        let parent = root
            .parent()
            .ok_or_else(|| format!("artifact has no parent directory: {}", root.display()))?;
        (parent.to_path_buf(), BTreeSet::from([name.to_string()]))
    } else {
        return Err(format!(
            "artifact is neither a real directory nor a regular file: {}",
            root.display()
        ));
    };
    let manifest_paths = manifest
        .entries
        .iter()
        .map(|entry| entry.path().to_string())
        .collect::<BTreeSet<_>>();
    if manifest_paths.len() != manifest.entries.len() || manifest_paths != actual_paths {
        return Err("artifact entries differ from the signed tree manifest".into());
    }

    let mut tree_digest = Sha256::new();
    for entry in &manifest.entries {
        let relative = safe_relative_path(entry.path())?;
        let path = base.join(relative);
        let encoded = match entry {
            ArtifactEntry::Directory { path: relative } => {
                require_real_directory(&path)?;
                serde_json::json!({ "path": relative, "type": "directory" })
            }
            ArtifactEntry::File {
                path: relative,
                size,
                sha256,
            } => {
                require_regular_file(&path)?;
                let bytes = fs::read(&path)
                    .map_err(|error| format!("read artifact {}: {error}", path.display()))?;
                if bytes.len() as u64 != *size || sha256_hex(&bytes) != *sha256 {
                    return Err(format!("artifact file digest mismatch: {relative}"));
                }
                serde_json::json!({
                    "path": relative,
                    "sha256": sha256,
                    "size": size,
                    "type": "file",
                })
            }
            ArtifactEntry::Symlink {
                path: relative,
                target,
            } => {
                safe_symlink_target(target)?;
                let actual = fs::read_link(&path).map_err(|error| {
                    format!("read artifact symlink {}: {error}", path.display())
                })?;
                if actual != Path::new(target) {
                    return Err(format!("artifact symlink target mismatch: {relative}"));
                }
                serde_json::json!({ "path": relative, "target": target, "type": "symlink" })
            }
        };
        let line = serde_json::to_string(&encoded).map_err(|error| error.to_string())?;
        tree_digest.update(line.as_bytes());
        tree_digest.update(b"\n");
    }
    let actual_tree_digest = tree_digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual_tree_digest != manifest.sha256 {
        return Err("artifact tree digest mismatch".into());
    }
    Ok(())
}

fn safe_symlink_target(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe artifact symlink target: {value}"));
    }
    Ok(())
}

fn collect_paths(
    root: &Path,
    directory: &Path,
    output: &mut BTreeSet<String>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("enumerate artifact {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("enumerate artifact entry: {error}"))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        output.insert(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect artifact {}: {error}", path.display()))?;
        if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
            collect_paths(root, &path, output)?;
        }
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> Result<&Path, String> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe artifact manifest path: {value}"));
    }
    Ok(path)
}

fn require_real_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect required directory {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "required path is not a real directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect required file {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "required path is not a regular file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
