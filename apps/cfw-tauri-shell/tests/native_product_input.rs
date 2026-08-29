#[path = "../build_support/native_product_input.rs"]
mod native_product_input;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};

use native_product_input::{
    CandidateNativeProducts, NativeProductContext, require_single_link_regular_file,
    require_utf8_relative_artifact_path,
};
use tempfile::TempDir;

const ARTIFACTS: [&str; 5] = [
    "CFWGlobalAuthority",
    "CFWNativeBridge.framework",
    "CFWProxyAgent.app",
    "com.bill.clashformac.packet-tunnel.systemextension",
    "CFWLegacyTombstone",
];

struct CandidateFixture {
    _temporary: TempDir,
    candidate_root: PathBuf,
}

impl CandidateFixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("create candidate fixture");
        let canonical_temporary = fs::canonicalize(temporary.path()).expect("resolve fixture root");
        let candidate_root = canonical_temporary.join("target/candidates/0.4.0");
        fs::create_dir_all(candidate_root.join("unsigned/native-products"))
            .expect("create unsigned candidate root");
        fs::create_dir_all(candidate_root.join("ga-preflight/40036/native-products"))
            .expect("create GA pre-sign candidate root");
        Self {
            _temporary: temporary,
            candidate_root,
        }
    }

    fn output(&self, relative: &str) -> String {
        self.candidate_root
            .join(relative)
            .to_str()
            .expect("fixture path is UTF-8")
            .to_string()
    }
}

fn metadata(build_number: &str, signing_mode: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("buildNumber".to_string(), build_number.to_string()),
        ("signingMode".to_string(), signing_mode.to_string()),
    ])
}

#[test]
fn exact_candidate_roots_select_one_context() {
    let fixture = CandidateFixture::new();
    let unsigned = CandidateNativeProducts::resolve(
        &fixture.candidate_root,
        &fixture.output("unsigned/native-products"),
        "40000",
    )
    .expect("resolve unsigned candidate");
    assert_eq!(unsigned.context, NativeProductContext::UnsignedValidation);
    assert_eq!(
        unsigned.context.expected_signing_mode(),
        "unsigned-validation"
    );
    assert_eq!(unsigned.context.expected_build_number(), "40000");

    let ga = CandidateNativeProducts::resolve(
        &fixture.candidate_root,
        &fixture.output("ga-preflight/40036/native-products"),
        "40036",
    )
    .expect("resolve GA pre-sign candidate");
    assert_eq!(ga.context, NativeProductContext::GaPreSign);
    assert_eq!(ga.context.expected_signing_mode(), "pre-sign");
    assert_eq!(ga.context.expected_build_number(), "40036");
}

#[test]
fn candidate_root_and_build_number_must_match_exactly() {
    let fixture = CandidateFixture::new();
    for (relative, build_number) in [
        ("unsigned/native-products", "40036"),
        ("ga-preflight/40036/native-products", "40000"),
        ("ga-preflight/40036/native-products", "040036"),
        ("ga-preflight/40036/native-products", "0"),
        ("ga-preflight/40036/native-products", "not-a-build"),
        ("ga-preflight/40036/native-products", "9223372036854775808"),
    ] {
        let error = CandidateNativeProducts::resolve(
            &fixture.candidate_root,
            &fixture.output(relative),
            build_number,
        )
        .expect_err("reject mismatched candidate build");
        assert!(error.contains("candidate build number"), "{error}");
    }
}

#[test]
fn unapproved_or_noncanonical_candidate_paths_are_rejected() {
    let fixture = CandidateFixture::new();
    for declared in [
        fixture.output("validation/40036/native-products"),
        fixture.output("release-build/40036/native-products"),
        fixture.output("ga-preflight/40030/native-products"),
        fixture.output("ga-preflight/40031/native-products"),
        fixture.output("ga-preflight/40032/native-products"),
        fixture.output("ga-preflight/40033/native-products"),
        fixture.output("ga-preflight/40034/native-products"),
        fixture.output("ga-preflight/40035/native-products"),
        fixture.output("ga/40036/signing-output/signed-native-products"),
        fixture.output("ga-preflight/40036/native-products/extra"),
        format!(
            "{}/ga-preflight//40036/native-products",
            fixture.candidate_root.display()
        ),
        format!(
            "{}/ga-preflight/../ga-preflight/40036/native-products",
            fixture.candidate_root.display()
        ),
        "ga-preflight/40036/native-products".to_string(),
    ] {
        let error = CandidateNativeProducts::resolve(&fixture.candidate_root, &declared, "40036")
            .expect_err("reject unapproved candidate path");
        assert!(error.contains("must be exactly"), "{error}");
    }
}

#[test]
fn symlinked_candidate_component_is_rejected() {
    let temporary = tempfile::tempdir().expect("create symlink fixture");
    let root = fs::canonicalize(temporary.path()).expect("resolve fixture root");
    let candidate_root = root.join("target/candidates/0.4.0");
    let real_unsigned = root.join("real-unsigned/native-products");
    fs::create_dir_all(&candidate_root).expect("create candidate root");
    fs::create_dir_all(&real_unsigned).expect("create real output");
    std::os::unix::fs::symlink(
        real_unsigned.parent().expect("real output has parent"),
        candidate_root.join("unsigned"),
    )
    .expect("create lane symlink");
    let declared = candidate_root.join("unsigned/native-products");
    let error = CandidateNativeProducts::resolve(
        &candidate_root,
        declared.to_str().expect("fixture path is UTF-8"),
        "40000",
    )
    .expect_err("reject symlinked candidate component");
    assert!(error.contains("real directory"), "{error}");
}

#[test]
fn every_artifact_uses_the_context_identity() {
    for (context, good, bad) in [
        (
            NativeProductContext::UnsignedValidation,
            metadata("40000", "unsigned-validation"),
            metadata("40036", "pre-sign"),
        ),
        (
            NativeProductContext::GaPreSign,
            metadata("40036", "pre-sign"),
            metadata("40000", "unsigned-validation"),
        ),
    ] {
        for artifact in ARTIFACTS {
            context
                .require_manifest_identity(&good, artifact)
                .expect("accept matching manifest identity");
            let error = context
                .require_manifest_identity(&bad, artifact)
                .expect_err("reject mixed manifest identity");
            assert!(error.contains(artifact), "{error}");
        }
    }
}

#[test]
fn missing_unknown_and_developer_id_metadata_are_rejected() {
    for artifact in ARTIFACTS {
        for invalid in [
            metadata("40036", "developer-id"),
            metadata("40036", ""),
            metadata("40036", "unknown"),
            metadata("40030", "pre-sign"),
            metadata("40031", "pre-sign"),
            metadata("40032", "pre-sign"),
            metadata("40033", "pre-sign"),
            metadata("40034", "pre-sign"),
            metadata("40035", "pre-sign"),
        ] {
            let error = NativeProductContext::GaPreSign
                .require_manifest_identity(&invalid, artifact)
                .expect_err("reject wrong manifest identity");
            assert!(error.contains(artifact), "{error}");
        }

        let mut missing_build = metadata("40036", "pre-sign");
        missing_build.remove("buildNumber");
        let error = NativeProductContext::GaPreSign
            .require_manifest_identity(&missing_build, artifact)
            .expect_err("reject missing build number");
        assert!(error.contains("buildNumber"), "{error}");

        let mut missing_mode = metadata("40036", "pre-sign");
        missing_mode.remove("signingMode");
        let error = NativeProductContext::GaPreSign
            .require_manifest_identity(&missing_mode, artifact)
            .expect_err("reject missing signing mode");
        assert!(error.contains("signingMode"), "{error}");
    }
}

#[test]
fn regular_release_inputs_must_not_be_symlinks_or_hardlinks() {
    let temporary = tempfile::tempdir().expect("create file fixture");
    let regular = temporary.path().join("manifest.json");
    fs::write(&regular, b"{}").expect("write regular fixture");
    require_single_link_regular_file(&regular).expect("accept single-link regular file");

    let hardlink = temporary.path().join("manifest-hardlink.json");
    fs::hard_link(&regular, &hardlink).expect("create hardlink fixture");
    let error = require_single_link_regular_file(&regular).expect_err("reject hardlinked file");
    assert!(error.contains("single-link regular file"), "{error}");

    fs::remove_file(&hardlink).expect("remove hardlink fixture");
    let symlink = temporary.path().join("manifest-symlink.json");
    std::os::unix::fs::symlink(Path::new("manifest.json"), &symlink)
        .expect("create symlink fixture");
    let error = require_single_link_regular_file(&symlink).expect_err("reject symlinked file");
    assert!(error.contains("single-link regular file"), "{error}");
}

#[test]
fn artifact_entry_paths_must_be_exact_utf8() {
    let temporary = tempfile::tempdir().expect("create path fixture");
    let root = fs::canonicalize(temporary.path()).expect("resolve path fixture");
    let utf8 = root.join("CFWNativeBridge.framework/Versions/A");
    assert_eq!(
        require_utf8_relative_artifact_path(&root, &utf8).expect("accept UTF-8 artifact path"),
        "CFWNativeBridge.framework/Versions/A"
    );

    let non_utf8 = root.join(OsString::from_vec(b"artifact-\x80".to_vec()));
    let error = require_utf8_relative_artifact_path(&root, &non_utf8)
        .expect_err("reject non-UTF-8 artifact path");
    assert_eq!(error, "artifact entry path is not valid UTF-8");
}
