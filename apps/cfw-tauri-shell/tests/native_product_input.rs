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

#[test]
fn ga_apple_identity_stays_pinned_and_refuses_every_validation_selection() {
    let pinned = ("27.0", "27A266a");
    assert_eq!(
        NativeProductContext::GaPreSign
            .expected_apple_identity(pinned, (None, None), None)
            .unwrap(),
        pinned
    );
    for selection in [
        (Some("27.0"), Some("27A5252f")),
        (Some("27.0"), Some("27A266a")),
        (Some(""), None),
    ] {
        assert!(
            NativeProductContext::GaPreSign
                .expected_apple_identity(pinned, selection, Some("/toolchain/python3"))
                .is_err()
        );
    }
    assert!(
        NativeProductContext::GaPreSign
            .expected_apple_identity(pinned, (None, None), Some("/toolchain/python3"))
            .is_err()
    );
}

#[test]
fn unsigned_apple_identity_accepts_the_explicit_hosted_version() {
    let context = NativeProductContext::UnsignedValidation;
    let pinned = ("27.0", "27A266a");
    assert_eq!(
        context
            .expected_apple_identity(pinned, (None, None), None)
            .unwrap(),
        pinned
    );
    for expected in [
        ("27.0", "27A5252f"),
        ("26.4", "17E133"),
        ("27.1", "27B5032a"),
    ] {
        assert_eq!(
            context
                .expected_apple_identity(
                    pinned,
                    (Some(expected.0), Some(expected.1)),
                    Some("/toolchain/python3")
                )
                .unwrap(),
            expected
        );
    }
}

#[test]
fn unsigned_apple_identity_rejects_partial_or_malformed_selection() {
    let context = NativeProductContext::UnsignedValidation;
    let pinned = ("27.0", "27A266a");
    for selected in [
        (Some("27.0"), None),
        (None, Some("27A5252f")),
        (Some("27.0\n"), Some("27A5252f")),
        (Some("27"), Some("27A5252f")),
        (Some("27.0"), Some("27A5252f\n")),
        (Some("27.0"), Some("27AB5252")),
    ] {
        assert!(
            context
                .expected_apple_identity(pinned, selected, Some("/toolchain/python3"))
                .is_err()
        );
    }
    for python in [None, Some("python3"), Some("/bad\0path")] {
        assert!(
            context
                .expected_apple_identity(pinned, (Some("27.0"), Some("27A5252f")), python)
                .is_err()
        );
    }
}

/// Neutral GA builds. The resolver derives the GA pre-sign root from the
/// declared build, so no test names the active allocation.
const FIXTURE_BUILD: &str = "70001";
const OTHER_BUILD: &str = "70002";

fn ga_pre_sign_relative(build: &str) -> String {
    format!("ga-preflight/{build}/native-products")
}

struct CandidateFixture {
    _temporary: TempDir,
    candidate_root: PathBuf,
}

impl CandidateFixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("create candidate fixture");
        let canonical_temporary = fs::canonicalize(temporary.path()).expect("resolve fixture root");
        let candidate_root =
            canonical_temporary.join(concat!("target/candidates/", env!("CARGO_PKG_VERSION")));
        for relative in [
            "unsigned/native-products".to_owned(),
            ga_pre_sign_relative(FIXTURE_BUILD),
            ga_pre_sign_relative(OTHER_BUILD),
        ] {
            fs::create_dir_all(candidate_root.join(relative)).expect("create candidate root");
        }
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

    fn unsigned_products(&self) -> CandidateNativeProducts {
        CandidateNativeProducts::resolve(
            &self.candidate_root,
            &self.output("unsigned/native-products"),
            "40000",
        )
        .expect("resolve unsigned candidate")
    }

    fn ga_products(&self, build: &str) -> CandidateNativeProducts {
        CandidateNativeProducts::resolve(
            &self.candidate_root,
            &self.output(&ga_pre_sign_relative(build)),
            build,
        )
        .expect("resolve GA pre-sign candidate")
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
    let unsigned = fixture.unsigned_products();
    assert_eq!(unsigned.context, NativeProductContext::UnsignedValidation);
    assert_eq!(unsigned.build_number(), "40000");
    assert_eq!(
        unsigned.context.expected_signing_mode(),
        "unsigned-validation"
    );
    unsigned
        .require_manifest_identity(&metadata("40000", "unsigned-validation"), "UI")
        .expect("accept the unsigned validation identity");

    // Each GA pre-sign root admits exactly the build it is named after.
    for build in [FIXTURE_BUILD, OTHER_BUILD] {
        let ga = fixture.ga_products(build);
        assert_eq!(ga.context, NativeProductContext::GaPreSign);
        assert_eq!(ga.build_number(), build);
        assert_eq!(ga.context.expected_signing_mode(), "pre-sign");
        ga.require_manifest_identity(&metadata(build, "pre-sign"), "UI")
            .expect("accept the GA pre-sign identity");
    }
}

#[test]
fn candidate_root_and_build_number_must_match_exactly() {
    let fixture = CandidateFixture::new();
    let ga = ga_pre_sign_relative(FIXTURE_BUILD);
    let leading_zero = format!("0{FIXTURE_BUILD}");
    for (relative, build_number) in [
        ("unsigned/native-products", FIXTURE_BUILD),
        (ga.as_str(), "40000"),
        (ga.as_str(), OTHER_BUILD),
        (ga.as_str(), leading_zero.as_str()),
        (ga.as_str(), "0"),
        (ga.as_str(), ""),
        (ga.as_str(), "not-a-build"),
        (ga.as_str(), "9223372036854775808"),
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
    let root = fixture.candidate_root.display();
    for declared in [
        fixture.output("validation/40073/native-products"),
        fixture.output("release-build/40073/native-products"),
        fixture.output("ga/40073/signing-output/signed-native-products"),
        fixture.output(&format!(
            "ga/{FIXTURE_BUILD}/signing-output/signed-native-products"
        )),
        fixture.output(&format!("{}/extra", ga_pre_sign_relative(FIXTURE_BUILD))),
        fixture.output(&ga_pre_sign_relative(&format!("0{FIXTURE_BUILD}"))),
        fixture.output(&ga_pre_sign_relative(&format!("+{FIXTURE_BUILD}"))),
        fixture.output(&ga_pre_sign_relative("0")),
        fixture.output(&ga_pre_sign_relative("not-a-build")),
        fixture.output(&ga_pre_sign_relative("9223372036854775808")),
        format!("{root}/ga-preflight//{FIXTURE_BUILD}/native-products"),
        format!("{root}/ga-preflight/../ga-preflight/{FIXTURE_BUILD}/native-products"),
        format!("{root}/ga-preflight/{FIXTURE_BUILD}/../{FIXTURE_BUILD}/native-products"),
        ga_pre_sign_relative(FIXTURE_BUILD),
    ] {
        let error =
            CandidateNativeProducts::resolve(&fixture.candidate_root, &declared, FIXTURE_BUILD)
                .expect_err("reject unapproved candidate path");
        assert!(error.contains("must be exactly"), "{error}");
    }
}

#[test]
fn a_noncanonical_root_is_rejected_even_when_it_names_the_declared_build() {
    let fixture = CandidateFixture::new();
    for build in [
        format!("0{FIXTURE_BUILD}"),
        format!("+{FIXTURE_BUILD}"),
        "9223372036854775808".to_owned(),
    ] {
        let relative = ga_pre_sign_relative(&build);
        fs::create_dir_all(fixture.candidate_root.join(&relative))
            .expect("create noncanonical candidate root");
        let error = CandidateNativeProducts::resolve(
            &fixture.candidate_root,
            &fixture.output(&relative),
            &build,
        )
        .expect_err("reject noncanonical GA root");
        assert!(error.contains("must be exactly"), "{build}: {error}");
    }
}

#[test]
fn the_largest_signed_64_bit_build_is_a_ga_root() {
    let fixture = CandidateFixture::new();
    let build = "9223372036854775807";
    fs::create_dir_all(fixture.candidate_root.join(ga_pre_sign_relative(build)))
        .expect("create upper-bound candidate root");
    let products = fixture.ga_products(build);
    assert_eq!(products.context, NativeProductContext::GaPreSign);
    products
        .require_manifest_identity(&metadata(build, "pre-sign"), "UI")
        .expect("accept the upper-bound identity");
}

#[test]
fn a_ga_root_aliasing_another_build_is_rejected() {
    let fixture = CandidateFixture::new();
    let alias = fixture.candidate_root.join("ga-preflight/70003");
    std::os::unix::fs::symlink(
        fixture
            .candidate_root
            .join(format!("ga-preflight/{OTHER_BUILD}")),
        &alias,
    )
    .expect("create aliasing build root");
    let error = CandidateNativeProducts::resolve(
        &fixture.candidate_root,
        &fixture.output(&ga_pre_sign_relative("70003")),
        "70003",
    )
    .expect_err("reject aliased GA root");
    assert!(error.contains("real directory"), "{error}");
}

#[test]
fn symlinked_candidate_component_is_rejected() {
    let temporary = tempfile::tempdir().expect("create symlink fixture");
    let root = fs::canonicalize(temporary.path()).expect("resolve fixture root");
    let candidate_root = root.join(concat!("target/candidates/", env!("CARGO_PKG_VERSION")));
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
fn every_artifact_uses_the_resolved_identity() {
    let fixture = CandidateFixture::new();
    for (products, good, bad) in [
        (
            fixture.unsigned_products(),
            metadata("40000", "unsigned-validation"),
            [
                metadata(FIXTURE_BUILD, "pre-sign"),
                metadata(FIXTURE_BUILD, "unsigned-validation"),
            ],
        ),
        (
            fixture.ga_products(FIXTURE_BUILD),
            metadata(FIXTURE_BUILD, "pre-sign"),
            [
                metadata("40000", "unsigned-validation"),
                metadata(OTHER_BUILD, "pre-sign"),
            ],
        ),
    ] {
        for artifact in ARTIFACTS {
            products
                .require_manifest_identity(&good, artifact)
                .expect("accept matching manifest identity");
            for mixed in &bad {
                let error = products
                    .require_manifest_identity(mixed, artifact)
                    .expect_err("reject mixed manifest identity");
                assert!(error.contains(artifact), "{error}");
            }
        }
    }
}

#[test]
fn missing_unknown_and_developer_id_metadata_are_rejected() {
    let fixture = CandidateFixture::new();
    let ga = fixture.ga_products(FIXTURE_BUILD);
    let leading_zero = format!("0{FIXTURE_BUILD}");
    for artifact in ARTIFACTS {
        for invalid in [
            metadata(FIXTURE_BUILD, "developer-id"),
            metadata(FIXTURE_BUILD, ""),
            metadata(FIXTURE_BUILD, "unknown"),
            metadata(FIXTURE_BUILD, "unsigned-validation"),
            metadata(OTHER_BUILD, "pre-sign"),
            metadata(&leading_zero, "pre-sign"),
            metadata("40000", "pre-sign"),
            metadata("", "pre-sign"),
        ] {
            let error = ga
                .require_manifest_identity(&invalid, artifact)
                .expect_err("reject wrong manifest identity");
            assert!(error.contains(artifact), "{error}");
        }

        let mut missing_build = metadata(FIXTURE_BUILD, "pre-sign");
        missing_build.remove("buildNumber");
        let error = ga
            .require_manifest_identity(&missing_build, artifact)
            .expect_err("reject missing build number");
        assert!(error.contains("buildNumber"), "{error}");

        let mut missing_mode = metadata(FIXTURE_BUILD, "pre-sign");
        missing_mode.remove("signingMode");
        let error = ga
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
