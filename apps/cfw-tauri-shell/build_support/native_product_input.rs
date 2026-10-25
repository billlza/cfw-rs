use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Cargo's DEP_* metadata can contain names that Bash cannot represent (for
/// example Tauri permission keys containing ':'). Pass only the release inputs
/// the verifier consumes, then let its normal production seal validate them.
pub fn native_ui_verifier_command(
    script: &Path,
    environment: impl IntoIterator<Item = (OsString, OsString)>,
    context: NativeProductContext,
) -> Command {
    const INPUTS: &[&str] = &[
        "CFW_BUILD_NUMBER",
        "CFW_NATIVE_PRODUCTS_OUTPUT",
        "CFW_RELEASE_RUST_TOOLCHAIN",
        "CFW_TOOLCHAIN_ROOT",
        "CFW_REPOSITORY_COMMIT",
        "CFW_RELEASE_SOURCE_SHA256",
        "DEVELOPER_DIR",
        // Preserve explicit refusal of validation-only compiler selections.
        "CFW_UNSIGNED_VALIDATION_PYTHON",
        "CFW_UNSIGNED_VALIDATION_XCODE_VERSION",
        "CFW_UNSIGNED_VALIDATION_XCODE_BUILD_VERSION",
    ];
    let mut command = Command::new("/bin/bash");
    command.arg("-p").arg(script).arg("--verify");
    match context {
        NativeProductContext::GaPreSign => {
            command.arg("--release");
        }
        NativeProductContext::UnsignedPreviewValidation => {
            command.arg("--unsigned-preview-validation");
        }
        NativeProductContext::UnsignedValidation => {}
    }
    command.env_clear().envs(
        environment
            .into_iter()
            .filter(|(key, _)| key.to_str().is_some_and(|name| INPUTS.contains(&name))),
    );
    command
}

const UNSIGNED_RELATIVE_ROOT: &str = "unsigned/native-products";
const UNSIGNED_BUILD_NUMBER: &str = "40000";
const UNSIGNED_SIGNING_MODE: &str = "unsigned-validation";
/// The GA pre-sign root is `ga-preflight/<build>/native-products`. The signed
/// builder derives that build from the release identity and exports it as
/// CFW_BUILD_NUMBER, so the root names exactly the declared build.
const GA_PRE_SIGN_ROOT_PREFIX: &str = "ga-preflight/";
const GA_PRE_SIGN_ROOT_SUFFIX: &str = "/native-products";
const GA_PRE_SIGNING_MODE: &str = "pre-sign";
/// The GA pre-sign output and the unsigned validation outputs share the one
/// product version; the three are told apart by their exact relative roots.
/// The crate version is that product version: the version contract binds it
/// to the release identity.
const CANDIDATE_ROOT: &str = concat!("target/candidates/", env!("CARGO_PKG_VERSION"));
const UNSIGNED_PREVIEW_RELATIVE_ROOT: &str = "unsigned/50000/native-products";
const UNSIGNED_PREVIEW_BUILD_NUMBER: &str = "50000";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProductContext {
    UnsignedValidation,
    UnsignedPreviewValidation,
    GaPreSign,
}

impl NativeProductContext {
    /// Hosted Xcode selection belongs only to the non-distributable unsigned
    /// validation contexts. GA inputs retain the production pins.
    pub fn expected_apple_identity<'a>(
        self,
        pinned: (&'a str, &'a str),
        selected: (Option<&'a str>, Option<&'a str>),
        validation_python: Option<&str>,
    ) -> Result<(&'a str, &'a str), String> {
        if self == Self::GaPreSign {
            if selected.0.is_some() || selected.1.is_some() || validation_python.is_some() {
                return Err(
                    "GA native inputs refuse unsigned-validation toolchain selection".into(),
                );
            }
            return Ok(pinned);
        }
        let (version, build) = match selected {
            (None, None) => return Ok(pinned),
            (Some(version), Some(build)) => (version, build),
            _ => return Err("unsigned-validation Apple identity is incomplete".into()),
        };
        let python = validation_python
            .filter(|value| Path::new(value).is_absolute() && !value.contains('\0'))
            .ok_or("unsigned-validation Apple identity requires its explicit Python runtime")?;
        if python.len() > 4096 || version.len() > 64 || build.len() > 64 {
            return Err("unsigned-validation Apple identity exceeds its bound".into());
        }
        let version_parts: Vec<_> = version.split('.').collect();
        let decimal =
            |value: &str| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
        let build_number = build
            .strip_suffix(|character: char| character.is_ascii_lowercase())
            .unwrap_or(build);
        let build_parts: Vec<_> = build_number
            .split(|character: char| character.is_ascii_uppercase())
            .collect();
        if !(2..=3).contains(&version_parts.len())
            || !version_parts.iter().all(|part| decimal(part))
            || build_parts.len() != 2
            || !build_parts.iter().all(|part| decimal(part))
        {
            return Err("unsigned-validation Apple identity is not canonical".into());
        }
        Ok((version, build))
    }

    pub const fn expected_signing_mode(self) -> &'static str {
        match self {
            Self::UnsignedValidation | Self::UnsignedPreviewValidation => UNSIGNED_SIGNING_MODE,
            Self::GaPreSign => GA_PRE_SIGNING_MODE,
        }
    }
}

/// One resolved native product root and the identity every manifest in it
/// must carry: the build its root names and the signing mode of its context.
#[derive(Debug, Eq, PartialEq)]
pub struct CandidateNativeProducts {
    pub root: PathBuf,
    pub context: NativeProductContext,
    build_number: String,
}

impl CandidateNativeProducts {
    pub fn resolve(
        candidate_root: &Path,
        declared_output: &str,
        declared_build_number: &str,
    ) -> Result<Self, String> {
        if !candidate_root.is_absolute() {
            return Err(format!(
                "candidate root must be absolute: {}",
                candidate_root.display()
            ));
        }
        let candidate_root_text = candidate_root
            .to_str()
            .ok_or_else(|| "candidate root must be valid UTF-8".to_string())?;
        if candidate_root_text
            .split('/')
            .skip(1)
            .any(|part| matches!(part, "" | "." | ".."))
        {
            return Err("candidate root must be a canonical absolute path".into());
        }
        let unsigned = format!("{candidate_root_text}/{UNSIGNED_RELATIVE_ROOT}");
        let ga_pre_sign_prefix = format!("{candidate_root_text}/{GA_PRE_SIGN_ROOT_PREFIX}");
        let unsigned_preview = format!("{candidate_root_text}/{UNSIGNED_PREVIEW_RELATIVE_ROOT}");
        if !candidate_root.ends_with(CANDIDATE_ROOT) {
            return Err(format!(
                "candidate root must end with {CANDIDATE_ROOT}: {candidate_root_text}"
            ));
        }
        let (context, expected_build_number) = if declared_output == unsigned {
            (
                NativeProductContext::UnsignedValidation,
                UNSIGNED_BUILD_NUMBER,
            )
        } else if declared_output == unsigned_preview {
            (
                NativeProductContext::UnsignedPreviewValidation,
                UNSIGNED_PREVIEW_BUILD_NUMBER,
            )
        } else if let Some(build_number) = declared_output
            .strip_prefix(&ga_pre_sign_prefix)
            .and_then(|rest| rest.strip_suffix(GA_PRE_SIGN_ROOT_SUFFIX))
            .filter(|build_number| is_canonical_build_number(build_number))
        {
            (NativeProductContext::GaPreSign, build_number)
        } else {
            return Err(format!(
                "candidate native-products output must be exactly {unsigned}, {ga_pre_sign_prefix}<build>{GA_PRE_SIGN_ROOT_SUFFIX} or {unsigned_preview}, found {declared_output}"
            ));
        };
        if declared_build_number != expected_build_number {
            return Err(format!(
                "candidate build number is {declared_build_number}, expected {expected_build_number} for {declared_output}"
            ));
        }

        let root = PathBuf::from(declared_output);
        require_canonical_real_directory(candidate_root, &root)?;
        Ok(Self {
            root,
            context,
            build_number: expected_build_number.to_owned(),
        })
    }

    /// The build number this root names and every manifest in it carries.
    pub fn build_number(&self) -> &str {
        &self.build_number
    }

    /// Requires one native manifest to carry this root's build and the
    /// signing mode of its context.
    pub fn require_manifest_identity(
        &self,
        metadata: &BTreeMap<String, String>,
        artifact: &str,
    ) -> Result<(), String> {
        require_metadata(metadata, artifact, "buildNumber", &self.build_number)?;
        require_metadata(
            metadata,
            artifact,
            "signingMode",
            self.context.expected_signing_mode(),
        )
    }
}

/// One canonical positive decimal within the signed 64-bit bound that the
/// release identity and Apple bundle versions share.
fn is_canonical_build_number(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<i64>().is_ok()
}

pub fn require_single_link_regular_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect required file {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1
    {
        return Err(format!(
            "required path is not a single-link regular file: {}",
            path.display()
        ));
    }
    Ok(())
}

pub fn require_utf8_relative_artifact_path(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "artifact entry must be below the product root: {}",
            path.display()
        )
    })?;
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "artifact entry path is not valid UTF-8".to_owned())
}

fn require_canonical_real_directory(candidate_root: &Path, output: &Path) -> Result<(), String> {
    let relative = output.strip_prefix(candidate_root).map_err(|_| {
        format!(
            "candidate native-products output must be under {}, found {}",
            candidate_root.display(),
            output.display()
        )
    })?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "candidate native-products output is not canonical: {}",
            output.display()
        ));
    }

    let mut current = candidate_root.to_path_buf();
    require_real_directory(&current)?;
    for component in relative.components() {
        current.push(component.as_os_str());
        require_real_directory(&current)?;
    }
    for path in [candidate_root, output] {
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("resolve candidate directory {}: {error}", path.display()))?;
        if canonical != path {
            return Err(format!(
                "candidate directory must be canonical: {} resolves to {}",
                path.display(),
                canonical.display()
            ));
        }
    }
    Ok(())
}

pub fn require_real_directory(path: &Path) -> Result<(), String> {
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

fn require_metadata(
    metadata: &BTreeMap<String, String>,
    artifact: &str,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    match metadata.get(key).map(String::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!(
            "{artifact} metadata {key} is {actual}, expected {expected}"
        )),
        None => Err(format!("{artifact} metadata {key} is missing")),
    }
}

#[cfg(test)]
mod candidate_input_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    /// Neutral GA builds: the GA pre-sign root is derived from the declared
    /// build, so no test names the active allocation.
    const FIXTURE_BUILD: &str = "70001";
    const OTHER_BUILD: &str = "70002";
    const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

    fn ga_pre_sign_relative(build: &str) -> String {
        format!("ga-preflight/{build}/native-products")
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical temp directory");
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = parent.join(format!(
                "cfm-native-input-test-{}-{nonce}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("exclusive fixture directory");
            Self(path)
        }

        fn root(&self, version: &str) -> PathBuf {
            self.0.join("target/candidates").join(version)
        }

        fn output(&self, version: &str, relative: &str) -> String {
            let path = self.root(version).join(relative);
            fs::create_dir_all(&path).expect("fixture candidate structure");
            path.to_str().expect("UTF-8 fixture").to_owned()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove owned test fixture");
        }
    }

    #[test]
    fn native_ui_verifier_does_not_inherit_cargo_or_loader_environment() {
        let environment = [
            ("CFW_BUILD_NUMBER", FIXTURE_BUILD),
            ("CFW_NATIVE_PRODUCTS_OUTPUT", "/candidate/native-products"),
            ("CFW_RELEASE_RUST_TOOLCHAIN", "private"),
            ("CFW_UNSIGNED_VALIDATION_XCODE_VERSION", "reject-me"),
            (
                "DEP_TAURI_CORE:MENU__CORE_PLUGIN___PERMISSION_FILES_PATH",
                "/permissions",
            ),
            ("CARGO_HOME", "/unrelated-cargo"),
            ("BASH_ENV", "/injected-shell"),
            ("DYLD_INSERT_LIBRARIES", "/injected-library"),
            ("PATH", "/injected-path"),
        ];
        let command = native_ui_verifier_command(
            Path::new("/repo/scripts/build_native_ui.sh"),
            environment.map(|(key, value)| (key.into(), value.into())),
            NativeProductContext::GaPreSign,
        );
        let passed = command
            .get_envs()
            .map(|(key, value)| (key.to_str().unwrap(), value.unwrap().to_str().unwrap()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            passed,
            BTreeMap::from([
                ("CFW_BUILD_NUMBER", FIXTURE_BUILD),
                ("CFW_NATIVE_PRODUCTS_OUTPUT", "/candidate/native-products"),
                ("CFW_RELEASE_RUST_TOOLCHAIN", "private"),
                ("CFW_UNSIGNED_VALIDATION_XCODE_VERSION", "reject-me"),
            ])
        );
        assert_eq!(command.get_program(), "/bin/bash");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                "-p",
                "/repo/scripts/build_native_ui.sh",
                "--verify",
                "--release"
            ]
        );
    }

    #[test]
    fn ga_path_build_and_manifest_are_one_exact_identity() {
        let fixture = Fixture::new();
        let root = fixture.root(PRODUCT_VERSION);
        let output = fixture.output(PRODUCT_VERSION, &ga_pre_sign_relative(FIXTURE_BUILD));
        let resolved = CandidateNativeProducts::resolve(&root, &output, FIXTURE_BUILD).unwrap();
        assert_eq!(resolved.context, NativeProductContext::GaPreSign);
        assert_eq!(resolved.context.expected_signing_mode(), "pre-sign");
        let metadata = BTreeMap::from([
            ("buildNumber".into(), FIXTURE_BUILD.into()),
            ("signingMode".into(), "pre-sign".into()),
        ]);
        resolved.require_manifest_identity(&metadata, "UI").unwrap();
        for (key, value) in [
            ("buildNumber", OTHER_BUILD),
            ("buildNumber", "070001"),
            ("buildNumber", "40000"),
            ("buildNumber", "50000"),
            ("signingMode", "unsigned-validation"),
            ("signingMode", "developer-id"),
        ] {
            let mut wrong = metadata.clone();
            wrong.insert(key.into(), value.into());
            assert!(resolved.require_manifest_identity(&wrong, "UI").is_err());
        }
        let preview = CandidateNativeProducts::resolve(
            &root,
            &fixture.output(PRODUCT_VERSION, UNSIGNED_PREVIEW_RELATIVE_ROOT),
            UNSIGNED_PREVIEW_BUILD_NUMBER,
        )
        .unwrap();
        assert!(preview.require_manifest_identity(&metadata, "UI").is_err());
    }

    #[test]
    fn release_refuses_other_builds_and_legacy_context_paths() {
        let fixture = Fixture::new();
        let root = fixture.root(PRODUCT_VERSION);
        let output = fixture.output(PRODUCT_VERSION, &ga_pre_sign_relative(FIXTURE_BUILD));
        for build in [
            OTHER_BUILD,
            "40000",
            "50000",
            "070001",
            "0",
            "",
            "+70001",
            "70001\n",
            "9223372036854775808",
        ] {
            assert!(
                CandidateNativeProducts::resolve(&root, &output, build).is_err(),
                "{build:?}"
            );
        }
        // Sibling validation roots, another build's root and the signed
        // output are never this build's GA pre-sign Host input.
        let other_build_root = ga_pre_sign_relative(OTHER_BUILD);
        let signed_output = format!("ga/{FIXTURE_BUILD}/signing-output/signed-native-products");
        for relative in [
            UNSIGNED_RELATIVE_ROOT,
            UNSIGNED_PREVIEW_RELATIVE_ROOT,
            other_build_root.as_str(),
            signed_output.as_str(),
        ] {
            let wrong = fixture.output(PRODUCT_VERSION, relative);
            assert!(
                CandidateNativeProducts::resolve(&root, &wrong, FIXTURE_BUILD).is_err(),
                "{relative}"
            );
        }
        // The retired 0.4.0 candidate root is no longer a candidate root at all.
        let old_root = fixture.root("0.4.0");
        for relative in [
            ga_pre_sign_relative(FIXTURE_BUILD),
            UNSIGNED_RELATIVE_ROOT.into(),
        ] {
            let old = fixture.output("0.4.0", &relative);
            for build in [FIXTURE_BUILD, "40000"] {
                assert!(CandidateNativeProducts::resolve(&old_root, &old, build).is_err());
            }
        }
        // Release and validation outputs live under the same product version root and
        // are told apart by their exact relative roots and build numbers.
        for (relative, build, expected) in [
            (
                UNSIGNED_RELATIVE_ROOT,
                "40000",
                NativeProductContext::UnsignedValidation,
            ),
            (
                UNSIGNED_PREVIEW_RELATIVE_ROOT,
                "50000",
                NativeProductContext::UnsignedPreviewValidation,
            ),
        ] {
            let sibling = fixture.output(PRODUCT_VERSION, relative);
            assert_eq!(
                CandidateNativeProducts::resolve(&root, &sibling, build)
                    .unwrap()
                    .context,
                expected
            );
            assert!(CandidateNativeProducts::resolve(&root, &sibling, FIXTURE_BUILD).is_err());
            assert!(CandidateNativeProducts::resolve(&root, &output, build).is_err());
        }
    }

    #[test]
    fn unsigned_preview_context_is_disjoint_from_every_production_root_and_mode() {
        let fixture = Fixture::new();
        let root = fixture.root(PRODUCT_VERSION);
        let output = fixture.output(PRODUCT_VERSION, UNSIGNED_PREVIEW_RELATIVE_ROOT);
        let admitted = CandidateNativeProducts::resolve(&root, &output, "50000").unwrap();
        assert_eq!(
            admitted.context,
            NativeProductContext::UnsignedPreviewValidation
        );
        assert_eq!(
            admitted.context.expected_signing_mode(),
            "unsigned-validation"
        );
        let good = BTreeMap::from([
            ("buildNumber".into(), "50000".into()),
            ("signingMode".into(), "unsigned-validation".into()),
        ]);
        admitted.require_manifest_identity(&good, "UI").unwrap();
        for signing in ["pre-sign", "developer-id"] {
            let mut changed = good.clone();
            changed.insert("signingMode".into(), signing.into());
            assert!(admitted.require_manifest_identity(&changed, "UI").is_err());
        }
        let ga_root = ga_pre_sign_relative(FIXTURE_BUILD);
        for (version, relative, build) in [
            (PRODUCT_VERSION, UNSIGNED_RELATIVE_ROOT, "40000"),
            (PRODUCT_VERSION, ga_root.as_str(), FIXTURE_BUILD),
        ] {
            let other = fixture.output(version, relative);
            assert!(CandidateNativeProducts::resolve(&root, &output, build).is_err());
            assert!(
                CandidateNativeProducts::resolve(&fixture.root(version), &other, "50000").is_err()
            );
        }
        let pinned = ("27.0", "27A266a");
        assert_eq!(
            admitted
                .context
                .expected_apple_identity(
                    pinned,
                    (Some("27.0"), Some("27A5252f")),
                    Some("/runtime/python3")
                )
                .unwrap(),
            ("27.0", "27A5252f")
        );
        assert!(
            admitted
                .context
                .expected_apple_identity(pinned, (Some("27.0"), Some("27A5252f")), None)
                .is_err()
        );
        assert!(
            admitted
                .context
                .expected_apple_identity(pinned, (Some("27.0"), None), Some("/runtime/python3"))
                .is_err()
        );
        let command = native_ui_verifier_command(
            Path::new("/repo/scripts/build_native_ui.sh"),
            [],
            admitted.context,
        );
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                "-p",
                "/repo/scripts/build_native_ui.sh",
                "--verify",
                "--unsigned-preview-validation"
            ]
        );
    }

    #[test]
    fn release_rejects_raw_alias_and_symlinked_roots() {
        let fixture = Fixture::new();
        let root = fixture.root(PRODUCT_VERSION);
        let relative = ga_pre_sign_relative(FIXTURE_BUILD);
        let output = fixture.output(PRODUCT_VERSION, &relative);
        for wrong in [
            output.replace("ga-preflight/", "ga-preflight//"),
            output.replace("ga-preflight/", "ga-preflight/./"),
            format!("{output}/"),
        ] {
            assert!(CandidateNativeProducts::resolve(&root, &wrong, FIXTURE_BUILD).is_err());
        }
        let raw_root = root
            .to_str()
            .unwrap()
            .replace("candidates/", "candidates//");
        let raw_output = format!("{raw_root}/{relative}");
        assert!(
            CandidateNativeProducts::resolve(Path::new(&raw_root), &raw_output, FIXTURE_BUILD)
                .is_err()
        );
        let moved = root.with_file_name("moved-release");
        fs::rename(&root, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &root).unwrap();
        assert!(CandidateNativeProducts::resolve(&root, &output, FIXTURE_BUILD).is_err());
    }
}
