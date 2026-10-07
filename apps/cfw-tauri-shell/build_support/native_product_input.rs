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
const GA_PRE_SIGN_RELATIVE_ROOT: &str = "ga-preflight/50027/native-products";
const GA_BUILD_NUMBER: &str = "50027";
const GA_PRE_SIGNING_MODE: &str = "pre-sign";
/// The GA pre-sign output and the unsigned validation outputs share the one
/// product version; the three are told apart by their exact relative roots.
const CANDIDATE_ROOT: &str = "target/candidates/0.5.0";
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

    pub const fn expected_build_number(self) -> &'static str {
        match self {
            Self::UnsignedValidation => UNSIGNED_BUILD_NUMBER,
            Self::UnsignedPreviewValidation => UNSIGNED_PREVIEW_BUILD_NUMBER,
            Self::GaPreSign => GA_BUILD_NUMBER,
        }
    }

    pub const fn expected_signing_mode(self) -> &'static str {
        match self {
            Self::UnsignedValidation | Self::UnsignedPreviewValidation => UNSIGNED_SIGNING_MODE,
            Self::GaPreSign => GA_PRE_SIGNING_MODE,
        }
    }

    pub fn require_manifest_identity(
        self,
        metadata: &BTreeMap<String, String>,
        artifact: &str,
    ) -> Result<(), String> {
        require_metadata(
            metadata,
            artifact,
            "buildNumber",
            self.expected_build_number(),
        )?;
        require_metadata(
            metadata,
            artifact,
            "signingMode",
            self.expected_signing_mode(),
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CandidateNativeProducts {
    pub root: PathBuf,
    pub context: NativeProductContext,
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
        let ga_pre_sign = format!("{candidate_root_text}/{GA_PRE_SIGN_RELATIVE_ROOT}");
        let unsigned_preview = format!("{candidate_root_text}/{UNSIGNED_PREVIEW_RELATIVE_ROOT}");
        if !candidate_root.ends_with(CANDIDATE_ROOT) {
            return Err(format!(
                "candidate root must end with {CANDIDATE_ROOT}: {candidate_root_text}"
            ));
        }
        let context = if declared_output == unsigned {
            NativeProductContext::UnsignedValidation
        } else if declared_output == ga_pre_sign {
            NativeProductContext::GaPreSign
        } else if declared_output == unsigned_preview {
            NativeProductContext::UnsignedPreviewValidation
        } else {
            return Err(format!(
                "candidate native-products output must be exactly {unsigned}, {ga_pre_sign} or {unsigned_preview}, found {declared_output}"
            ));
        };
        if declared_build_number != context.expected_build_number() {
            return Err(format!(
                "candidate build number is {declared_build_number}, expected {} for {declared_output}",
                context.expected_build_number()
            ));
        }

        let root = PathBuf::from(declared_output);
        require_canonical_real_directory(candidate_root, &root)?;
        Ok(Self { root, context })
    }
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
            ("CFW_BUILD_NUMBER", "50027"),
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
                ("CFW_BUILD_NUMBER", "50027"),
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
        let root = fixture.root("0.5.0");
        let output = fixture.output("0.5.0", GA_PRE_SIGN_RELATIVE_ROOT);
        let resolved = CandidateNativeProducts::resolve(&root, &output, "50027").unwrap();
        assert_eq!(resolved.context, NativeProductContext::GaPreSign);
        assert_eq!(resolved.context.expected_build_number(), "50027");
        assert_eq!(resolved.context.expected_signing_mode(), "pre-sign");
        let metadata = BTreeMap::from([
            ("buildNumber".into(), "50027".into()),
            ("signingMode".into(), "pre-sign".into()),
        ]);
        resolved
            .context
            .require_manifest_identity(&metadata, "UI")
            .unwrap();
        for (key, value) in [
            ("buildNumber", "50025"),
            ("buildNumber", "50017"),
            ("buildNumber", "50018"),
            ("buildNumber", "50019"),
            ("buildNumber", "40073"),
            ("signingMode", "unsigned-validation"),
            ("signingMode", "developer-id"),
        ] {
            let mut wrong = metadata.clone();
            wrong.insert(key.into(), value.into());
            assert!(
                resolved
                    .context
                    .require_manifest_identity(&wrong, "UI")
                    .is_err()
            );
        }
        assert!(
            NativeProductContext::UnsignedPreviewValidation
                .require_manifest_identity(&metadata, "UI")
                .is_err()
        );
    }

    #[test]
    fn release_refuses_other_builds_and_legacy_context_paths() {
        let fixture = Fixture::new();
        let root = fixture.root("0.5.0");
        let output = fixture.output("0.5.0", GA_PRE_SIGN_RELATIVE_ROOT);
        for build in [
            "50025",
            "40000",
            "50001",
            "50002",
            "50003",
            "50004",
            "50005",
            "50006",
            "50007",
            "50008",
            "50009",
            "50012",
            "50013",
            "50014",
            "50015",
            "50016",
            "50017",
            "50018",
            "50019",
            "40073",
            "50026",
            "050027",
            "0",
            "+50027",
            "50027\n",
            "9223372036854775808",
        ] {
            assert!(
                CandidateNativeProducts::resolve(&root, &output, build).is_err(),
                "{build}"
            );
        }
        // The retained signed preview and every earlier preview root are
        // verification subjects, never Host build inputs.
        for relative in [
            UNSIGNED_RELATIVE_ROOT,
            UNSIGNED_PREVIEW_RELATIVE_ROOT,
            "ga-preflight/40073/native-products",
            "ga-preflight/50025/native-products",
            "preview-preflight/50025/native-products",
            "preview-preflight/50027/native-products",
            "preview/50025/signing-output/signed-native-products",
            "ga/50027/signing-output/signed-native-products",
        ] {
            let wrong = fixture.output("0.5.0", relative);
            assert!(
                CandidateNativeProducts::resolve(&root, &wrong, "50027").is_err(),
                "{relative}"
            );
        }
        // The retired 0.4.0 candidate root is no longer a candidate root at all.
        let old_root = fixture.root("0.4.0");
        for relative in [
            GA_PRE_SIGN_RELATIVE_ROOT,
            UNSIGNED_RELATIVE_ROOT,
            "ga-preflight/40073/native-products",
        ] {
            let old = fixture.output("0.4.0", relative);
            for build in ["50027", "40073", "40000"] {
                assert!(CandidateNativeProducts::resolve(&old_root, &old, build).is_err());
            }
        }
        // Release and validation outputs live under the same 0.5.0 root and
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
            let sibling = fixture.output("0.5.0", relative);
            assert_eq!(
                CandidateNativeProducts::resolve(&root, &sibling, build)
                    .unwrap()
                    .context,
                expected
            );
            assert!(CandidateNativeProducts::resolve(&root, &sibling, "50027").is_err());
            assert!(CandidateNativeProducts::resolve(&root, &output, build).is_err());
        }
    }

    #[test]
    fn unsigned_preview_context_is_disjoint_from_every_production_root_and_mode() {
        let fixture = Fixture::new();
        let root = fixture.root("0.5.0");
        let output = fixture.output("0.5.0", UNSIGNED_PREVIEW_RELATIVE_ROOT);
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
        admitted
            .context
            .require_manifest_identity(&good, "UI")
            .unwrap();
        for signing in ["pre-sign", "developer-id"] {
            let mut changed = good.clone();
            changed.insert("signingMode".into(), signing.into());
            assert!(
                admitted
                    .context
                    .require_manifest_identity(&changed, "UI")
                    .is_err()
            );
        }
        for (version, relative, build) in [
            ("0.5.0", UNSIGNED_RELATIVE_ROOT, "40000"),
            ("0.5.0", GA_PRE_SIGN_RELATIVE_ROOT, "50027"),
            ("0.5.0", "preview-preflight/50025/native-products", "50025"),
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
        let root = fixture.root("0.5.0");
        let output = fixture.output("0.5.0", GA_PRE_SIGN_RELATIVE_ROOT);
        for wrong in [
            output.replace("ga-preflight/", "ga-preflight//"),
            output.replace("ga-preflight/", "ga-preflight/./"),
            format!("{output}/"),
        ] {
            assert!(CandidateNativeProducts::resolve(&root, &wrong, "50027").is_err());
        }
        let raw_root = root
            .to_str()
            .unwrap()
            .replace("candidates/", "candidates//");
        let raw_output = format!("{raw_root}/{GA_PRE_SIGN_RELATIVE_ROOT}");
        assert!(
            CandidateNativeProducts::resolve(Path::new(&raw_root), &raw_output, "50027").is_err()
        );
        let moved = root.with_file_name("moved-release");
        fs::rename(&root, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &root).unwrap();
        assert!(CandidateNativeProducts::resolve(&root, &output, "50027").is_err());
    }
}
