use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const UNSIGNED_RELATIVE_ROOT: &str = "unsigned/native-products";
const UNSIGNED_BUILD_NUMBER: &str = "40000";
const UNSIGNED_SIGNING_MODE: &str = "unsigned-validation";
const GA_PRE_SIGN_RELATIVE_ROOT: &str = "ga-preflight/40073/native-products";
const GA_BUILD_NUMBER: &str = "40073";
const GA_PRE_SIGNING_MODE: &str = "pre-sign";
const PREVIEW_CANDIDATE_ROOT: &str = "target/candidates/0.5.0";
const PREVIEW_PRE_SIGN_RELATIVE_ROOT: &str = "preview-preflight/50002/native-products";
const PREVIEW_BUILD_NUMBER: &str = "50002";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProductContext {
    UnsignedValidation,
    GaPreSign,
    PreviewPreSign,
}

impl NativeProductContext {
    /// Hosted Xcode selection belongs only to the non-distributable 40000
    /// validation context. GA and signed previews retain the production pins.
    pub fn expected_apple_identity<'a>(
        self,
        pinned: (&'a str, &'a str),
        selected: (Option<&'a str>, Option<&'a str>),
        validation_python: Option<&str>,
    ) -> Result<(&'a str, &'a str), String> {
        if matches!(self, Self::GaPreSign | Self::PreviewPreSign) {
            if selected.0.is_some() || selected.1.is_some() || validation_python.is_some() {
                return Err(if self == Self::GaPreSign {
                    "GA native inputs refuse unsigned-validation toolchain selection"
                } else {
                    "signed preview native inputs refuse unsigned-validation toolchain selection"
                }
                .into());
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
            Self::GaPreSign => GA_BUILD_NUMBER,
            Self::PreviewPreSign => PREVIEW_BUILD_NUMBER,
        }
    }

    pub const fn expected_signing_mode(self) -> &'static str {
        match self {
            Self::UnsignedValidation => UNSIGNED_SIGNING_MODE,
            Self::GaPreSign | Self::PreviewPreSign => GA_PRE_SIGNING_MODE,
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
        let preview_pre_sign = format!("{candidate_root_text}/{PREVIEW_PRE_SIGN_RELATIVE_ROOT}");
        let context = if candidate_root.ends_with(PREVIEW_CANDIDATE_ROOT) {
            if declared_output != preview_pre_sign {
                return Err(format!(
                    "preview native-products output must be exactly {preview_pre_sign}, found {declared_output}"
                ));
            }
            NativeProductContext::PreviewPreSign
        } else if declared_output == unsigned {
            NativeProductContext::UnsignedValidation
        } else if declared_output == ga_pre_sign {
            NativeProductContext::GaPreSign
        } else {
            return Err(format!(
                "candidate native-products output must be exactly {unsigned} or {ga_pre_sign}, found {declared_output}"
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
mod preview_tests {
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
                "cfm-preview-input-test-{}-{nonce}-{}",
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
    fn preview_path_build_and_manifest_are_one_exact_identity() {
        let fixture = Fixture::new();
        let root = fixture.root("0.5.0");
        let output = fixture.output("0.5.0", PREVIEW_PRE_SIGN_RELATIVE_ROOT);
        let resolved = CandidateNativeProducts::resolve(&root, &output, "50002").unwrap();
        assert_eq!(resolved.context, NativeProductContext::PreviewPreSign);
        assert_eq!(resolved.context.expected_build_number(), "50002");
        assert_eq!(resolved.context.expected_signing_mode(), "pre-sign");
        let metadata = BTreeMap::from([
            ("buildNumber".into(), "50002".into()),
            ("signingMode".into(), "pre-sign".into()),
        ]);
        resolved
            .context
            .require_manifest_identity(&metadata, "UI")
            .unwrap();
        for (key, value) in [
            ("buildNumber", "40073"),
            ("buildNumber", "50003"),
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
            NativeProductContext::GaPreSign
                .require_manifest_identity(&metadata, "UI")
                .is_err()
        );
    }

    #[test]
    fn preview_refuses_other_builds_and_legacy_context_paths() {
        let fixture = Fixture::new();
        let root = fixture.root("0.5.0");
        let output = fixture.output("0.5.0", PREVIEW_PRE_SIGN_RELATIVE_ROOT);
        for build in [
            "40073",
            "40000",
            "50001",
            "50003",
            "050002",
            "0",
            "+50002",
            "50002\n",
            "9223372036854775808",
        ] {
            assert!(
                CandidateNativeProducts::resolve(&root, &output, build).is_err(),
                "{build}"
            );
        }
        for relative in [
            UNSIGNED_RELATIVE_ROOT,
            GA_PRE_SIGN_RELATIVE_ROOT,
            "preview-preflight/50003/native-products",
            "preview/50002/signing-output/signed-native-products",
        ] {
            let wrong = fixture.output("0.5.0", relative);
            assert!(
                CandidateNativeProducts::resolve(&root, &wrong, "50002").is_err(),
                "{relative}"
            );
        }
        let old_root = fixture.root("0.4.0");
        let wrong = fixture.output("0.4.0", PREVIEW_PRE_SIGN_RELATIVE_ROOT);
        assert!(CandidateNativeProducts::resolve(&old_root, &wrong, "50002").is_err());
        for (relative, build, expected) in [
            (
                GA_PRE_SIGN_RELATIVE_ROOT,
                "40073",
                NativeProductContext::GaPreSign,
            ),
            (
                UNSIGNED_RELATIVE_ROOT,
                "40000",
                NativeProductContext::UnsignedValidation,
            ),
        ] {
            let old = fixture.output("0.4.0", relative);
            assert_eq!(
                CandidateNativeProducts::resolve(&old_root, &old, build)
                    .unwrap()
                    .context,
                expected
            );
            assert!(CandidateNativeProducts::resolve(&root, &old, build).is_err());
            assert!(CandidateNativeProducts::resolve(&old_root, &old, "50002").is_err());
        }
    }

    #[test]
    fn preview_requires_production_apple_toolchain() {
        let context = NativeProductContext::PreviewPreSign;
        let pinned = ("27.0", "27A266a");
        assert_eq!(
            context
                .expected_apple_identity(pinned, (None, None), None)
                .unwrap(),
            pinned
        );
        for selected in [
            (Some("27.0"), Some("27A266a")),
            (Some("27.1"), Some("27B1")),
            (Some(""), None),
            (None, Some("27A266a")),
        ] {
            assert!(
                context
                    .expected_apple_identity(pinned, selected, None)
                    .is_err()
            );
        }
        assert!(
            context
                .expected_apple_identity(pinned, (None, None), Some("/python3"))
                .is_err()
        );
    }

    #[test]
    fn preview_rejects_raw_alias_and_symlinked_roots() {
        let fixture = Fixture::new();
        let root = fixture.root("0.5.0");
        let output = fixture.output("0.5.0", PREVIEW_PRE_SIGN_RELATIVE_ROOT);
        for wrong in [
            output.replace("preview-preflight/", "preview-preflight//"),
            output.replace("preview-preflight/", "preview-preflight/./"),
            format!("{output}/"),
        ] {
            assert!(CandidateNativeProducts::resolve(&root, &wrong, "50002").is_err());
        }
        let raw_root = root
            .to_str()
            .unwrap()
            .replace("candidates/", "candidates//");
        let raw_output = format!("{raw_root}/{PREVIEW_PRE_SIGN_RELATIVE_ROOT}");
        assert!(
            CandidateNativeProducts::resolve(Path::new(&raw_root), &raw_output, "50002").is_err()
        );
        let moved = root.with_file_name("moved-preview");
        fs::rename(&root, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &root).unwrap();
        assert!(CandidateNativeProducts::resolve(&root, &output, "50002").is_err());
    }
}
