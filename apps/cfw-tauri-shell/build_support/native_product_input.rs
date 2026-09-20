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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProductContext {
    UnsignedValidation,
    GaPreSign,
}

impl NativeProductContext {
    /// Hosted Xcode selection belongs only to the non-distributable 40000
    /// validation context. GA always retains the production pins.
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
            Self::GaPreSign => GA_BUILD_NUMBER,
        }
    }

    pub const fn expected_signing_mode(self) -> &'static str {
        match self {
            Self::UnsignedValidation => UNSIGNED_SIGNING_MODE,
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
        let unsigned = format!("{candidate_root_text}/{UNSIGNED_RELATIVE_ROOT}");
        let ga_pre_sign = format!("{candidate_root_text}/{GA_PRE_SIGN_RELATIVE_ROOT}");
        let context = if declared_output == unsigned {
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
