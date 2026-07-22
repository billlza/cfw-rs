use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

#[cfg(test)]
use std::path::PathBuf;

use thiserror::Error;

const CANONICAL_APP_BUNDLE: &str = "/Applications/Clash for Mac.app";
const CANONICAL_APP_EXECUTABLE: &str =
    "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(super) enum InstallAdmissionError {
    #[error("cannot determine the current executable for update installation ({0:?})")]
    CurrentExecutableUnavailable(ErrorKind),
    #[error(
        "updates may be installed only from the canonical /Applications/Clash for Mac.app bundle"
    )]
    NonCanonicalInstallLocation,
    #[error("cannot inspect the installed application before update commit ({0:?})")]
    InstallMetadataUnavailable(ErrorKind),
    #[error("the installed application has unsafe path, ownership, or permission metadata")]
    UnsafeInstallMetadata,
    #[error("cannot inspect the private update staging directory ({0:?})")]
    TemporaryRootUnavailable(ErrorKind),
    #[error("the update staging directory has unsafe path, ownership, or permission metadata")]
    UnsafeTemporaryRoot,
    #[error("the update staging directory changed while it was being pinned")]
    TemporaryRootChanged,
}

pub(super) fn validate_install_environment() -> Result<(), InstallAdmissionError> {
    let executable = std::env::current_exe()
        .map_err(|error| InstallAdmissionError::CurrentExecutableUnavailable(error.kind()))?;
    validate_current_executable_path(&executable)?;

    // SAFETY: geteuid has no preconditions and only reads process credentials.
    let effective_uid = unsafe { libc::geteuid() };
    validate_installed_application(effective_uid)?;

    let temporary_root = tempfile::env::temp_dir();
    validate_temporary_root(&temporary_root, effective_uid)?;
    match tempfile::env::override_temp_dir(&temporary_root) {
        Ok(()) => {}
        Err(existing) if existing == temporary_root => {}
        Err(_) => return Err(InstallAdmissionError::TemporaryRootChanged),
    }
    if tempfile::env::temp_dir() != temporary_root {
        return Err(InstallAdmissionError::TemporaryRootChanged);
    }
    Ok(())
}

fn validate_current_executable_path(executable: &Path) -> Result<(), InstallAdmissionError> {
    if executable != Path::new(CANONICAL_APP_EXECUTABLE) {
        return Err(InstallAdmissionError::NonCanonicalInstallLocation);
    }
    Ok(())
}

fn validate_installed_application(effective_uid: u32) -> Result<(), InstallAdmissionError> {
    let bundle = Path::new(CANONICAL_APP_BUNDLE);
    let executable = Path::new(CANONICAL_APP_EXECUTABLE);
    let bundle_metadata = fs::symlink_metadata(bundle)
        .map_err(|error| InstallAdmissionError::InstallMetadataUnavailable(error.kind()))?;
    let executable_metadata = fs::symlink_metadata(executable)
        .map_err(|error| InstallAdmissionError::InstallMetadataUnavailable(error.kind()))?;
    if !bundle_metadata.file_type().is_dir()
        || bundle_metadata.file_type().is_symlink()
        || !executable_metadata.file_type().is_file()
        || executable_metadata.file_type().is_symlink()
        || executable_metadata.nlink() != 1
        || !trusted_install_owner(bundle_metadata.uid(), effective_uid)
        || executable_metadata.uid() != bundle_metadata.uid()
        || bundle_metadata.mode() & 0o022 != 0
        || executable_metadata.mode() & 0o022 != 0
    {
        return Err(InstallAdmissionError::UnsafeInstallMetadata);
    }

    let canonical_bundle = fs::canonicalize(bundle)
        .map_err(|error| InstallAdmissionError::InstallMetadataUnavailable(error.kind()))?;
    let canonical_executable = fs::canonicalize(executable)
        .map_err(|error| InstallAdmissionError::InstallMetadataUnavailable(error.kind()))?;
    if canonical_bundle != bundle || canonical_executable != executable {
        return Err(InstallAdmissionError::UnsafeInstallMetadata);
    }
    Ok(())
}

fn trusted_install_owner(owner_uid: u32, effective_uid: u32) -> bool {
    owner_uid == 0 || owner_uid == effective_uid
}

fn validate_temporary_root(
    temporary_root: &Path,
    effective_uid: u32,
) -> Result<(), InstallAdmissionError> {
    validate_shell_safe_temporary_path(temporary_root)?;
    let metadata = fs::symlink_metadata(temporary_root)
        .map_err(|error| InstallAdmissionError::TemporaryRootUnavailable(error.kind()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(InstallAdmissionError::UnsafeTemporaryRoot);
    }

    let canonical = fs::canonicalize(temporary_root)
        .map_err(|error| InstallAdmissionError::TemporaryRootUnavailable(error.kind()))?;
    validate_shell_safe_temporary_path(&canonical)?;
    let canonical_metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| InstallAdmissionError::TemporaryRootUnavailable(error.kind()))?;
    if canonical_metadata.dev() != metadata.dev() || canonical_metadata.ino() != metadata.ino() {
        return Err(InstallAdmissionError::UnsafeTemporaryRoot);
    }
    Ok(())
}

fn validate_shell_safe_temporary_path(path: &Path) -> Result<(), InstallAdmissionError> {
    let Some(value) = path.to_str() else {
        return Err(InstallAdmissionError::UnsafeTemporaryRoot);
    };
    if !path.is_absolute()
        || value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(InstallAdmissionError::UnsafeTemporaryRoot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_applications_bundle_executable_is_admitted() {
        validate_current_executable_path(Path::new(CANONICAL_APP_EXECUTABLE))
            .expect("canonical executable");
        for path in [
            "/Volumes/Clash for Mac/Clash for Mac.app/Contents/MacOS/clash-for-mac",
            "/Applications/Clash for Mac.app.backup/Contents/MacOS/clash-for-mac",
            "/Applications/Other.app/Contents/MacOS/clash-for-mac",
            "/Volumes/Clash'$(touch injected)'/Clash for Mac.app/Contents/MacOS/clash-for-mac",
        ] {
            assert_eq!(
                validate_current_executable_path(Path::new(path)),
                Err(InstallAdmissionError::NonCanonicalInstallLocation),
                "unsafe updater source was admitted: {path:?}"
            );
        }
    }

    #[test]
    fn temporary_shell_path_rejects_quotes_substitutions_and_whitespace() {
        validate_shell_safe_temporary_path(Path::new("/private/var/folders/c7/safe_123/T"))
            .expect("system-style temporary root");
        for path in [
            "/tmp/quote'root",
            "/tmp/$(touch_injected)",
            "/tmp/`touch_injected`",
            "/tmp/space root",
            "relative/root",
        ] {
            assert_eq!(
                validate_shell_safe_temporary_path(Path::new(path)),
                Err(InstallAdmissionError::UnsafeTemporaryRoot),
                "unsafe temporary root was admitted: {path:?}"
            );
        }
    }

    #[test]
    fn bundle_owner_must_be_root_or_the_effective_user() {
        assert!(trusted_install_owner(0, 501));
        assert!(trusted_install_owner(501, 501));
        assert!(!trusted_install_owner(502, 501));
    }

    #[test]
    fn install_admission_errors_never_echo_attacker_controlled_paths() {
        let malicious = "/Volumes/evil'$(touch injected)'/Clash for Mac.app/Contents/MacOS/x";
        let error = validate_current_executable_path(Path::new(malicious))
            .expect_err("malicious path must fail")
            .to_string();
        assert!(!error.contains("evil"));
        assert!(!error.contains("touch"));
    }

    #[test]
    fn canonical_paths_are_stored_as_absolute_constants() {
        assert_eq!(
            PathBuf::from(CANONICAL_APP_BUNDLE),
            Path::new(CANONICAL_APP_EXECUTABLE)
                .ancestors()
                .nth(3)
                .expect("bundle ancestor")
        );
    }
}
