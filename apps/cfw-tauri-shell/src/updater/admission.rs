use std::ffi::CString;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use cfw_platform::ReleaseSignedComponent;
use thiserror::Error;

pub(super) const BUNDLE_IDENTIFIER: &str = "com.bill.clashformac";
pub(super) const INFO_PLIST: &str = "Contents/Info.plist";

/// Reasons this installation cannot be replaced in place. Each one is a
/// property of the machine, so the user is directed to the disk image instead
/// of being asked to retry.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum InstallAdmissionError {
    #[error("cannot determine the running executable ({0:?})")]
    CurrentExecutableUnavailable(ErrorKind),
    #[error("in-app updates require the application to run from /Applications")]
    NotInApplications,
    #[error("cannot inspect the installed application ({0:?})")]
    InstallMetadataUnavailable(ErrorKind),
    #[error("the installed application is not an ordinary bundle owned by this user")]
    BundleNotUserOwned,
    #[error("this user cannot replace items in the Applications folder")]
    ApplicationsNotWritable,
    #[error("the installed application does not describe a valid release identity")]
    InstalledIdentityInvalid,
    #[error("update staging is not on the same volume as the installed application")]
    StagingVolumeMismatch,
}

impl InstallAdmissionError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::CurrentExecutableUnavailable(_) => "executable_unavailable",
            Self::NotInApplications => "not_in_applications",
            Self::InstallMetadataUnavailable(_) => "install_metadata_unavailable",
            Self::BundleNotUserOwned => "bundle_not_user_owned",
            Self::ApplicationsNotWritable => "applications_not_writable",
            Self::InstalledIdentityInvalid => "installed_identity_invalid",
            Self::StagingVolumeMismatch => "staging_volume_mismatch",
        }
    }
}

/// Version and build of an application bundle as its Info.plist states them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleIdentity {
    pub(crate) version: String,
    pub(crate) build: u64,
}

/// The bundle an update replaces and the directory that contains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InstallLocation {
    pub(super) bundle: PathBuf,
    pub(super) executable: PathBuf,
}

impl InstallLocation {
    pub(super) fn canonical() -> Self {
        Self {
            bundle: ReleaseSignedComponent::Application.path().to_path_buf(),
            executable: ReleaseSignedComponent::MainExecutable.path().to_path_buf(),
        }
    }
}

/// Whether this process is the installed copy. Only that copy owns update
/// records and staging; one run from a disk image or a build directory must
/// neither judge nor remove what the installed application left.
pub(super) fn runs_from_installed_location() -> bool {
    std::env::current_exe().ok().as_deref() == Some(ReleaseSignedComponent::MainExecutable.path())
}

/// Admits the running application as the one installed copy this user may
/// replace, and returns the identity it currently has on disk.
pub(super) fn admit_running_installation() -> Result<BundleIdentity, InstallAdmissionError> {
    let executable = std::env::current_exe()
        .map_err(|error| InstallAdmissionError::CurrentExecutableUnavailable(error.kind()))?;
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    let effective_uid = unsafe { libc::geteuid() };
    admit_installation(
        &InstallLocation::canonical(),
        &executable,
        effective_uid,
        env!("CARGO_PKG_VERSION"),
    )
}

fn admit_installation(
    location: &InstallLocation,
    running_executable: &Path,
    effective_uid: u32,
    running_version: &str,
) -> Result<BundleIdentity, InstallAdmissionError> {
    if running_executable != location.executable {
        return Err(InstallAdmissionError::NotInApplications);
    }
    let bundle = inspect(&location.bundle)?;
    let executable = inspect(&location.executable)?;
    if !bundle.file_type().is_dir()
        || !executable.file_type().is_file()
        || executable.nlink() != 1
        || [&bundle, &executable]
            .into_iter()
            .any(|entry| entry.uid() != effective_uid || entry.mode() & 0o022 != 0)
    {
        return Err(InstallAdmissionError::BundleNotUserOwned);
    }
    for path in [&location.bundle, &location.executable] {
        let resolved = fs::canonicalize(path)
            .map_err(|error| InstallAdmissionError::InstallMetadataUnavailable(error.kind()))?;
        if resolved != *path {
            return Err(InstallAdmissionError::BundleNotUserOwned);
        }
    }
    let parent = location
        .bundle
        .parent()
        .ok_or(InstallAdmissionError::NotInApplications)?;
    if !writable(parent)? {
        return Err(InstallAdmissionError::ApplicationsNotWritable);
    }
    let identity = read_bundle_identity(&location.bundle)
        .map_err(|_| InstallAdmissionError::InstalledIdentityInvalid)?;
    if identity.version != running_version {
        return Err(InstallAdmissionError::InstalledIdentityInvalid);
    }
    Ok(identity)
}

fn inspect(path: &Path) -> Result<fs::Metadata, InstallAdmissionError> {
    fs::symlink_metadata(path)
        .map_err(|error| InstallAdmissionError::InstallMetadataUnavailable(error.kind()))
}

fn writable(directory: &Path) -> Result<bool, InstallAdmissionError> {
    let path = CString::new(directory.as_os_str().as_bytes())
        .map_err(|_| InstallAdmissionError::InstallMetadataUnavailable(ErrorKind::InvalidInput))?;
    // SAFETY: the path is a live NUL-terminated string for the duration of
    // the call, which only consults the caller's access rights.
    if unsafe { libc::access(path.as_ptr(), libc::W_OK) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.kind() {
        ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem => Ok(false),
        kind => Err(InstallAdmissionError::InstallMetadataUnavailable(kind)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BundleIdentityError {
    Unreadable,
    WrongIdentifier,
    InvalidVersion,
    InvalidBuild,
}

/// Reads the product identifier, marketing version and build number of an
/// application bundle. The build must be a canonical positive decimal.
pub(super) fn read_bundle_identity(bundle: &Path) -> Result<BundleIdentity, BundleIdentityError> {
    let info = bundle.join(INFO_PLIST);
    let metadata = fs::symlink_metadata(&info).map_err(|_| BundleIdentityError::Unreadable)?;
    if !metadata.file_type().is_file() {
        return Err(BundleIdentityError::Unreadable);
    }
    let value = plist::Value::from_file(&info).map_err(|_| BundleIdentityError::Unreadable)?;
    let dictionary = value
        .as_dictionary()
        .ok_or(BundleIdentityError::Unreadable)?;
    let string = |key: &str| dictionary.get(key).and_then(plist::Value::as_string);
    if string("CFBundleIdentifier") != Some(BUNDLE_IDENTIFIER) {
        return Err(BundleIdentityError::WrongIdentifier);
    }
    let version = string("CFBundleShortVersionString")
        .filter(|value| {
            semver::Version::parse(value).is_ok_and(|parsed| parsed.to_string() == **value)
        })
        .ok_or(BundleIdentityError::InvalidVersion)?;
    let build = string("CFBundleVersion")
        .and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|build| *build > 0 && build.to_string() == value)
        })
        .ok_or(BundleIdentityError::InvalidBuild)?;
    Ok(BundleIdentity {
        version: version.to_owned(),
        build,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    pub(in crate::updater) fn write_bundle(
        root: &Path,
        identifier: &str,
        version: &str,
        build: &str,
    ) -> InstallLocation {
        let bundle = root.join("Clash for Mac.app");
        let macos = bundle.join("Contents/MacOS");
        fs::create_dir_all(&macos).expect("bundle layout");
        let executable = macos.join("clash-for-mac");
        fs::write(&executable, b"host").expect("executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("mode");
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert("CFBundleIdentifier".into(), identifier.into());
        dictionary.insert("CFBundleShortVersionString".into(), version.into());
        dictionary.insert("CFBundleVersion".into(), build.into());
        dictionary.insert("LSMinimumSystemVersion".into(), "15.0".into());
        plist::Value::Dictionary(dictionary)
            .to_file_xml(bundle.join(INFO_PLIST))
            .expect("Info.plist");
        InstallLocation { bundle, executable }
    }

    fn scratch() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("scratch");
        let root = fs::canonicalize(directory.path()).expect("canonical scratch");
        (directory, root)
    }

    fn uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    #[test]
    fn a_user_owned_bundle_in_a_writable_directory_is_admitted_with_its_identity() {
        let (_guard, root) = scratch();
        let location = write_bundle(&root, BUNDLE_IDENTIFIER, "0.4.0", "40074");
        assert_eq!(
            admit_installation(&location, &location.executable, uid(), "0.4.0"),
            Ok(BundleIdentity {
                version: "0.4.0".into(),
                build: 40074,
            })
        );
    }

    #[test]
    fn only_the_canonical_executable_is_admitted() {
        let (_guard, root) = scratch();
        let location = write_bundle(&root, BUNDLE_IDENTIFIER, "0.4.0", "40074");
        for elsewhere in [
            root.join("Other.app/Contents/MacOS/clash-for-mac"),
            Path::new("/Volumes/Clash for Mac/Clash for Mac.app/Contents/MacOS/clash-for-mac")
                .to_path_buf(),
        ] {
            assert_eq!(
                admit_installation(&location, &elsewhere, uid(), "0.4.0"),
                Err(InstallAdmissionError::NotInApplications)
            );
        }
    }

    #[test]
    fn bundles_of_another_owner_or_with_loose_modes_are_refused() {
        let (_guard, root) = scratch();
        let location = write_bundle(&root, BUNDLE_IDENTIFIER, "0.4.0", "40074");
        assert_eq!(
            admit_installation(&location, &location.executable, uid() + 1, "0.4.0"),
            Err(InstallAdmissionError::BundleNotUserOwned)
        );
        for loose in [&location.bundle, &location.executable] {
            let original = fs::metadata(loose).expect("metadata").permissions();
            fs::set_permissions(loose, fs::Permissions::from_mode(0o775)).expect("loose mode");
            assert_eq!(
                admit_installation(&location, &location.executable, uid(), "0.4.0"),
                Err(InstallAdmissionError::BundleNotUserOwned),
                "{}",
                loose.display()
            );
            fs::set_permissions(loose, original).expect("restore mode");
        }
        admit_installation(&location, &location.executable, uid(), "0.4.0")
            .expect("the restored bundle is admitted again");
    }

    #[test]
    fn a_symlinked_bundle_is_refused() {
        let (_guard, root) = scratch();
        let real = root.join("real");
        fs::create_dir(&real).expect("real directory");
        let installed = write_bundle(&real, BUNDLE_IDENTIFIER, "0.4.0", "40074");
        let link = root.join("Clash for Mac.app");
        std::os::unix::fs::symlink(&installed.bundle, &link).expect("symlink");
        let location = InstallLocation {
            executable: link.join("Contents/MacOS/clash-for-mac"),
            bundle: link,
        };
        assert_eq!(
            admit_installation(&location, &location.executable, uid(), "0.4.0"),
            Err(InstallAdmissionError::BundleNotUserOwned)
        );
    }

    #[test]
    fn a_read_only_parent_directory_is_refused_without_touching_the_bundle() {
        let (_guard, root) = scratch();
        let parent = root.join("Applications");
        fs::create_dir(&parent).expect("parent");
        let location = write_bundle(&parent, BUNDLE_IDENTIFIER, "0.4.0", "40074");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o555)).expect("read-only");
        let outcome = admit_installation(&location, &location.executable, uid(), "0.4.0");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).expect("restore");
        assert_eq!(outcome, Err(InstallAdmissionError::ApplicationsNotWritable));
    }

    #[test]
    fn the_installed_identity_must_match_the_running_release() {
        let (_guard, root) = scratch();
        let location = write_bundle(&root, BUNDLE_IDENTIFIER, "0.4.1", "40080");
        assert_eq!(
            admit_installation(&location, &location.executable, uid(), "0.4.0"),
            Err(InstallAdmissionError::InstalledIdentityInvalid)
        );
    }

    #[test]
    fn bundle_identity_requires_this_product_and_canonical_numbers() {
        let cases = [
            (
                "com.example.other",
                "0.4.0",
                "40074",
                BundleIdentityError::WrongIdentifier,
            ),
            (
                BUNDLE_IDENTIFIER,
                "0.4",
                "40074",
                BundleIdentityError::InvalidVersion,
            ),
            (
                BUNDLE_IDENTIFIER,
                "00.4.0",
                "40074",
                BundleIdentityError::InvalidVersion,
            ),
            (
                BUNDLE_IDENTIFIER,
                "0.4.0",
                "040074",
                BundleIdentityError::InvalidBuild,
            ),
            (
                BUNDLE_IDENTIFIER,
                "0.4.0",
                "0",
                BundleIdentityError::InvalidBuild,
            ),
            (
                BUNDLE_IDENTIFIER,
                "0.4.0",
                "40074.1",
                BundleIdentityError::InvalidBuild,
            ),
            (
                BUNDLE_IDENTIFIER,
                "0.4.0",
                "",
                BundleIdentityError::InvalidBuild,
            ),
        ];
        for (identifier, version, build, expected) in cases {
            let (_guard, root) = scratch();
            let location = write_bundle(&root, identifier, version, build);
            assert_eq!(
                read_bundle_identity(&location.bundle),
                Err(expected),
                "{identifier} {version} {build}"
            );
        }
        let (_guard, root) = scratch();
        assert_eq!(
            read_bundle_identity(&root.join("Missing.app")),
            Err(BundleIdentityError::Unreadable)
        );
    }

    #[test]
    fn admission_errors_never_echo_paths() {
        for error in [
            InstallAdmissionError::NotInApplications,
            InstallAdmissionError::BundleNotUserOwned,
            InstallAdmissionError::ApplicationsNotWritable,
            InstallAdmissionError::InstalledIdentityInvalid,
            InstallAdmissionError::StagingVolumeMismatch,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("/Users/"), "{rendered}");
            assert!(!error.code().is_empty());
        }
    }
}
