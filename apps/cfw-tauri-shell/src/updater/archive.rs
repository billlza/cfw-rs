use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use cfw_platform::{AppUpdateToolError, extract_update_archive};
use thiserror::Error;

use super::admission::INFO_PLIST;
use super::error::bounded_diagnostic;
use super::staging::BUNDLE_NAME;

const MAIN_EXECUTABLE: &str = "Contents/MacOS/clash-for-mac";
const MAX_ENTRY_COUNT: usize = 50_000;
const MAX_EXPANDED_BYTES: u64 = 1024 * 1024 * 1024;

/// A signed archive that still cannot be installed. The archive was produced
/// by the release key holder, so each case is a packaging fault to report, not
/// an attack to defend against in depth.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum UpdateArchiveError {
    #[error("the update archive could not be extracted: {0}")]
    ExtractionRejected(String),
    #[error("the update archive extractor could not run")]
    ExtractorUnavailable,
    #[error("the extracted update cannot be inspected ({0:?})")]
    Inspection(ErrorKind),
    #[error("the update archive does not contain exactly the application bundle")]
    UnexpectedLayout,
    #[error("the update archive contains an entry that is not a file, directory or symlink")]
    ForbiddenEntryType,
    #[error("the update archive contains an entry with unsafe ownership, links or mode")]
    UnsafeEntry,
    #[error("the update archive contains a symlink that leaves the application bundle")]
    EscapingSymlink,
    #[error("the extracted update exceeds its entry or size limit")]
    TooLarge,
}

impl UpdateArchiveError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::ExtractionRejected(_) => "archive_extraction_rejected",
            Self::ExtractorUnavailable => "archive_extractor_unavailable",
            Self::Inspection(_) => "archive_inspection_failed",
            Self::UnexpectedLayout => "archive_layout_invalid",
            Self::ForbiddenEntryType => "archive_entry_forbidden",
            Self::UnsafeEntry => "archive_entry_unsafe",
            Self::EscapingSymlink => "archive_symlink_escapes",
            Self::TooLarge => "archive_expansion_exceeded",
        }
    }
}

/// Extracts an authenticated archive into an empty private directory and
/// returns the application bundle it contained.
pub(super) fn extract_bundle(
    archive: &Path,
    payload: &Path,
) -> Result<PathBuf, UpdateArchiveError> {
    extract_update_archive(archive, payload).map_err(|error| {
        // The extractor's own words are the only detail of a packaging
        // fault: the log keeps them whole, the journal one bounded line.
        eprintln!("update archive extraction failed: {error}");
        match error {
            AppUpdateToolError::Rejected { diagnostic, .. } => {
                UpdateArchiveError::ExtractionRejected(bounded_diagnostic(&diagnostic))
            }
            AppUpdateToolError::UnsafeArgument(_) | AppUpdateToolError::Unavailable { .. } => {
                UpdateArchiveError::ExtractorUnavailable
            }
        }
    })?;
    validate_extracted_payload(payload)
}

fn validate_extracted_payload(payload: &Path) -> Result<PathBuf, UpdateArchiveError> {
    let mut entries = fs::read_dir(payload)
        .map_err(inspection)?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(inspection)?;
    let Some(only) = entries.pop().filter(|_| entries.is_empty()) else {
        return Err(UpdateArchiveError::UnexpectedLayout);
    };
    if only.file_name() != BUNDLE_NAME {
        return Err(UpdateArchiveError::UnexpectedLayout);
    }
    let bundle = only.path();
    validate_tree(&bundle)?;
    let info = fs::symlink_metadata(bundle.join(INFO_PLIST)).map_err(layout)?;
    let executable = fs::symlink_metadata(bundle.join(MAIN_EXECUTABLE)).map_err(layout)?;
    if !info.file_type().is_file()
        || !executable.file_type().is_file()
        || executable.mode() & 0o100 == 0
    {
        return Err(UpdateArchiveError::UnexpectedLayout);
    }
    Ok(bundle)
}

fn validate_tree(bundle: &Path) -> Result<(), UpdateArchiveError> {
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    let owner = unsafe { libc::geteuid() };
    let root = fs::symlink_metadata(bundle).map_err(inspection)?;
    if !root.file_type().is_dir() {
        return Err(UpdateArchiveError::UnexpectedLayout);
    }
    require_safe_directory(&root, owner)?;
    let canonical_bundle = fs::canonicalize(bundle).map_err(inspection)?;
    let mut pending = vec![(bundle.to_path_buf(), PathBuf::new())];
    let mut visited = 0_usize;
    let mut expanded = 0_u64;
    while let Some((directory, relative)) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(inspection)? {
            let entry = entry.map_err(inspection)?;
            visited += 1;
            if visited > MAX_ENTRY_COUNT {
                return Err(UpdateArchiveError::TooLarge);
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(inspection)?;
            let relative = relative.join(entry.file_name());
            let kind = metadata.file_type();
            if kind.is_symlink() {
                let target = fs::read_link(entry.path()).map_err(inspection)?;
                require_confined_symlink(&relative, &target)?;
                require_resolved_inside(&entry.path(), &canonical_bundle)?;
            } else if kind.is_dir() {
                require_safe_directory(&metadata, owner)?;
                pending.push((entry.path(), relative));
            } else if kind.is_file() {
                require_safe_entry(&metadata, owner)?;
                if metadata.nlink() != 1 {
                    return Err(UpdateArchiveError::UnsafeEntry);
                }
                expanded = expanded
                    .checked_add(metadata.len())
                    .filter(|total| *total <= MAX_EXPANDED_BYTES)
                    .ok_or(UpdateArchiveError::TooLarge)?;
            } else {
                return Err(UpdateArchiveError::ForbiddenEntryType);
            }
        }
    }
    Ok(())
}

fn require_safe_entry(metadata: &fs::Metadata, owner: u32) -> Result<(), UpdateArchiveError> {
    if metadata.uid() != owner || metadata.mode() & 0o7022 != 0 {
        return Err(UpdateArchiveError::UnsafeEntry);
    }
    Ok(())
}

/// A directory the installed application must be able to enter and the next
/// update must be able to replace: its owner has full access.
fn require_safe_directory(metadata: &fs::Metadata, owner: u32) -> Result<(), UpdateArchiveError> {
    require_safe_entry(metadata, owner)?;
    if metadata.mode() & 0o700 != 0o700 {
        return Err(UpdateArchiveError::UnsafeEntry);
    }
    Ok(())
}

/// The lexical rule cannot see a link that climbs through another link. What
/// a link finally names must exist and lie inside the bundle.
fn require_resolved_inside(link: &Path, canonical_bundle: &Path) -> Result<(), UpdateArchiveError> {
    let resolved = fs::canonicalize(link).map_err(|error| match error.kind() {
        ErrorKind::NotFound => UpdateArchiveError::EscapingSymlink,
        _ => inspection(error),
    })?;
    if !resolved.starts_with(canonical_bundle) {
        return Err(UpdateArchiveError::EscapingSymlink);
    }
    Ok(())
}

/// A symlink may only name something inside the bundle, by a relative path
/// that never climbs above the bundle root at any step.
fn require_confined_symlink(link: &Path, target: &Path) -> Result<(), UpdateArchiveError> {
    let mut depth = link.components().count() - 1;
    let mut components = target.components().peekable();
    if components.peek().is_none() {
        return Err(UpdateArchiveError::EscapingSymlink);
    }
    for component in components {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(UpdateArchiveError::EscapingSymlink)?;
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(UpdateArchiveError::EscapingSymlink);
            }
        }
    }
    Ok(())
}

fn inspection(error: std::io::Error) -> UpdateArchiveError {
    UpdateArchiveError::Inspection(error.kind())
}

fn layout(error: std::io::Error) -> UpdateArchiveError {
    if error.kind() == ErrorKind::NotFound {
        UpdateArchiveError::UnexpectedLayout
    } else {
        inspection(error)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    use super::*;

    fn payload_with_bundle() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let scratch = tempfile::tempdir().expect("scratch");
        let payload = fs::canonicalize(scratch.path())
            .expect("canonical")
            .join("payload");
        let bundle = payload.join(BUNDLE_NAME);
        fs::create_dir_all(bundle.join("Contents/MacOS")).expect("layout");
        fs::write(bundle.join(INFO_PLIST), b"<plist/>").expect("Info.plist");
        let executable = bundle.join(MAIN_EXECUTABLE);
        fs::write(&executable, b"host").expect("executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("mode");
        (scratch, payload, bundle)
    }

    #[test]
    fn a_release_shaped_bundle_with_internal_symlinks_is_accepted() {
        let (_guard, payload, bundle) = payload_with_bundle();
        let versions = bundle.join("Contents/Frameworks/Bridge.framework/Versions");
        fs::create_dir_all(versions.join("A")).expect("framework");
        fs::write(versions.join("A/Bridge"), b"library").expect("library");
        std::os::unix::fs::symlink("A", versions.join("Current")).expect("version link");
        std::os::unix::fs::symlink(
            "Versions/Current/Bridge",
            bundle.join("Contents/Frameworks/Bridge.framework/Bridge"),
        )
        .expect("library link");
        std::os::unix::fs::symlink(
            "../MacOS/clash-for-mac",
            bundle.join("Contents/Frameworks/host"),
        )
        .expect("sibling link");
        assert_eq!(validate_extracted_payload(&payload), Ok(bundle));
    }

    #[test]
    fn the_payload_must_contain_exactly_the_application_bundle() {
        let (_guard, payload, bundle) = payload_with_bundle();
        fs::write(payload.join("README"), b"extra").expect("extra entry");
        assert_eq!(
            validate_extracted_payload(&payload),
            Err(UpdateArchiveError::UnexpectedLayout)
        );
        fs::remove_file(payload.join("README")).expect("remove extra");
        fs::rename(&bundle, payload.join("Other.app")).expect("rename");
        assert_eq!(
            validate_extracted_payload(&payload),
            Err(UpdateArchiveError::UnexpectedLayout)
        );
        fs::remove_dir_all(payload.join("Other.app")).expect("empty payload");
        assert_eq!(
            validate_extracted_payload(&payload),
            Err(UpdateArchiveError::UnexpectedLayout)
        );
    }

    #[test]
    fn a_bundle_without_its_executable_or_info_plist_is_refused() {
        for missing in [INFO_PLIST, MAIN_EXECUTABLE] {
            let (_guard, payload, bundle) = payload_with_bundle();
            fs::remove_file(bundle.join(missing)).expect("remove");
            assert_eq!(
                validate_extracted_payload(&payload),
                Err(UpdateArchiveError::UnexpectedLayout),
                "{missing}"
            );
        }
        let (_guard, payload, bundle) = payload_with_bundle();
        fs::set_permissions(
            bundle.join(MAIN_EXECUTABLE),
            fs::Permissions::from_mode(0o644),
        )
        .expect("not executable");
        assert_eq!(
            validate_extracted_payload(&payload),
            Err(UpdateArchiveError::UnexpectedLayout)
        );
    }

    #[test]
    fn symlinks_that_leave_the_bundle_are_refused() {
        for target in [
            "/etc/hosts",
            "../../outside",
            "../../../outside",
            "Resources/../../../x",
        ] {
            let (_guard, payload, bundle) = payload_with_bundle();
            std::os::unix::fs::symlink(target, bundle.join("Contents/escape")).expect("symlink");
            assert_eq!(
                validate_extracted_payload(&payload),
                Err(UpdateArchiveError::EscapingSymlink),
                "{target}"
            );
        }
    }

    #[test]
    fn a_link_that_leaves_the_bundle_through_another_link_is_refused() {
        let (_guard, payload, bundle) = payload_with_bundle();
        let deep = bundle.join("Contents/Frameworks/Deep/Deeper");
        fs::create_dir_all(&deep).expect("nested directories");
        // Each link alone stays inside by the lexical rule: the first names
        // the bundle root, the second one step above whatever the first names.
        std::os::unix::fs::symlink("../../../..", deep.join("up")).expect("link to the root");
        std::os::unix::fs::symlink(
            "Frameworks/Deep/Deeper/up/..",
            bundle.join("Contents/outside"),
        )
        .expect("link through the first link");
        assert_eq!(
            fs::canonicalize(bundle.join("Contents/outside")).expect("resolves"),
            payload,
            "the second link really names the directory above the bundle"
        );
        assert_eq!(
            validate_extracted_payload(&payload),
            Err(UpdateArchiveError::EscapingSymlink)
        );
    }

    #[test]
    fn a_link_to_nothing_is_refused() {
        let (_guard, payload, bundle) = payload_with_bundle();
        std::os::unix::fs::symlink("Resources/missing", bundle.join("Contents/dangling"))
            .expect("dangling link");
        assert_eq!(
            validate_extracted_payload(&payload),
            Err(UpdateArchiveError::EscapingSymlink)
        );
    }

    #[test]
    fn a_directory_its_owner_cannot_fully_use_is_refused() {
        for mode in [0o500, 0o600, 0o300] {
            let (_guard, payload, bundle) = payload_with_bundle();
            let directory = bundle.join("Contents/Resources");
            fs::create_dir(&directory).expect("directory");
            fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).expect("mode");
            let verdict = validate_extracted_payload(&payload);
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("restore for cleanup");
            assert_eq!(verdict, Err(UpdateArchiveError::UnsafeEntry), "{mode:o}");
        }
    }

    #[test]
    fn hard_links_special_files_and_loose_modes_are_refused() {
        let (_guard, payload, bundle) = payload_with_bundle();
        fs::hard_link(bundle.join(INFO_PLIST), bundle.join("Contents/alias")).expect("hard link");
        assert_eq!(
            validate_extracted_payload(&payload),
            Err(UpdateArchiveError::UnsafeEntry)
        );

        let (_guard, payload, bundle) = payload_with_bundle();
        let made = Command::new("/usr/bin/mkfifo")
            .arg(bundle.join("Contents/pipe"))
            .status()
            .expect("mkfifo");
        assert!(made.success());
        assert_eq!(
            validate_extracted_payload(&payload),
            Err(UpdateArchiveError::ForbiddenEntryType)
        );

        for mode in [0o666, 0o4755, 0o2755] {
            let (_guard, payload, bundle) = payload_with_bundle();
            fs::set_permissions(bundle.join(INFO_PLIST), fs::Permissions::from_mode(mode))
                .expect("mode");
            assert_eq!(
                validate_extracted_payload(&payload),
                Err(UpdateArchiveError::UnsafeEntry),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn extraction_of_a_real_archive_returns_the_validated_bundle() {
        let (_guard, source, _bundle) = payload_with_bundle();
        let archive = source.parent().expect("scratch").join("update.tar.gz");
        let packed = Command::new("/usr/bin/tar")
            .current_dir(&source)
            .env("COPYFILE_DISABLE", "1")
            .arg("-czf")
            .arg(&archive)
            .args(["--no-xattrs", "--no-mac-metadata", BUNDLE_NAME])
            .status()
            .expect("pack");
        assert!(packed.success());
        let payload = source.parent().expect("scratch").join("extracted");
        fs::create_dir(&payload).expect("payload");
        assert_eq!(
            extract_bundle(&archive, &payload),
            Ok(payload.join(BUNDLE_NAME))
        );

        fs::write(&archive, b"not an archive").expect("corrupt archive");
        let second = source.parent().expect("scratch").join("second");
        fs::create_dir(&second).expect("payload");
        let verdict = extract_bundle(&archive, &second);
        assert!(
            matches!(&verdict, Err(UpdateArchiveError::ExtractionRejected(detail)) if detail.contains("tar")),
            "{verdict:?}"
        );
    }
}
