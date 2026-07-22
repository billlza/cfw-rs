use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::read::GzDecoder;
use tar::Archive;
use thiserror::Error;

mod extract;

use extract::extract_archive;

const BUNDLE_ROOT: &str = "Clash for Mac.app";
const INSTALLED_BUNDLE: &str = "/Applications/Clash for Mac.app";
const APPLICATIONS_DIRECTORY: &str = "/Applications";
const INFO_PLIST: &str = "Contents/Info.plist";
const MAIN_EXECUTABLE: &str = "Contents/MacOS/clash-for-mac";
const MAX_ENTRY_COUNT: usize = 50_000;
const MAX_SINGLE_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 1024;
const MAX_EXTENSION_ENTRY_BYTES: u64 = 64 * 1024;
const MAX_TOTAL_EXTENSION_BYTES: u64 = 32 * 1024 * 1024;
const RAW_ENTRY_MULTIPLIER: usize = 4;
const TAR_STREAM_FIXED_OVERHEAD: u64 = 4 * 1024 * 1024;
const TAR_STREAM_ENTRY_OVERHEAD: u64 = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(super) enum UpdateArchiveError {
    #[error("update archive cannot be read during {stage} ({kind:?})")]
    Io {
        stage: &'static str,
        kind: ErrorKind,
    },
    #[error("update archive contains too many entries")]
    TooManyEntries,
    #[error("update archive entry path is not canonical UTF-8 inside the fixed app root")]
    InvalidPath,
    #[error("update archive contains a duplicate or conflicting path")]
    PathConflict,
    #[error("update archive contains a forbidden entry type")]
    ForbiddenEntryType,
    #[error("update archive entry permissions are unsafe")]
    UnsafePermissions,
    #[error("update archive contains an oversized entry")]
    EntryTooLarge,
    #[error("update archive expanded size exceeds its fixed limit")]
    ExpandedSizeExceeded,
    #[error("update archive extension metadata exceeds its fixed limits")]
    ExtensionMetadataExceeded,
    #[error("update archive symlink target is invalid or escapes the app root")]
    InvalidSymlink,
    #[error("update archive omits the canonical app bundle layout")]
    MissingBundleLayout,
    #[error("update archive changed between validation and extraction")]
    PlanMismatch,
    #[error("extracted update has an invalid Info.plist or version")]
    InvalidBundleVersion,
    #[error("extracted update failed {tool} verification")]
    BundleVerification { tool: &'static str },
    #[error("private update staging is not on the installed application's volume")]
    StagingVolumeMismatch,
    #[error("cannot atomically replace the installed application ({0:?})")]
    AtomicReplace(ErrorKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InstallOutcome {
    pub(super) cleanup_warning: Option<ErrorKind>,
}

#[derive(Debug, Clone, Copy)]
struct ArchiveLimits {
    entry_count: usize,
    single_file_bytes: u64,
    expanded_bytes: u64,
}

const RELEASE_LIMITS: ArchiveLimits = ArchiveLimits {
    entry_count: MAX_ENTRY_COUNT,
    single_file_bytes: MAX_SINGLE_FILE_BYTES,
    expanded_bytes: MAX_EXPANDED_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlannedKind {
    Directory,
    File,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedEntry {
    relative_path: PathBuf,
    kind: PlannedKind,
    mode: u32,
    size: u64,
    link_target: Option<PathBuf>,
}

pub(super) fn install_verified_archive(
    bytes: &[u8],
    expected_version: &str,
) -> Result<InstallOutcome, UpdateArchiveError> {
    let plan = validate_archive(bytes, RELEASE_LIMITS)?;
    let staging = tempfile::Builder::new()
        .prefix(".cfw-update-stage-")
        .suffix(".app")
        .tempdir()
        .map_err(|error| io_error("create-staging", error))?;
    let staging_device = fs::symlink_metadata(staging.path())
        .map_err(|error| io_error("inspect-staging", error))?
        .dev();
    let installed_device = fs::symlink_metadata(INSTALLED_BUNDLE)
        .map_err(|error| io_error("inspect-installed", error))?
        .dev();
    if staging_device != installed_device {
        return Err(UpdateArchiveError::StagingVolumeMismatch);
    }
    extract_archive(bytes, &plan, staging.path())?;
    validate_extracted_bundle(staging.path(), expected_version)?;
    verify_bundle(staging.path(), "/usr/bin/codesign", "codesign")?;
    verify_bundle(staging.path(), "/usr/sbin/spctl", "Gatekeeper")?;

    let staging_parent = staging
        .path()
        .parent()
        .ok_or(UpdateArchiveError::InvalidPath)?
        .to_owned();
    atomic_swap(staging.path(), Path::new(INSTALLED_BUNDLE))?;
    let old_bundle = staging.keep();
    let mut cleanup_warning = fs::remove_dir_all(&old_bundle)
        .err()
        .map(|error| error.kind());
    for directory in [Path::new(APPLICATIONS_DIRECTORY), staging_parent.as_path()] {
        if let Err(error) = File::open(directory).and_then(|directory| directory.sync_all())
            && cleanup_warning.is_none()
        {
            cleanup_warning = Some(error.kind());
        }
    }
    Ok(InstallOutcome { cleanup_warning })
}

fn validate_archive(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<Vec<PlannedEntry>, UpdateArchiveError> {
    validate_raw_archive_metadata(bytes, limits)?;
    let decoder = bounded_decoder(bytes, limits)?;
    let mut archive = Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| io_error("read-entries", error))?;
    let mut plan = Vec::new();
    let mut paths = BTreeMap::<PathBuf, PlannedKind>::new();
    let mut required_directories = BTreeSet::<PathBuf>::new();
    let mut expanded_bytes = 0_u64;

    for entry in entries {
        if plan.len() >= limits.entry_count {
            return Err(UpdateArchiveError::TooManyEntries);
        }
        let entry = entry.map_err(|error| io_error("read-entry", error))?;
        let planned = describe_entry(&entry)?;
        if paths.contains_key(&planned.relative_path) {
            return Err(UpdateArchiveError::PathConflict);
        }
        for ancestor in planned.relative_path.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                break;
            }
            if paths
                .get(ancestor)
                .is_some_and(|kind| *kind != PlannedKind::Directory)
            {
                return Err(UpdateArchiveError::PathConflict);
            }
            required_directories.insert(ancestor.to_path_buf());
        }
        if planned.kind != PlannedKind::Directory
            && required_directories.contains(&planned.relative_path)
        {
            return Err(UpdateArchiveError::PathConflict);
        }
        if planned.kind == PlannedKind::File {
            if planned.size > limits.single_file_bytes {
                return Err(UpdateArchiveError::EntryTooLarge);
            }
            expanded_bytes = expanded_bytes
                .checked_add(planned.size)
                .ok_or(UpdateArchiveError::ExpandedSizeExceeded)?;
            if expanded_bytes > limits.expanded_bytes {
                return Err(UpdateArchiveError::ExpandedSizeExceeded);
            }
        }
        paths.insert(planned.relative_path.clone(), planned.kind);
        plan.push(planned);
    }

    if plan.is_empty()
        || paths.get(Path::new("")) != Some(&PlannedKind::Directory)
        || paths.get(Path::new("Contents")) != Some(&PlannedKind::Directory)
        || paths.get(Path::new("Contents/MacOS")) != Some(&PlannedKind::Directory)
        || paths.get(Path::new(INFO_PLIST)) != Some(&PlannedKind::File)
        || paths.get(Path::new(MAIN_EXECUTABLE)) != Some(&PlannedKind::File)
        || required_directories
            .iter()
            .any(|path| paths.get(path) != Some(&PlannedKind::Directory))
    {
        return Err(UpdateArchiveError::MissingBundleLayout);
    }
    if plan.iter().any(|entry| {
        (entry.kind == PlannedKind::Directory && entry.mode & 0o500 != 0o500)
            || (entry.relative_path == Path::new(INFO_PLIST) && entry.mode & 0o400 == 0)
            || (entry.relative_path == Path::new(MAIN_EXECUTABLE) && entry.mode & 0o500 != 0o500)
    }) {
        return Err(UpdateArchiveError::UnsafePermissions);
    }
    Ok(plan)
}

fn validate_raw_archive_metadata(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<(), UpdateArchiveError> {
    let maximum_entries = limits
        .entry_count
        .checked_mul(RAW_ENTRY_MULTIPLIER)
        .ok_or(UpdateArchiveError::TooManyEntries)?;
    let decoder = bounded_decoder(bytes, limits)?;
    let mut archive = Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| io_error("read-raw-entries", error))?
        .raw(true);
    let mut extension_bytes = 0_u64;
    for (entry_index, entry) in entries.enumerate() {
        if entry_index >= maximum_entries {
            return Err(UpdateArchiveError::TooManyEntries);
        }
        let entry = entry.map_err(|error| io_error("read-raw-entry", error))?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_pax_global_extensions()
        {
            if entry.size() > MAX_EXTENSION_ENTRY_BYTES {
                return Err(UpdateArchiveError::ExtensionMetadataExceeded);
            }
            extension_bytes = extension_bytes
                .checked_add(entry.size())
                .ok_or(UpdateArchiveError::ExtensionMetadataExceeded)?;
            if extension_bytes > MAX_TOTAL_EXTENSION_BYTES {
                return Err(UpdateArchiveError::ExtensionMetadataExceeded);
            }
        }
    }
    Ok(())
}

fn describe_entry<R: Read>(entry: &tar::Entry<'_, R>) -> Result<PlannedEntry, UpdateArchiveError> {
    let entry_type = entry.header().entry_type();
    let kind = if entry_type.is_dir() {
        PlannedKind::Directory
    } else if entry_type.is_file() {
        PlannedKind::File
    } else if entry_type.is_symlink() {
        PlannedKind::Symlink
    } else {
        return Err(UpdateArchiveError::ForbiddenEntryType);
    };
    let relative_path = validated_relative_path(&entry.path_bytes(), kind)?;
    let size = entry.size();
    if kind != PlannedKind::File && size != 0 {
        return Err(UpdateArchiveError::ForbiddenEntryType);
    }
    let mode = entry
        .header()
        .mode()
        .map_err(|error| io_error("read-mode", error))?;
    if mode & !0o777 != 0 || (kind != PlannedKind::Symlink && mode & 0o022 != 0) {
        return Err(UpdateArchiveError::UnsafePermissions);
    }
    let link_target = if kind == PlannedKind::Symlink {
        let target = entry
            .link_name_bytes()
            .ok_or(UpdateArchiveError::InvalidSymlink)?;
        Some(validate_symlink_target(&relative_path, &target)?)
    } else {
        None
    };
    Ok(PlannedEntry {
        relative_path,
        kind,
        mode,
        size,
        link_target,
    })
}

fn validated_relative_path(bytes: &[u8], kind: PlannedKind) -> Result<PathBuf, UpdateArchiveError> {
    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES {
        return Err(UpdateArchiveError::InvalidPath);
    }
    let value = std::str::from_utf8(bytes).map_err(|_| UpdateArchiveError::InvalidPath)?;
    if value.starts_with('/') || value.contains('\\') || value.contains("//") {
        return Err(UpdateArchiveError::InvalidPath);
    }
    let canonical = if kind == PlannedKind::Directory {
        value.strip_suffix('/').unwrap_or(value)
    } else {
        value
    };
    if canonical
        .split('/')
        .any(|component| component.starts_with("._") || component == ".DS_Store")
    {
        return Err(UpdateArchiveError::InvalidPath);
    }
    if canonical.is_empty()
        || canonical
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(UpdateArchiveError::InvalidPath);
    }
    let relative = canonical
        .strip_prefix(BUNDLE_ROOT)
        .ok_or(UpdateArchiveError::InvalidPath)?;
    if !relative.is_empty() && !relative.starts_with('/') {
        return Err(UpdateArchiveError::InvalidPath);
    }
    Ok(PathBuf::from(
        relative.strip_prefix('/').unwrap_or(relative),
    ))
}

fn validate_symlink_target(
    relative_path: &Path,
    bytes: &[u8],
) -> Result<PathBuf, UpdateArchiveError> {
    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES {
        return Err(UpdateArchiveError::InvalidSymlink);
    }
    let value = std::str::from_utf8(bytes).map_err(|_| UpdateArchiveError::InvalidSymlink)?;
    if value.starts_with('/') || value.contains('\\') || value.contains("//") {
        return Err(UpdateArchiveError::InvalidSymlink);
    }
    let target = PathBuf::from(value);
    let mut resolved = relative_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();
    for component in value.split('/') {
        match component {
            "" | "." => return Err(UpdateArchiveError::InvalidSymlink),
            ".." => {
                if !resolved.pop() {
                    return Err(UpdateArchiveError::InvalidSymlink);
                }
            }
            normal => resolved.push(normal),
        }
    }
    Ok(target)
}

fn validate_extracted_bundle(
    bundle: &Path,
    expected_version: &str,
) -> Result<(), UpdateArchiveError> {
    for relative in [INFO_PLIST, MAIN_EXECUTABLE] {
        let metadata = fs::symlink_metadata(bundle.join(relative))
            .map_err(|error| io_error("inspect-layout", error))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(UpdateArchiveError::MissingBundleLayout);
        }
    }
    let plist = plist::Value::from_file(bundle.join(INFO_PLIST))
        .map_err(|_| UpdateArchiveError::InvalidBundleVersion)?;
    let version = plist
        .as_dictionary()
        .and_then(|dictionary| dictionary.get("CFBundleShortVersionString"))
        .and_then(plist::Value::as_string)
        .ok_or(UpdateArchiveError::InvalidBundleVersion)?;
    if version != expected_version {
        return Err(UpdateArchiveError::InvalidBundleVersion);
    }
    Ok(())
}

fn verify_bundle(
    bundle: &Path,
    executable: &'static str,
    tool: &'static str,
) -> Result<(), UpdateArchiveError> {
    let mut command = Command::new(executable);
    if tool == "codesign" {
        command.args(["--verify", "--deep", "--strict", "--verbose=2"]);
    } else {
        command.args(["--assess", "--type", "execute"]);
    }
    let status = command
        .arg(bundle)
        .status()
        .map_err(|error| io_error("launch-verifier", error))?;
    if !status.success() {
        return Err(UpdateArchiveError::BundleVerification { tool });
    }
    Ok(())
}

fn atomic_swap(staging: &Path, installed: &Path) -> Result<(), UpdateArchiveError> {
    let staging = CString::new(staging.as_os_str().as_bytes())
        .map_err(|_| UpdateArchiveError::InvalidPath)?;
    let installed = CString::new(installed.as_os_str().as_bytes())
        .map_err(|_| UpdateArchiveError::InvalidPath)?;
    // SAFETY: both C strings are NUL-terminated, point to live memory for the
    // duration of the call, and AT_FDCWD requires no file descriptor ownership.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            staging.as_ptr(),
            libc::AT_FDCWD,
            installed.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result != 0 {
        return Err(UpdateArchiveError::AtomicReplace(
            io::Error::last_os_error().kind(),
        ));
    }
    Ok(())
}

fn io_error(stage: &'static str, error: io::Error) -> UpdateArchiveError {
    UpdateArchiveError::Io {
        stage,
        kind: error.kind(),
    }
}

fn bounded_decoder(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<io::Take<GzDecoder<&[u8]>>, UpdateArchiveError> {
    let entry_overhead = (limits.entry_count as u64)
        .checked_mul(TAR_STREAM_ENTRY_OVERHEAD)
        .ok_or(UpdateArchiveError::ExpandedSizeExceeded)?;
    let maximum = limits
        .expanded_bytes
        .checked_add(entry_overhead)
        .and_then(|value| value.checked_add(TAR_STREAM_FIXED_OVERHEAD))
        .ok_or(UpdateArchiveError::ExpandedSizeExceeded)?;
    Ok(GzDecoder::new(bytes).take(maximum))
}

#[cfg(test)]
#[path = "archive/tests.rs"]
mod tests;
