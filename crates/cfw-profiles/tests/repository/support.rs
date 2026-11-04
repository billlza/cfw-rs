//! Repositories in fresh temporary directories, sample profiles, and the
//! paths and privacy checks of their stored entries.

use std::fs;
#[cfg(target_os = "macos")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use cfw_profiles::{ProfileError, ProfileRecord, ProfileRepository, ValidatedSingBoxProfile};
use uuid::Uuid;

/// The platform's file symlink, for fixtures that plant one.
#[cfg(target_os = "macos")]
pub(crate) use std::os::unix::fs::symlink;
#[cfg(windows)]
pub(crate) use std::os::windows::fs::symlink_file as symlink;

pub(crate) const MAX_STORED_BYTES: usize = cfw_singbox_config::MAX_PROFILE_BYTES + 256 * 1024;

pub(crate) fn repository(name: &str) -> (PathBuf, ProfileRepository) {
    let root = std::env::temp_dir().join(format!(
        "cfw-profile-repository-{name}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let repository = ProfileRepository::new(root.join("profiles"));
    (root, repository)
}

pub(crate) fn profile() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(
        r#"{"route":{"final":"direct"},"outbounds":[{"tag":"direct","type":"direct"}]}"#,
    )
    .expect("valid profile")
}

pub(crate) fn credential_profile(reference_id: &str) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{reference_id}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"proxy.example.com"}}}}]}}"#
    ))
    .expect("valid credential profile")
}

pub(crate) fn stored_path(root: &std::path::Path, id: &str) -> PathBuf {
    root.join("profiles").join(format!("{id}.profile.json"))
}

pub(crate) fn selection_path(root: &std::path::Path) -> PathBuf {
    root.join("profiles").join("selected-profile-v1.json")
}

/// The valid profiles of a repository these tests expect to hold no invalid
/// entry; one would fail the call instead of being left out.
pub(crate) fn listed(repository: &ProfileRepository) -> Result<Vec<ProfileRecord>, ProfileError> {
    let snapshot = repository.snapshot()?;
    assert!(
        snapshot.invalid_profiles.is_empty(),
        "unexpected invalid profiles: {:?}",
        snapshot.invalid_profiles
    );
    Ok(snapshot.profiles)
}

pub(crate) fn create_private_directory(path: &std::path::Path) {
    #[cfg(target_os = "macos")]
    {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    cfw_windows_storage::PrivateDirectory::open_or_create(path).unwrap();
}

pub(crate) fn assert_private_file(path: &std::path::Path) {
    #[cfg(target_os = "macos")]
    {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.nlink(), 1);
    }
    #[cfg(windows)]
    cfw_windows_storage::validate_private_file(&fs::File::open(path).unwrap()).unwrap();
}

pub(crate) fn assert_private_directory(path: &std::path::Path) {
    #[cfg(target_os = "macos")]
    {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    }
    #[cfg(windows)]
    assert!(
        cfw_windows_storage::PrivateDirectory::open_existing(path)
            .unwrap()
            .is_some()
    );
}

pub(crate) fn weaken_file_privacy(path: &std::path::Path) {
    #[cfg(target_os = "macos")]
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    #[cfg(windows)]
    {
        let grant = std::process::Command::new("icacls.exe")
            .arg(path)
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()
            .unwrap();
        assert!(grant.status.success(), "weaken fixture DACL");
    }
}

pub(crate) fn application_entries(path: &std::path::Path) -> Vec<fs::DirEntry> {
    let entries = fs::read_dir(path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    #[cfg(windows)]
    {
        let lock = path.join(".cfw-storage-lock-v1");
        assert_private_file(&lock);
        assert_eq!(fs::metadata(&lock).unwrap().len(), 0);
        entries
            .into_iter()
            .filter(|entry| entry.file_name() != ".cfw-storage-lock-v1")
            .collect()
    }
    #[cfg(target_os = "macos")]
    entries
}
