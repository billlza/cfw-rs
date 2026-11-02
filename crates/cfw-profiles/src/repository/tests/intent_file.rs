//! The replacement intent file: private, canonical, bounded, never followed
//! through a link, and written only when the selected digest changes.

#[cfg(target_os = "macos")]
use std::os::unix::fs::{PermissionsExt as _, symlink};
#[cfg(windows)]
use std::os::windows::fs::symlink_file as symlink;

use super::*;

#[test]
fn same_content_metadata_replace_needs_no_multi_file_intent() {
    let (root, repository, original) = selected_fixture("metadata-only");
    repository
        .replace(
            &original.record.id,
            Some("Renamed without content change"),
            &original.profile,
            Some("https://example.com/rebound"),
        )
        .expect("metadata-only selected replacement");

    let selected = repository
        .load_selected()
        .expect("load metadata replacement")
        .expect("selected profile");
    assert_eq!(selected.record.name, "Renamed without content change");
    assert_eq!(selected.record.digest, original.record.digest);
    assert_eq!(
        selected.source_url.as_deref(),
        Some("https://example.com/rebound")
    );
    assert!(
        !root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn selected_replace_intent_must_be_private_canonical_and_bounded() {
    let (mode_root, mode_repository, mode_original) = selected_fixture("intent-mode");
    stage_selected_replace(&mode_root, &mode_original, &profile("direct-replacement"));
    let mode_path = mode_root.join("profiles").join(SELECTED_REPLACE_FILE_NAME);
    #[cfg(target_os = "macos")]
    fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o644))
        .expect("weaken intent mode for fixture");
    #[cfg(windows)]
    {
        let grant = std::process::Command::new("icacls.exe")
            .arg(&mode_path)
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()
            .unwrap();
        assert!(grant.status.success(), "weaken intent DACL for fixture");
    }
    assert!(matches!(
        mode_repository.snapshot(),
        Err(ProfileError::UnsafeSelectedReplaceFile)
    ));
    fs::remove_dir_all(mode_root).expect("remove mode repository");

    let (canonical_root, canonical_repository, canonical_original) =
        selected_fixture("intent-canonical");
    stage_selected_replace(
        &canonical_root,
        &canonical_original,
        &profile("direct-replacement"),
    );
    let canonical_path = canonical_root
        .join("profiles")
        .join(SELECTED_REPLACE_FILE_NAME);
    let mut noncanonical = fs::read(&canonical_path).expect("read canonical intent");
    noncanonical.push(b'\n');
    write_private(&canonical_path, &noncanonical);
    assert!(matches!(
        canonical_repository.snapshot(),
        Err(ProfileError::InvalidSelectedReplace(_))
    ));
    fs::remove_dir_all(canonical_root).expect("remove canonical repository");

    let (size_root, size_repository, size_original) = selected_fixture("intent-size");
    stage_selected_replace(&size_root, &size_original, &profile("direct-replacement"));
    write_private(
        &size_root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
        &vec![b'x'; crate::MAX_SELECTED_REPLACE_BYTES + 1],
    );
    assert!(matches!(
        size_repository.snapshot(),
        Err(ProfileError::SelectedReplaceTooLarge { .. })
    ));
    fs::remove_dir_all(size_root).expect("remove size repository");
}

#[test]
fn selected_replace_intent_symlink_is_never_followed() {
    let (root, repository, _original) = selected_fixture("intent-symlink");
    let target = root.join("outside-intent");
    write_private(&target, b"not an intent");
    symlink(
        &target,
        root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
    )
    .expect("create intent symlink fixture");

    assert!(matches!(
        repository.snapshot(),
        Err(ProfileError::UnsafeSelectedReplaceFile)
    ));
    assert_eq!(
        fs::read(&target).expect("read symlink target"),
        b"not an intent"
    );
    fs::remove_dir_all(root).expect("remove symlink repository");
}
