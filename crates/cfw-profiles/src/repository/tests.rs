use std::fs;
#[cfg(target_os = "macos")]
use std::os::unix::fs::{PermissionsExt as _, symlink};
#[cfg(windows)]
use std::os::windows::fs::symlink_file as symlink;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::{
    ProfileRepository, ProfileSourceKind, SelectedProfileReplaceIntent, StoredProfile,
    ensure_credential_reference_capacity, ensure_repository_bytes, sha256_hex,
    stored_envelope_digest,
};
use crate::envelope::{encode_with_timestamp, profile_file_name};
use crate::selection::{ProfileSelection, encode as encode_selection};
use crate::{
    MAX_REPOSITORY_BYTES, MAX_REPOSITORY_CREDENTIAL_REFERENCES, ProfileError,
    SELECTED_REPLACE_FILE_NAME, SELECTION_FILE_NAME, ValidatedSingBoxProfile,
};

fn repository(name: &str) -> (PathBuf, ProfileRepository) {
    let root = std::env::temp_dir().join(format!(
        "cfw-selected-replace-{name}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let repository = ProfileRepository::new(root.join("profiles"));
    (root, repository)
}

fn profile(tag: &str) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"route":{{"final":"{tag}"}},"outbounds":[{{"tag":"{tag}","type":"direct"}}]}}"#
    ))
    .expect("valid profile")
}

use crate::private_file_fixture::write_private;

fn stage_selected_replace(
    root: &Path,
    original: &StoredProfile,
    replacement: &ValidatedSingBoxProfile,
) -> (SelectedProfileReplaceIntent, Vec<u8>) {
    let replacement_bytes = encode_with_timestamp(
        &original.record.id,
        "Replacement",
        replacement,
        original.source_url.as_deref(),
        original.record.created_epoch_secs + 1,
    )
    .expect("replacement envelope");
    let intent = SelectedProfileReplaceIntent::new(
        &original.record.id,
        &original.record.digest,
        replacement.digest(),
        &stored_envelope_digest(original).expect("original envelope digest"),
        &sha256_hex(&replacement_bytes),
    )
    .expect("replacement intent");
    write_private(
        &root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
        &intent.encode().expect("intent bytes"),
    );
    (intent, replacement_bytes)
}

fn selected_fixture(name: &str) -> (PathBuf, ProfileRepository, StoredProfile) {
    let (root, repository) = repository(name);
    let imported = repository
        .import(Some("Original"), &profile("direct-original"))
        .expect("import original");
    repository.select(&imported.id).expect("select original");
    let original = repository
        .load_selected()
        .expect("load selected")
        .expect("selected original");
    (root, repository, original)
}

#[test]
fn profile_lists_derive_source_kind_without_disclosing_subscription_urls() {
    let (root, repository) = repository("source-kind");
    let local = repository
        .import(Some("本地-示例-09.18"), &profile("local"))
        .expect("local import");
    let subscription = repository
        .import_with_source(
            Some("Subscription"),
            &profile("remote"),
            Some("https://subscription.example/profile?token=private-test-value"),
        )
        .expect("subscription import");
    repository.select(&local.id).expect("select local");
    let snapshot = repository
        .snapshot()
        .expect("list without loading profiles individually");
    let local_record = snapshot
        .profiles
        .iter()
        .find(|record| record.id == local.id)
        .expect("local record");
    let remote_record = snapshot
        .profiles
        .iter()
        .find(|record| record.id == subscription.id)
        .expect("subscription record");
    assert_eq!(local_record.source_kind, ProfileSourceKind::Local);
    assert_eq!(local_record.name, "本地-示例-09.18");
    assert_eq!(remote_record.source_kind, ProfileSourceKind::Subscription);
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(local.id.as_str())
    );
    let json = serde_json::to_string(&snapshot).expect("serialize list");
    assert!(!json.contains("subscription.example"));
    assert!(!json.contains("private-test-value"));
    assert!(!json.contains("source_url"));
    for id in [&local.id, &subscription.id] {
        let stored: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join("profiles").join(profile_file_name(id))).expect("read envelope"),
        )
        .expect("parse envelope");
        assert_eq!(stored["schema_version"], 1);
        assert!(
            stored.get("source_kind").is_none(),
            "source kind is derived, not persisted"
        );
    }
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn source_kind_tracks_metadata_changes_and_rollback() {
    let (root, repository, original) = selected_fixture("source-kind-update");
    let record = repository
        .update_metadata(
            &original.record.id,
            Some("Renamed"),
            Some("https://subscription.example/profile"),
        )
        .expect("bind subscription");
    assert_eq!(record.source_kind, ProfileSourceKind::Subscription);
    assert_eq!(
        record.created_epoch_secs,
        original.record.created_epoch_secs
    );
    let rebound = repository
        .load_selected()
        .expect("load selection")
        .expect("selected");
    assert_eq!(rebound.record, record);
    assert_eq!(rebound.profile, original.profile);
    repository
        .restore(&original)
        .expect("restore local metadata");
    assert_eq!(
        repository.load_selected().expect("load restored"),
        Some(original.clone())
    );
    let mut inconsistent = original;
    inconsistent.record.source_kind = ProfileSourceKind::Subscription;
    assert!(matches!(
        repository.restore(&inconsistent),
        Err(ProfileError::SourceKindMismatch { .. })
    ));
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn aggregate_repository_limit_is_checked_before_a_new_write() {
    ensure_repository_bytes(MAX_REPOSITORY_BYTES - 1, 1).expect("exact limit is admitted");
    assert!(matches!(
        ensure_repository_bytes(MAX_REPOSITORY_BYTES, 1),
        Err(ProfileError::RepositoryTooLarge { actual })
            if actual == MAX_REPOSITORY_BYTES + 1
    ));
    assert!(matches!(
        ensure_repository_bytes(u64::MAX, 1),
        Err(ProfileError::RepositoryTooLarge { actual: u64::MAX })
    ));
}

#[test]
fn aggregate_credential_refs_cannot_exceed_the_native_vault_capacity() {
    ensure_credential_reference_capacity(MAX_REPOSITORY_CREDENTIAL_REFERENCES)
        .expect("exact vault capacity is admitted");
    assert!(matches!(
        ensure_credential_reference_capacity(MAX_REPOSITORY_CREDENTIAL_REFERENCES + 1),
        Err(ProfileError::TooManyCredentialReferences)
    ));
}

#[test]
fn selected_replace_recovery_aborts_an_untouched_intent_idempotently() {
    let (root, repository, original) = selected_fixture("old-old");
    stage_selected_replace(&root, &original, &profile("direct-replacement"));

    assert_eq!(
        repository
            .load_selected()
            .expect("recover untouched intent")
            .expect("selected original"),
        original
    );
    assert!(
        !root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    assert_eq!(
        repository
            .load_selected()
            .expect("repeat recovered read")
            .expect("selected original"),
        original
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn selected_replace_recovery_rolls_selection_forward_after_profile_commit() {
    let (root, repository, original) = selected_fixture("new-old");
    let replacement = profile("direct-replacement");
    let (_intent, replacement_bytes) = stage_selected_replace(&root, &original, &replacement);
    write_private(
        &root
            .join("profiles")
            .join(profile_file_name(&original.record.id)),
        &replacement_bytes,
    );

    let recovered = repository
        .load_selected()
        .expect("roll selection forward")
        .expect("selected replacement");
    assert_eq!(recovered.profile, replacement);
    assert_eq!(recovered.record.name, "Replacement");
    assert!(
        !root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    assert_eq!(
        repository
            .load_selected()
            .expect("repeat recovered read")
            .expect("selected replacement"),
        recovered
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn selected_replace_recovery_cleans_an_already_committed_intent() {
    let (root, repository, original) = selected_fixture("new-new");
    let replacement = profile("direct-replacement");
    let (_intent, replacement_bytes) = stage_selected_replace(&root, &original, &replacement);
    write_private(
        &root
            .join("profiles")
            .join(profile_file_name(&original.record.id)),
        &replacement_bytes,
    );
    let replacement_selection = ProfileSelection::new(&original.record.id, replacement.digest())
        .expect("replacement selection");
    write_private(
        &root.join("profiles").join(SELECTION_FILE_NAME),
        &encode_selection(&replacement_selection).expect("selection bytes"),
    );

    assert_eq!(
        repository
            .load_selected()
            .expect("clean committed intent")
            .expect("selected replacement")
            .profile,
        replacement
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
fn selected_replace_recovery_never_overwrites_a_different_selection() {
    let (root, repository, original) = selected_fixture("selection-changed");
    let other = repository
        .import(Some("Other"), &profile("direct-other"))
        .expect("import other profile");
    let replacement = profile("direct-replacement");
    let (_intent, replacement_bytes) = stage_selected_replace(&root, &original, &replacement);
    write_private(
        &root
            .join("profiles")
            .join(profile_file_name(&original.record.id)),
        &replacement_bytes,
    );
    let other_selection = ProfileSelection::new(&other.id, &other.digest).expect("other selection");
    let other_selection_bytes = encode_selection(&other_selection).expect("selection bytes");
    write_private(
        &root.join("profiles").join(SELECTION_FILE_NAME),
        &other_selection_bytes,
    );

    assert!(matches!(
        repository.snapshot(),
        Err(ProfileError::SelectedReplaceConflict(_))
    ));
    assert_eq!(
        fs::read(root.join("profiles").join(SELECTION_FILE_NAME))
            .expect("read preserved selection"),
        other_selection_bytes
    );
    assert!(
        root.join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn selected_replace_recovery_preserves_intent_when_required_state_is_missing() {
    let (root, repository, original) = selected_fixture("missing-selection");
    stage_selected_replace(&root, &original, &profile("direct-replacement"));
    fs::remove_file(root.join("profiles").join(SELECTION_FILE_NAME))
        .expect("remove selection for fault fixture");

    assert!(matches!(
        repository.load_selected(),
        Err(ProfileError::SelectedReplaceConflict(_))
    ));
    assert!(
        root.join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    fs::remove_dir_all(root).expect("remove test repository");
}

#[test]
fn selected_replace_recovery_rejects_a_missing_or_third_profile_envelope() {
    let (missing_root, missing_repository, missing_original) = selected_fixture("missing-profile");
    stage_selected_replace(
        &missing_root,
        &missing_original,
        &profile("direct-replacement"),
    );
    fs::remove_file(
        missing_root
            .join("profiles")
            .join(profile_file_name(&missing_original.record.id)),
    )
    .expect("remove profile for fault fixture");
    assert!(matches!(
        missing_repository.snapshot(),
        Err(ProfileError::SelectedReplaceConflict(_))
    ));
    assert!(
        missing_root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    fs::remove_dir_all(missing_root).expect("remove missing-profile repository");

    let (third_root, third_repository, third_original) = selected_fixture("third-profile");
    stage_selected_replace(&third_root, &third_original, &profile("direct-replacement"));
    let third_bytes = encode_with_timestamp(
        &third_original.record.id,
        "Unexpected third state",
        &profile("direct-third"),
        third_original.source_url.as_deref(),
        third_original.record.created_epoch_secs + 2,
    )
    .expect("third envelope");
    write_private(
        &third_root
            .join("profiles")
            .join(profile_file_name(&third_original.record.id)),
        &third_bytes,
    );
    assert!(matches!(
        third_repository.snapshot(),
        Err(ProfileError::SelectedReplaceConflict(_))
    ));
    assert!(
        third_root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    fs::remove_dir_all(third_root).expect("remove third-profile repository");
}

/// A selected Reality node rewritten as a build before Reality required
/// uTLS stored it: digest and selection follow the edited document.
/// Returns the id, the stored digest and the canonical envelope bytes.
fn store_selected_invalid(
    root: &Path,
    repository: &ProfileRepository,
) -> (String, String, Vec<u8>) {
    let reality = ValidatedSingBoxProfile::parse(
            r#"{"outbounds":[{"type":"http","tag":"proxy","server":"proxy.example.com","server_port":443,"tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}}]}"#,
        )
        .expect("Reality with uTLS");
    let imported = repository
        .import(Some("Reality node"), &reality)
        .expect("import Reality node");
    repository
        .select(&imported.id)
        .expect("select Reality node");
    let earlier =
        reality
            .as_json()
            .replacen(r#","utls":{"enabled":true,"fingerprint":"chrome"}"#, "", 1);
    let digest = sha256_hex(earlier.as_bytes());
    let profiles = root.join("profiles");
    let envelope = fs::read_to_string(profiles.join(profile_file_name(&imported.id)))
        .expect("read envelope")
        .replacen(reality.as_json(), &earlier, 1)
        .replacen(reality.digest(), &digest, 1);
    write_private(
        &profiles.join(profile_file_name(&imported.id)),
        envelope.as_bytes(),
    );
    write_private(
        &profiles.join(SELECTION_FILE_NAME),
        &encode_selection(&ProfileSelection::new(&imported.id, &digest).expect("selection"))
            .expect("selection bytes"),
    );
    (imported.id, digest, envelope.into_bytes())
}

#[test]
fn selected_replace_recovery_resolves_an_entry_that_no_longer_validates() {
    // Aborted: the intent replaced the entry that is now invalid.
    let (root, aborted) = repository("invalid-intent-previous");
    let (id, digest, envelope) = store_selected_invalid(&root, &aborted);
    let replacement = profile("direct-replacement");
    let replacement_bytes =
        encode_with_timestamp(&id, "Replacement", &replacement, None, 1).expect("replacement");
    let intent = SelectedProfileReplaceIntent::new(
        &id,
        &digest,
        replacement.digest(),
        &sha256_hex(&envelope),
        &sha256_hex(&replacement_bytes),
    )
    .expect("intent");
    write_private(
        &root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
        &intent.encode().expect("intent bytes"),
    );
    let snapshot = aborted.snapshot().expect("recover the untouched intent");
    assert!(
        !root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    assert_eq!(snapshot.selected_profile_id.as_deref(), Some(id.as_str()));
    assert_eq!(snapshot.invalid_profiles[0].id, id);
    fs::remove_dir_all(root).expect("remove test repository");

    // Rolled forward: the replacement written before the interruption is
    // the entry that is now invalid.
    let (root, rolled) = repository("invalid-intent-replacement");
    let original = profile("direct-original");
    let (id, digest, envelope) = store_selected_invalid(&root, &rolled);
    let original_bytes =
        encode_with_timestamp(&id, "Original", &original, None, 1).expect("original");
    let intent = SelectedProfileReplaceIntent::new(
        &id,
        original.digest(),
        &digest,
        &sha256_hex(&original_bytes),
        &sha256_hex(&envelope),
    )
    .expect("intent");
    write_private(
        &root.join("profiles").join(SELECTED_REPLACE_FILE_NAME),
        &intent.encode().expect("intent bytes"),
    );
    write_private(
        &root.join("profiles").join(SELECTION_FILE_NAME),
        &encode_selection(&ProfileSelection::new(&id, original.digest()).expect("selection"))
            .expect("selection bytes"),
    );
    let snapshot = rolled.snapshot().expect("roll the selection forward");
    assert!(
        !root
            .join("profiles")
            .join(SELECTED_REPLACE_FILE_NAME)
            .exists()
    );
    assert_eq!(snapshot.selected_profile_id.as_deref(), Some(id.as_str()));
    assert_eq!(snapshot.invalid_profiles[0].id, id);
    assert!(matches!(
        rolled.load_selected(),
        Err(ProfileError::StoredProfileInvalid { id: invalid, .. }) if invalid == id
    ));
    fs::remove_dir_all(root).expect("remove test repository");
}

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
