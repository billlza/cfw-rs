//! Recovery of an interrupted selected-profile replacement: an untouched
//! intent aborts, a committed profile rolls the selection forward and a
//! finished one is cleaned up, also for an entry that no longer validates.

use super::*;

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
