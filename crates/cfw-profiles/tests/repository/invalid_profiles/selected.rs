//! A selected invalid profile: reported, never started, deleted only with
//! the engine off, and replaced by selecting a valid profile.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError, ProfileSelectionState};

use crate::invalid_profiles::{
    EARLIER_REALITY_DIGEST, EARLIER_REALITY_ENVELOPE, EARLIER_REALITY_ID,
    EARLIER_REALITY_SELECTION, earlier_label, is_earlier_invalid, reality_requires_utls,
    store_earlier_reality_profile,
};
use crate::private_file_fixture::write_private;
use crate::support::{profile, repository, selection_path};

#[test]
fn selected_invalid_profile_is_reported_and_never_started_or_replaced() {
    let (root, repository) = repository("earlier-selected");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    store_earlier_reality_profile(&root, true);

    let snapshot = repository.snapshot().expect("snapshot");
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(EARLIER_REALITY_ID)
    );
    assert_eq!(snapshot.invalid_profiles[0].id, EARLIER_REALITY_ID);
    for error in [
        repository.load_selected().map(|_| ()).expect_err("load"),
        repository
            .require_selected()
            .map(|_| ())
            .expect_err("require"),
        repository.lock_selected().map(|_| ()).expect_err("lock"),
    ] {
        assert!(is_earlier_invalid(&error), "{error}");
    }
    {
        let mutation = repository
            .begin_credential_profile_mutation()
            .expect("mutation lock");
        let state = mutation.selected_profile().expect("selection state");
        assert!(matches!(
            &state,
            ProfileSelectionState::Invalid(record)
                if record.id == EARLIER_REALITY_ID && record.error == reality_requires_utls()
        ));
        assert_eq!(state.clone().into_valid(), None);
        let error = state.into_loaded().expect_err("invalid selection");
        assert!(is_earlier_invalid(&error), "{error}");
    }

    // Choosing a valid profile is the in-app way off an invalid selection.
    repository
        .select(&other.id)
        .expect("select a valid profile");
    assert_eq!(
        repository
            .require_selected()
            .expect("valid selection")
            .record
            .id,
        other.id
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn deleting_the_selected_invalid_profile_needs_the_engine_off_and_selects_nothing() {
    let (root, repository) = repository("earlier-selected-delete");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    let path = store_earlier_reality_profile(&root, true);

    let error = repository
        .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
        .expect_err("a selected profile is kept while the engine may run");
    assert!(matches!(
        &error,
        ProfileError::InvalidSelectionKept(profile) if *profile == earlier_label()
    ));
    assert_eq!(
        error.to_string(),
        "the selected profile \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d) is invalid; deleting it would also clear the selection"
    );
    assert_eq!(
        fs::read_to_string(&path).expect("envelope kept"),
        EARLIER_REALITY_ENVELOPE
    );
    assert_eq!(
        fs::read_to_string(selection_path(&root)).expect("selection kept"),
        EARLIER_REALITY_SELECTION
    );

    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Clear)
            .expect("delete with the engine Off")
    );
    assert!(!path.exists());
    assert!(!selection_path(&root).exists());
    let snapshot = repository.snapshot().expect("snapshot after deletion");
    assert_eq!(snapshot.selected_profile_id, None);
    assert!(snapshot.invalid_profiles.is_empty());
    assert_eq!(snapshot.profiles.len(), 1);
    assert_eq!(snapshot.profiles[0].id, other.id);
    assert!(
        repository.load_selected().expect("no selection").is_none(),
        "no other profile is selected in its place"
    );
    assert!(matches!(
        repository.require_selected(),
        Err(ProfileError::NoSelectedProfile)
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_selection_bound_to_another_digest_of_an_invalid_profile_fails_closed() {
    let (root, repository) = repository("earlier-stale-selection");
    repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    store_earlier_reality_profile(&root, true);
    write_private(
        &selection_path(&root),
        EARLIER_REALITY_SELECTION
            .replacen(EARLIER_REALITY_DIGEST, &"11".repeat(32), 1)
            .as_bytes(),
    );
    assert!(matches!(
        repository.snapshot(),
        Err(ProfileError::SelectedProfileDigestMismatch { id, .. }) if id == EARLIER_REALITY_ID
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn selecting_a_valid_profile_repairs_a_stale_selection_of_an_invalid_one() {
    let (root, repository) = repository("earlier-stale-repair");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    store_earlier_reality_profile(&root, true);
    let stale = EARLIER_REALITY_SELECTION.replacen(EARLIER_REALITY_DIGEST, &"11".repeat(32), 1);
    write_private(&selection_path(&root), stale.as_bytes());
    for result in [
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Clear)
            .map(|_| ()),
        repository.import(Some("Blocked"), &profile()).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(ProfileError::SelectedProfileDigestMismatch { id, .. }) if id == EARLIER_REALITY_ID
        ));
    }
    assert_eq!(
        fs::read_to_string(selection_path(&root)).expect("selection kept"),
        stale
    );

    repository
        .select(&other.id)
        .expect("selecting a valid profile replaces the stale record");
    let snapshot = repository.snapshot().expect("snapshot");
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(other.id.as_str())
    );
    assert_eq!(snapshot.invalid_profiles[0].id, EARLIER_REALITY_ID);
    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
            .expect("delete the unselected invalid profile")
    );
    fs::remove_dir_all(root).expect("remove test directory");
}
