//! An invalid entry is never loaded, selected, rewritten or restored, and
//! it blocks credential cleanup until it is deleted.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError};

use crate::invalid_profiles::{
    EARLIER_REALITY_ENVELOPE, EARLIER_REALITY_ID, earlier_label, is_earlier_invalid,
    store_earlier_reality_profile,
};
use crate::support::{credential_profile, profile, repository, selection_path};

#[test]
fn invalid_profile_is_never_loaded_selected_or_rewritten() {
    let (root, repository) = repository("earlier-refused");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    repository.select(&other.id).expect("select other profile");
    let path = store_earlier_reality_profile(&root, false);
    let selection = fs::read(selection_path(&root)).expect("read selection");

    let error = repository
        .load(EARLIER_REALITY_ID)
        .expect_err("load is refused");
    assert!(is_earlier_invalid(&error), "{error}");
    assert_eq!(
        error.to_string(),
        "stored profile \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d) is invalid: unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
    );
    // Each attempt releases the repository lock before the next one runs.
    let attempts: [&dyn Fn() -> Result<(), ProfileError>; 5] = [
        &|| repository.select(EARLIER_REALITY_ID).map(|_| ()),
        &|| {
            repository
                .replace(EARLIER_REALITY_ID, None, &profile(), None)
                .map(|_| ())
        },
        &|| {
            repository
                .update_metadata(EARLIER_REALITY_ID, Some("Renamed"), None)
                .map(|_| ())
        },
        &|| {
            repository
                .begin_credential_profile_mutation()?
                .profile(EARLIER_REALITY_ID)
                .map(|_| ())
        },
        &|| {
            repository
                .begin_credential_profile_mutation()?
                .commit_selection(EARLIER_REALITY_ID)
                .map(|_| ())
        },
    ];
    for attempt in attempts {
        let error = attempt().expect_err("an invalid profile is refused");
        assert!(is_earlier_invalid(&error), "{error}");
    }
    // An exact-id import, such as a migration replay, names the invalid entry.
    let error = repository
        .import_with_id_and_source(EARLIER_REALITY_ID, Some("Reality node"), &profile(), None)
        .expect_err("the id is taken by an invalid entry");
    assert!(is_earlier_invalid(&error), "{error}");
    assert_eq!(
        fs::read_to_string(&path).expect("read envelope"),
        EARLIER_REALITY_ENVELOPE
    );
    assert_eq!(
        fs::read(selection_path(&root)).expect("read selection"),
        selection
    );
    assert_eq!(
        repository
            .require_selected()
            .expect("selection unchanged")
            .record
            .id,
        other.id
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn credential_cleanup_is_refused_while_an_invalid_profile_is_listed() {
    let (root, repository) = repository("earlier-credential-cleanup");
    let other = repository
        .import(
            Some("Other"),
            &credential_profile("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        )
        .expect("import other profile");
    store_earlier_reality_profile(&root, false);

    for error in [
        repository
            .credential_snapshot()
            .map(|_| ())
            .expect_err("snapshot refused"),
        repository
            .lock_credential_snapshot()
            .map(|_| ())
            .expect_err("locked snapshot refused"),
    ] {
        assert!(matches!(
            &error,
            ProfileError::CredentialCleanupBlocked { profiles } if *profiles == [earlier_label()]
        ));
        assert_eq!(
            error.to_string(),
            "credential cleanup needs every stored profile to pass validation; delete the invalid profiles first: \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d)"
        );
    }

    repository
        .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
        .expect("delete invalid profile");
    let snapshot = repository
        .credential_snapshot()
        .expect("cleanup is available again");
    assert_eq!(snapshot.profile_count, 1);
    assert_eq!(snapshot.catalog[0].audience.profile_id(), other.id);
    assert!(repository.lock_credential_snapshot().is_ok());
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_loaded_profile_that_later_fails_validation_is_never_replaced_or_restored() {
    const URL: &str = "https://subscription.example/profile?token=private-test-value";
    let (root, repository) = repository("earlier-stale-load");
    repository
        .import_with_id_and_source(
            EARLIER_REALITY_ID,
            Some("Reality node"),
            &profile(),
            Some(URL),
        )
        .expect("import a valid profile under the earlier id");
    let stored = repository
        .load(EARLIER_REALITY_ID)
        .expect("load")
        .expect("stored profile");
    let path = store_earlier_reality_profile(&root, false);

    let attempts: [&dyn Fn() -> Result<(), ProfileError>; 4] = [
        &|| {
            repository
                .begin_credential_profile_mutation_if_unchanged(&stored)
                .map(|_| ())
        },
        &|| {
            repository
                .replace_if_unchanged(&stored, None, &profile(), Some(URL))
                .map(|_| ())
        },
        &|| repository.restore(&stored).map(|_| ()),
        &|| {
            repository
                .restore_if_unchanged(&stored, &stored)
                .map(|_| ())
        },
    ];
    for attempt in attempts {
        let error = attempt().expect_err("an invalid entry is never overwritten");
        assert!(is_earlier_invalid(&error), "{error}");
    }
    assert_eq!(
        fs::read_to_string(&path).expect("read envelope"),
        EARLIER_REALITY_ENVELOPE
    );
    fs::remove_dir_all(root).expect("remove test directory");
}
