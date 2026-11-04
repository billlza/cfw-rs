//! The subscription source of an invalid entry, read so the subscription
//! can be imported again before the entry is deleted.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError};

use crate::invalid_profiles::{
    EARLIER_REALITY_DIGEST, EARLIER_REALITY_ENVELOPE, EARLIER_REALITY_ID,
    store_earlier_reality_profile,
};
use crate::private_file_fixture::write_private;
use crate::support::{create_private_directory, profile, repository, stored_path};

#[test]
fn the_source_of_an_invalid_subscription_can_be_read_and_imported_again() {
    const URL: &str = "https://subscription.example/profile?token=private-test-value";
    let (root, repository) = repository("earlier-reimport");
    let local = repository
        .import(Some("Local"), &profile())
        .expect("import local profile");
    store_earlier_reality_profile(&root, false);

    assert_eq!(
        repository
            .source_url(EARLIER_REALITY_ID)
            .expect("source of the invalid entry")
            .as_deref(),
        Some(URL)
    );
    assert_eq!(
        repository
            .source_url(&local.id)
            .expect("source of a local profile"),
        None
    );
    assert!(matches!(
        repository.source_url("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        Err(ProfileError::ProfileNotFound(id)) if id == "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    ));

    let replacement = repository
        .import_with_source(Some("Reality node"), &profile(), Some(URL))
        .expect("the same subscription imports beside the invalid entry");
    assert_eq!(
        repository
            .source_url(&replacement.id)
            .expect("replacement source")
            .as_deref(),
        Some(URL)
    );
    repository
        .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
        .expect("delete the old entry");
    let snapshot = repository.snapshot().expect("snapshot");
    assert!(snapshot.invalid_profiles.is_empty());
    assert_eq!(snapshot.profiles.len(), 2);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn the_source_of_a_damaged_missing_or_malformed_entry_is_not_read() {
    let (root, repository) = repository("earlier-source-errors");
    assert!(matches!(
        repository.source_url(EARLIER_REALITY_ID),
        Err(ProfileError::ProfileNotFound(id)) if id == EARLIER_REALITY_ID
    ));
    repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    write_private(
        &stored_path(&root, EARLIER_REALITY_ID),
        EARLIER_REALITY_ENVELOPE
            .replacen(EARLIER_REALITY_DIGEST, &"00".repeat(32), 1)
            .as_bytes(),
    );
    assert!(matches!(
        repository.source_url(EARLIER_REALITY_ID),
        Err(ProfileError::DigestMismatch { id }) if id == EARLIER_REALITY_ID
    ));
    assert!(matches!(
        repository.source_url("../x"),
        Err(ProfileError::InvalidProfileId(_))
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_repository_holding_only_a_selected_invalid_profile_admits_its_replacement() {
    const URL: &str = "https://subscription.example/profile?token=private-test-value";
    let (root, repository) = repository("earlier-only");
    create_private_directory(&root.join("profiles"));
    store_earlier_reality_profile(&root, true);

    let snapshot = repository.snapshot().expect("snapshot");
    assert!(snapshot.profiles.is_empty());
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(EARLIER_REALITY_ID)
    );
    let url = repository
        .source_url(EARLIER_REALITY_ID)
        .expect("source")
        .expect("subscription URL");
    assert_eq!(url, URL);
    let replacement = repository
        .import_with_source(Some("Reality node"), &profile(), Some(&url))
        .expect("import the subscription again");
    repository
        .select(&replacement.id)
        .expect("select the replacement");
    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
            .expect("delete the old entry")
    );
    let snapshot = repository.snapshot().expect("snapshot");
    assert_eq!(snapshot.profiles.len(), 1);
    assert!(snapshot.invalid_profiles.is_empty());
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(replacement.id.as_str())
    );
    fs::remove_dir_all(root).expect("remove test directory");
}
