//! Replacing a profile in place: stable identity, rollback, compare-and-swap
//! updates and metadata edits.

use std::fs;

use cfw_profiles::{ProfileError, StoredProfile};

use crate::support::{application_entries, credential_profile, profile, repository};

#[test]
fn replace_keeps_identity_credentials_and_rebinds_the_selection_digest() {
    let (root, repository) = repository("replace");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/sub"),
        )
        .expect("import remote profile");
    repository.select(&imported.id).expect("select profile");

    let replacement = credential_profile("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    let saved = repository
        .replace(
            &imported.id,
            None,
            &replacement,
            Some("https://example.com/sub2"),
        )
        .expect("replace profile");
    assert_eq!(saved.id, imported.id, "identity must be stable");
    assert_eq!(saved.name, "Remote", "the name is preserved by default");
    assert_eq!(saved.digest, replacement.digest());

    // The selection is rebound under the same lock, so the repository is
    // readable and the selected profile is the replacement.
    let selected = repository
        .load_selected()
        .expect("load selection after replace")
        .expect("selected profile");
    assert_eq!(selected.record.id, imported.id);
    assert_eq!(selected.record.digest, replacement.digest());
    assert_eq!(
        selected.source_url.as_deref(),
        Some("https://example.com/sub2")
    );
    assert_eq!(
        selected.profile.credential_references(),
        replacement.credential_references()
    );
    assert_eq!(
        repository
            .credential_snapshot()
            .expect("credential snapshot")
            .catalog
            .into_iter()
            .flat_map(|entry| entry.references)
            .collect::<Vec<_>>(),
        replacement.credential_references(),
        "the replaced document's credential references are no longer live"
    );

    // Only one entry plus the selection exists: replacing never adds a profile.
    let entries = application_entries(&root.join("profiles"));
    assert_eq!(entries.len(), 2);

    assert!(matches!(
        repository.replace(
            "34db18b6-9903-4e9f-8854-15648e19e4f3",
            None,
            &profile(),
            None
        ),
        Err(ProfileError::Io(_))
    ));
    assert!(matches!(
        repository.replace("not-a-uuid", None, &profile(), None),
        Err(ProfileError::InvalidProfileId(_))
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn rollback_restore_preserves_the_complete_loaded_profile_identity() {
    let (root, repository) = repository("restore");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/original"),
        )
        .expect("import original profile");
    repository.select(&imported.id).expect("select profile");
    let original = repository
        .load(&imported.id)
        .expect("load original")
        .expect("original profile");

    repository
        .replace(
            &imported.id,
            Some("Replacement"),
            &profile(),
            Some("https://example.com/replacement"),
        )
        .expect("replace before rollback");
    repository
        .restore(&original)
        .expect("restore exact profile");

    assert_eq!(
        repository
            .load_selected()
            .expect("load restored selection")
            .expect("restored selected profile"),
        original
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn conditional_replace_rejects_rebound_sources_and_out_of_order_responses() {
    let (root, repository) = repository("conditional-replace");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/original"),
        )
        .expect("import remote profile");
    let before_rebind = repository
        .load(&imported.id)
        .expect("load before rebind")
        .expect("stored profile");
    repository
        .update_metadata(
            &imported.id,
            Some("Rebound"),
            Some("https://example.com/rebound"),
        )
        .expect("rebind subscription source");

    let stale_response = credential_profile("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    assert!(matches!(
        repository.replace_if_unchanged(
            &before_rebind,
            None,
            &stale_response,
            Some("https://example.com/original")
        ),
        Err(ProfileError::ProfileChanged { ref id }) if id == &imported.id
    ));
    let rebound = repository
        .load(&imported.id)
        .expect("load after stale response")
        .expect("stored profile");
    assert_eq!(rebound.record.name, "Rebound");
    assert_eq!(
        rebound.source_url.as_deref(),
        Some("https://example.com/rebound")
    );
    assert_eq!(rebound.profile, before_rebind.profile);

    let first_fetch_snapshot = rebound.clone();
    let second_fetch_snapshot = rebound.clone();
    let newest_response = credential_profile("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    let older_response = credential_profile("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
    repository
        .replace_if_unchanged(
            &second_fetch_snapshot,
            None,
            &newest_response,
            second_fetch_snapshot.source_url.as_deref(),
        )
        .expect("newest response commits first");
    assert!(matches!(
        repository.replace_if_unchanged(
            &first_fetch_snapshot,
            None,
            &older_response,
            first_fetch_snapshot.source_url.as_deref()
        ),
        Err(ProfileError::ProfileChanged { ref id }) if id == &imported.id
    ));
    assert_eq!(
        repository
            .load(&imported.id)
            .expect("load after out-of-order response")
            .expect("stored profile")
            .profile,
        newest_response
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn conditional_restore_never_overwrites_a_newer_edit() {
    let (root, repository) = repository("conditional-restore");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/original"),
        )
        .expect("import remote profile");
    let original = repository
        .load(&imported.id)
        .expect("load original")
        .expect("stored profile");
    let replacement = credential_profile("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    let (_result, committed) = repository
        .replace_if_unchanged(
            &original,
            None,
            &replacement,
            Some("https://example.com/replacement"),
        )
        .expect("commit replacement");
    repository
        .update_metadata(
            &imported.id,
            Some("Edited after commit"),
            Some("https://example.com/edited"),
        )
        .expect("edit replacement before rollback");

    assert!(matches!(
        repository.restore_if_unchanged(&committed, &original),
        Err(ProfileError::ProfileChanged { ref id }) if id == &imported.id
    ));
    let current = repository
        .load(&imported.id)
        .expect("load after rejected rollback")
        .expect("stored profile");
    assert_eq!(current.record.name, "Edited after commit");
    assert_eq!(
        current.source_url.as_deref(),
        Some("https://example.com/edited")
    );
    assert_eq!(current.profile, replacement);

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn metadata_updates_change_no_document_digest_or_selection() {
    let (root, repository) = repository("metadata");
    let imported = repository
        .import(Some("Original"), &profile())
        .expect("import profile");
    repository.select(&imported.id).expect("select profile");
    let before = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");

    let renamed = repository
        .update_metadata(
            &imported.id,
            Some(" Renamed "),
            Some("https://example.com/sub"),
        )
        .expect("update metadata");
    assert_eq!(renamed.name, "Renamed");
    assert_eq!(renamed.digest, before.record.digest);
    assert_eq!(
        renamed.created_epoch_secs, before.record.created_epoch_secs,
        "renaming is not an update of the profile itself"
    );

    let after = repository
        .load_selected()
        .expect("load selection")
        .expect("selected profile");
    assert_eq!(after.record.id, imported.id);
    assert_eq!(after.record.name, "Renamed");
    assert_eq!(after.source_url.as_deref(), Some("https://example.com/sub"));

    // Clearing the subscription URL is allowed and keeps the profile intact.
    repository
        .update_metadata(&imported.id, None, None)
        .expect("clear subscription");
    let cleared = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(cleared.source_url, None);
    assert_eq!(cleared.record.name, "Renamed");
    assert_eq!(cleared.record.digest, before.record.digest);

    assert!(matches!(
        repository.update_metadata(&imported.id, Some("bad/name"), None),
        Err(ProfileError::InvalidName)
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_conditional_restore_of_another_profile_is_refused() {
    let (root, repository) = repository("restore-other-profile");
    let load = |id: &str| {
        repository
            .load(id)
            .expect("load profile")
            .expect("stored profile")
    };
    let first = load(
        &repository
            .import(Some("First"), &profile())
            .expect("import first")
            .id,
    );
    let second = load(
        &repository
            .import(Some("Second"), &profile())
            .expect("import second")
            .id,
    );
    assert!(matches!(
        repository.restore_if_unchanged(&first, &second),
        Err(ProfileError::ProfileChanged { id }) if id == second.record.id
    ));
    assert_eq!(load(&first.record.id), first);
    assert_eq!(load(&second.record.id), second);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_restore_needs_a_consistent_snapshot() {
    let (root, repository) = repository("restore-consistency");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &profile(),
            Some("https://subscription.example/profile"),
        )
        .expect("import profile");
    let stored = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    type Edit = fn(&mut StoredProfile);
    type Expect = fn(&ProfileError) -> bool;
    let cases: [(&str, Edit, Expect); 4] = [
        (
            "digest",
            |snapshot| snapshot.record.digest = "00".repeat(32),
            |error| matches!(error, ProfileError::DigestMismatch { .. }),
        ),
        (
            "length",
            |snapshot| snapshot.record.bytes += 1,
            |error| matches!(error, ProfileError::DigestMismatch { .. }),
        ),
        (
            "name",
            |snapshot| snapshot.record.name = " Remote".into(),
            |error| matches!(error, ProfileError::InvalidName),
        ),
        (
            "source URL",
            |snapshot| snapshot.source_url = Some("http://subscription.example/profile".into()),
            |error| matches!(error, ProfileError::InvalidSourceUrl),
        ),
    ];
    for (case, edit, expected) in cases {
        let mut snapshot = stored.clone();
        edit(&mut snapshot);
        let error = repository.restore(&snapshot).expect_err(case);
        assert!(expected(&error), "{case}: {error}");
        // As the expected current state it is refused for itself, not
        // because it differs from what is stored.
        let error = repository
            .restore_if_unchanged(&snapshot, &stored)
            .expect_err(case);
        assert!(expected(&error), "{case} as current: {error}");
    }
    assert_eq!(
        repository.load(&imported.id).expect("load profile"),
        Some(stored),
        "nothing was written"
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_locked_replacement_of_a_changed_profile_writes_nothing() {
    let (root, repository) = repository("locked-changed");
    let imported = repository
        .import(Some("Original"), &profile())
        .expect("import profile");
    let stale = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    let current = repository
        .update_metadata(&imported.id, Some("Renamed"), None)
        .expect("rename profile");
    let error = repository
        .begin_credential_profile_mutation()
        .expect("mutation lock")
        .commit_replace_if_unchanged(
            &stale,
            None,
            &credential_profile("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            None,
        )
        .expect_err("the profile changed");
    assert!(matches!(error, ProfileError::ProfileChanged { id } if id == imported.id));
    let stored = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(stored.record, current);
    assert_eq!(stored.profile, stale.profile);
    fs::remove_dir_all(root).expect("remove test directory");
}
