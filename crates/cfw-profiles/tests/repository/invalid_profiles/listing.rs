//! An invalid entry is listed with its reason, in profile order, and counts
//! toward the entry limit without blocking the repository.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError, ProfileSourceKind, ValidatedSingBoxProfile};
use cfw_singbox_config::{ConfigError, sha256_hex};
use uuid::Uuid;

use crate::invalid_profiles::{
    EARLIER_REALITY_DIGEST, EARLIER_REALITY_ENVELOPE, EARLIER_REALITY_ID, earlier_document,
    earlier_envelope_with_document, reality_requires_utls, store_earlier_reality_profile,
};
use crate::private_file_fixture::write_private;
use crate::support::{credential_profile, profile, repository, stored_path};

#[test]
fn the_earlier_digest_is_the_hash_of_its_stored_document() {
    // The integrity check for an entry that no longer validates relies on it.
    assert_eq!(
        sha256_hex(earlier_document().as_bytes()),
        EARLIER_REALITY_DIGEST
    );
    let (root, repository) = repository("stored-document-digest");
    let imported = repository
        .import_with_source(
            Some("Current"),
            &credential_profile("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
            Some("https://subscription.example/current"),
        )
        .expect("import current profile");
    let stored = fs::read_to_string(stored_path(&root, &imported.id)).expect("read envelope");
    let document = stored
        .split_once(r#""profile":"#)
        .and_then(|(_, rest)| rest.split_once(r#","digest":"#))
        .map(|(document, _)| document)
        .expect("stored document");
    assert_eq!(sha256_hex(document.as_bytes()), imported.digest);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn earlier_profile_failing_validation_is_listed_and_does_not_block_the_repository() {
    let (root, repository) = repository("earlier-invalid");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    let path = store_earlier_reality_profile(&root, false);

    let snapshot = repository
        .snapshot()
        .expect("an invalid profile does not block the snapshot");
    assert_eq!(
        snapshot
            .profiles
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec![other.id.as_str()]
    );
    assert_eq!(snapshot.invalid_profiles.len(), 1);
    let invalid = &snapshot.invalid_profiles[0];
    assert_eq!(invalid.id, EARLIER_REALITY_ID);
    assert_eq!(invalid.name, "Reality node");
    assert_eq!(invalid.created_epoch_secs, 1_791_415_969);
    assert_eq!(invalid.source_kind, ProfileSourceKind::Subscription);
    assert_eq!(invalid.error, reality_requires_utls());
    assert_eq!(snapshot.selected_profile_id, None);
    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    assert!(json.contains(
        "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
    ));
    for secret in [
        "subscription.example",
        "private-test-value",
        "source_url",
        EARLIER_REALITY_DIGEST,
    ] {
        assert!(!json.contains(secret), "snapshot exposes {secret}");
    }

    repository
        .import(Some("Third"), &profile())
        .expect("import beside an invalid profile");
    repository
        .select(&other.id)
        .expect("select a valid profile");
    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
            .expect("delete the unselected invalid profile")
    );
    assert!(!path.exists());
    let after = repository.snapshot().expect("snapshot after deletion");
    assert!(after.invalid_profiles.is_empty());
    assert_eq!(after.profiles.len(), 2);
    assert_eq!(
        after.selected_profile_id.as_deref(),
        Some(other.id.as_str())
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_document_that_no_longer_deserializes_is_listed_invalid() {
    let (root, repository) = repository("earlier-unknown-field");
    repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    let envelope = earlier_envelope_with_document(|document| {
        document.replacen(
            r#""flow":"xtls-rprx-vision","#,
            r#""flow":"xtls-rprx-vision","legacy_option":true,"#,
            1,
        )
    });
    assert_ne!(envelope, EARLIER_REALITY_ENVELOPE);
    write_private(&stored_path(&root, EARLIER_REALITY_ID), envelope.as_bytes());

    let snapshot = repository.snapshot().expect("an intact envelope is listed");
    assert_eq!(snapshot.invalid_profiles.len(), 1);
    assert!(
        matches!(&snapshot.invalid_profiles[0].error, ConfigError::InvalidJson(message) if message.contains("legacy_option")),
        "{:?}",
        snapshot.invalid_profiles[0].error
    );
    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
            .expect("delete")
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn invalid_profiles_count_toward_the_entry_limit() {
    // Mirrors the crate's 4,096-entry repository limit.
    const MAX_ENTRIES: usize = 4_096;
    let (root, repository) = repository("invalid-capacity");
    let seed = repository
        .import(Some("Seed"), &profile())
        .expect("import seed profile");
    let template = fs::read_to_string(stored_path(&root, &seed.id)).expect("read seed envelope");
    // The seed, the copies and the invalid entry fill the repository.
    for _ in 0..MAX_ENTRIES - 2 {
        let id = Uuid::new_v4().hyphenated().to_string();
        write_private(
            &stored_path(&root, &id),
            template.replacen(&seed.id, &id, 1).as_bytes(),
        );
    }
    store_earlier_reality_profile(&root, false);
    let snapshot = repository
        .snapshot()
        .expect("a full repository still lists");
    assert_eq!(snapshot.profiles.len(), MAX_ENTRIES - 1);
    assert_eq!(snapshot.invalid_profiles.len(), 1);

    assert!(matches!(
        repository.import(Some("One too many"), &profile()),
        Err(ProfileError::TooManyEntries)
    ));
    repository
        .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
        .expect("delete the invalid profile");
    repository
        .import(Some("Fits again"), &profile())
        .expect("the freed entry admits one import");
    fs::remove_dir_all(root).expect("remove test directory");
}

/// Appends optional envelope metadata in its canonical position at the end.
fn with_envelope_metadata(envelope: &str, metadata: &str) -> String {
    format!(
        "{},{metadata}}}",
        envelope.strip_suffix('}').expect("envelope object")
    )
}

#[test]
fn metadata_that_fails_current_validation_lists_the_profile_invalid() {
    let selector = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"selector","tag":"Proxy","outbounds":["direct"]},{"type":"direct","tag":"direct"}],"route":{"final":"Proxy"}}"#,
    )
    .expect("selector profile");
    for (case, profile, metadata, reason) in [
        (
            "provider sources",
            profile(),
            r#""provider_sources":{"proxy:missing":"https://provider.example/list"}"#,
            "unsupported credential-free policy shape at $.providers: provider URLs have no matching catalog",
        ),
        (
            "proxy selections",
            selector.clone(),
            r#""proxy_selections":{"Proxy":"missing"}"#,
            "unsupported credential-free policy shape at $.outbounds: selection must name a member of the group",
        ),
    ] {
        let (root, repository) = repository("metadata-invalid");
        let other = repository
            .import(Some("Other"), &selector)
            .expect("import other profile");
        let target = repository
            .import(Some("Target"), &profile)
            .expect("import target profile");
        let path = stored_path(&root, &target.id);
        let envelope =
            with_envelope_metadata(&fs::read_to_string(&path).expect("read envelope"), metadata);
        write_private(&path, envelope.as_bytes());

        let snapshot = repository.snapshot().expect(case);
        assert_eq!(snapshot.profiles.len(), 1, "{case}");
        assert_eq!(snapshot.profiles[0].id, other.id, "{case}");
        assert_eq!(snapshot.invalid_profiles.len(), 1, "{case}");
        assert_eq!(snapshot.invalid_profiles[0].id, target.id, "{case}");
        assert_eq!(
            snapshot.invalid_profiles[0].error.to_string(),
            reason,
            "{case}"
        );
        assert!(matches!(
            repository.load(&target.id),
            Err(ProfileError::StoredProfileInvalid { id, .. }) if id == target.id
        ));
        repository.select(&other.id).expect(case);
        assert!(
            repository
                .delete(&target.id, InvalidSelection::Keep)
                .expect(case)
        );
        fs::remove_dir_all(root).expect("remove test directory");
    }
}

#[test]
fn invalid_profiles_are_listed_and_named_in_profile_order() {
    const SECOND_ID: &str = "f0000000-0000-4000-8000-000000000001";
    let (root, repository) = repository("earlier-order");
    repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    store_earlier_reality_profile(&root, false);
    write_private(
        &stored_path(&root, SECOND_ID),
        EARLIER_REALITY_ENVELOPE
            .replacen(EARLIER_REALITY_ID, SECOND_ID, 1)
            .replacen(r#""name":"Reality node""#, r#""name":"A Reality node""#, 1)
            .as_bytes(),
    );

    let snapshot = repository.snapshot().expect("snapshot");
    // By name, then id: the id order alone would list them the other way.
    assert_eq!(
        snapshot
            .invalid_profiles
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec![SECOND_ID, EARLIER_REALITY_ID]
    );
    let error = repository
        .credential_snapshot()
        .expect_err("cleanup refused");
    assert_eq!(
        error.to_string(),
        "credential cleanup needs every stored profile to pass validation; delete the invalid profiles first: \"A Reality node\" (f0000000-0000-4000-8000-000000000001), \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d)"
    );
    fs::remove_dir_all(root).expect("remove test directory");
}
