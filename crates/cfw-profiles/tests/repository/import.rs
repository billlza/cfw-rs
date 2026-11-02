//! Imports and their round trips: privacy, exact-id replays, subscription
//! URLs and provider sources.

use std::fs;

use cfw_profiles::{InvalidSelection, ProfileError, ValidatedSingBoxProfile};

use crate::support::{
    application_entries, assert_private_directory, assert_private_file, listed, profile,
    repository, stored_path,
};

#[test]
fn provider_sources_round_trip_privately_and_participate_in_update_conflict_detection() {
    use std::collections::BTreeMap;
    let value = serde_json::json!({"outbounds":[{"type":"socks5","tag":"node","server":"node.example.com","server_port":1080}],
        "providers":{"proxies":[{"name":"Japan","source":{"interval_seconds":3600},"members":[{"tag":"node","name":"Tokyo"}],"filter":{}}]}});
    let profile = ValidatedSingBoxProfile::parse(&value.to_string())
        .unwrap()
        .with_provider_sources(BTreeMap::from([(
            "proxy:Japan".into(),
            "https://resource.example/nodes?token=private-token".into(),
        )]))
        .unwrap();
    let (root, repository) = repository("provider-private-source");
    let imported = repository.import(Some("Providers"), &profile).unwrap();
    let stored = repository.load(&imported.id).unwrap().unwrap();
    assert_eq!(
        stored.profile.provider_sources(),
        profile.provider_sources()
    );
    assert!(!stored.profile.as_json().contains("private-token"));
    assert!(
        !serde_json::to_string(&repository.snapshot().unwrap())
            .unwrap()
            .contains("private-token")
    );
    let public = ValidatedSingBoxProfile::parse(stored.profile.as_json()).unwrap();
    assert!(public.provider_sources().is_empty());
    assert_eq!(public.digest(), profile.digest());
    let changed = profile
        .with_provider_sources(BTreeMap::from([(
            "proxy:Japan".into(),
            "https://resource.example/new".into(),
        )]))
        .unwrap();
    repository
        .begin_credential_profile_mutation_if_unchanged(&stored)
        .unwrap()
        .commit_replace_if_unchanged(&stored, None, &changed, None)
        .unwrap();
    assert!(
        repository
            .begin_credential_profile_mutation_if_unchanged(&stored)
            .is_err(),
        "same-digest source URL drift must not overwrite the new source"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn import_list_load_and_delete_round_trip_is_private_and_atomic() {
    let (root, repository) = repository("round-trip");
    let imported = repository
        .import(Some(" Work profile "), &profile())
        .expect("import profile");
    assert_eq!(imported.name, "Work profile");

    let profiles_dir = root.join("profiles");
    assert_private_directory(&profiles_dir);
    let entries = application_entries(&profiles_dir);
    assert_eq!(entries.len(), 1);
    assert_private_file(&entries[0].path());
    assert!(!entries[0].file_name().to_string_lossy().contains(".tmp"));

    let records = listed(&repository).expect("list profiles");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, imported.id);
    assert_eq!(records[0].digest, imported.digest);
    let loaded = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(loaded.profile, profile());

    assert!(
        repository
            .delete(&imported.id, InvalidSelection::Keep)
            .expect("delete profile")
    );
    assert!(
        !repository
            .delete(&imported.id, InvalidSelection::Keep)
            .expect("idempotent delete")
    );
    assert!(listed(&repository).expect("empty list").is_empty());
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn exact_id_import_is_idempotent_and_never_overwrites_a_conflict() {
    let (root, repository) = repository("exact-id-import");
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let original = profile();
    let imported = repository
        .import_with_id_and_source_outcome(
            id,
            Some("Migrated subscription"),
            &original,
            Some("https://subscription.example/profile"),
        )
        .expect("first exact import");
    assert!(imported.created);
    let replayed = repository
        .import_with_id_and_source_outcome(
            id,
            Some("Migrated subscription"),
            &original,
            Some("https://subscription.example/profile"),
        )
        .expect("exact replay");
    assert!(!replayed.created);
    assert_eq!(replayed.profile, imported.profile);

    for conflict in [
        repository.import_with_id_and_source(
            id,
            Some("Different name"),
            &original,
            Some("https://subscription.example/profile"),
        ),
        repository.import_with_id_and_source(
            id,
            Some("Migrated subscription"),
            &ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"tag":"block","type":"block"}]}"#)
                .expect("different valid profile"),
            Some("https://subscription.example/profile"),
        ),
        repository.import_with_id_and_source(
            id,
            Some("Migrated subscription"),
            &original,
            Some("https://subscription.example/other"),
        ),
    ] {
        assert!(matches!(conflict, Err(ProfileError::AlreadyExists(existing)) if existing == id));
    }
    assert_eq!(listed(&repository).expect("single exact profile").len(), 1);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn subscription_url_survives_a_round_trip_and_is_bounded() {
    let (root, repository) = repository("subscription-round-trip");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &profile(),
            Some("https://example.com/sub?token=t"),
        )
        .expect("import remote profile");
    let stored = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(
        stored.source_url.as_deref(),
        Some("https://example.com/sub?token=t")
    );

    // A local import has no subscription URL, and the listing never carries one.
    let local = repository
        .import(Some("Local"), &profile())
        .expect("import local profile");
    assert_eq!(
        repository
            .load(&local.id)
            .expect("load local")
            .expect("stored local")
            .source_url,
        None
    );
    let listed = serde_json::to_string(&repository.snapshot().expect("list profiles"))
        .expect("serialize records");
    assert!(!listed.contains("token=t"));
    assert!(!listed.contains("source_url"));

    for rejected in [
        "not-a-url",
        "http://example.com/sub",
        "https://example.com/ sub",
        " https://example.com/sub",
    ] {
        assert!(
            matches!(
                repository.import_with_source(Some("Rejected"), &profile(), Some(rejected)),
                Err(ProfileError::InvalidSourceUrl)
            ),
            "accepted invalid subscription URL: {rejected}"
        );
    }
    let oversized = format!("https://example.com/{}", "a".repeat(2_048));
    assert!(matches!(
        repository.import_with_source(Some("Oversized"), &profile(), Some(&oversized)),
        Err(ProfileError::InvalidSourceUrl)
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn envelopes_written_before_subscriptions_existed_are_still_canonical() {
    let (root, repository) = repository("legacy-envelope");
    let imported = repository
        .import(Some("Legacy"), &profile())
        .expect("import profile");
    let path = stored_path(&root, &imported.id);
    let bytes = fs::read(&path).expect("read envelope");
    let rendered = String::from_utf8(bytes).expect("utf-8 envelope");
    assert!(
        !rendered.contains("source_url"),
        "an absent subscription URL must not be written"
    );

    // The unchanged bytes must still decode, so an installation created before
    // this field existed keeps working.
    let stored = repository
        .load(&imported.id)
        .expect("load legacy envelope")
        .expect("stored profile");
    assert_eq!(stored.source_url, None);
    assert_eq!(stored.record.name, "Legacy");

    fs::remove_dir_all(root).expect("remove test directory");
}
