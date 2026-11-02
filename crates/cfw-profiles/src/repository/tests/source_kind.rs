//! Source kinds: derived from the subscription URL, never persisted, and
//! never a way to read the URL from a listing.

use super::*;

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
