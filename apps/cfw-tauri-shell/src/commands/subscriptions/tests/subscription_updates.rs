//! Subscription updates: the result shape, stale and selected updates, one
//! stable audience across unchanged updates, one rotation after an immutable
//! conflict, and exact replays.

use super::*;

#[test]
fn subscription_update_result_flattens_profile_and_exposes_cleanup_state() {
    let value = serde_json::to_value(UiSubscriptionUpdateResult {
        profile: ProfileImportResult {
            id: TRANSACTION_PROFILE_ID.into(),
            name: "Work".into(),
            bytes: 123,
            digest: "ab".repeat(32),
        },
        credential_cleanup_removed: 2,
        credential_cleanup_pending: false,
        credential_cleanup_error: None,
        reset_proxy_groups: Vec::new(),
    })
    .expect("serialize update result");
    assert_eq!(value["name"], "Work");
    assert_eq!(value["credential_cleanup_removed"], 2);
    assert_eq!(value["credential_cleanup_pending"], false);
    assert!(value.get("credential_cleanup_error").is_none());
}

#[test]
fn only_a_direct_immutable_conflict_authorizes_reference_rotation() {
    let immutable =
        SubscriptionUpdateCommitError::Credential(ImportedCredentialProvisionError::Rejected(
            ImportedCredentialProvisionAttemptError::Vault(CredentialVaultError::ImmutableConflict),
        ));
    assert!(immutable.is_immutable_conflict());

    let unknown =
        SubscriptionUpdateCommitError::Credential(ImportedCredentialProvisionError::Rejected(
            ImportedCredentialProvisionAttemptError::Vault(CredentialVaultError::OutcomeUnknown),
        ));
    assert!(!unknown.is_immutable_conflict());
}

#[tokio::test]
async fn stale_update_is_rejected_before_vault_provisioning() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let original = selected_direct_profile(&repository);
    let mut stale_expected = original.clone();
    stale_expected.source_url = Some("https://subscription.example/stale".into());
    let imported = credential_subscription("44444444-4444-5444-8444-444444444444");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
    );

    let error = commit_subscription_update(
        &repository,
        &vault,
        &stale_expected,
        "https://subscription.example/replacement",
        &imported,
    )
    .await
    .expect_err("stale update CAS");

    assert!(error.contains("could not begin before credential provisioning"));
    assert_eq!(
        repository
            .load(TRANSACTION_PROFILE_ID)
            .expect("load unchanged profile")
            .expect("unchanged profile"),
        original
    );
    assert_eq!(
        repository
            .load_selected()
            .expect("load selected profile")
            .expect("selected profile"),
        original
    );
    assert!(
        vault.requests().is_empty(),
        "a stale response must not write a vault audience"
    );
    let catalog = repository
        .credential_snapshot()
        .expect("credential snapshot")
        .catalog;
    let live = catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == TRANSACTION_PROFILE_ID)
        .expect("live original audience");
    assert_eq!(live.audience.profile_digest(), original.profile.digest());
}

#[tokio::test]
async fn selected_update_is_visible_only_with_the_complete_vault_audience() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let original = selected_direct_profile(&repository);
    let imported = credential_subscription("55555555-5555-5555-8555-555555555555");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
    );

    let updated = commit_subscription_update(
        &repository,
        &vault,
        &original,
        "https://subscription.example/replacement",
        &imported,
    )
    .await
    .expect("vault-first selected update");

    assert_eq!(updated.id, TRANSACTION_PROFILE_ID);
    assert_eq!(updated.digest, imported.profile.digest());
    let requests = vault.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].repository_profile_visible);
    let selected = repository
        .load_selected()
        .expect("load selected profile")
        .expect("selected replacement");
    assert_eq!(selected.record.id, TRANSACTION_PROFILE_ID);
    assert_eq!(selected.profile, imported.profile);
    assert_eq!(
        selected.source_url.as_deref(),
        Some("https://subscription.example/replacement")
    );
    let catalog = repository
        .credential_snapshot()
        .expect("credential snapshot")
        .catalog;
    let live = catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == TRANSACTION_PROFILE_ID)
        .expect("selected replacement audience");
    assert_eq!(live.audience.profile_digest(), requests[0].profile_digest);
    assert_eq!(
        live.references.iter().cloned().collect::<BTreeSet<_>>(),
        requests[0]
            .required_references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    );
}

#[tokio::test]
async fn unchanged_subscription_updates_keep_one_stable_vault_audience() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let body = format!("trojan://{IMPORT_SECRET}@proxy.example.com:443?sni=proxy.example.com#Work");
    let initial = validated_subscription_import(&body, &EngineSettings::default())
        .expect("initial subscription");
    let receipt = successful_receipt(TRANSACTION_PROFILE_ID, &initial);
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(receipt.clone()), Ok(receipt.clone()), Ok(receipt)],
    );

    commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        Some("Work"),
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &initial,
        false,
    )
    .await
    .expect("initial import");

    for _ in 0..2 {
        let stored = repository
            .load(TRANSACTION_PROFILE_ID)
            .expect("load profile")
            .expect("stored profile");
        let replay = validated_subscription_import_with_reusable_references(
            &body,
            &EngineSettings::default(),
            stored.profile.credential_references_in_outbound_order(),
        )
        .expect("stable update import");
        assert_eq!(replay.profile.digest(), initial.profile.digest());
        commit_subscription_update_attempt(
            &repository,
            &vault,
            &stored,
            TRANSACTION_SOURCE_URL,
            &replay,
        )
        .await
        .expect("unchanged update");
    }

    let requests = vault.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests.windows(2).all(|pair| {
        pair[0].profile_digest == pair[1].profile_digest
            && pair[0].required_references == pair[1].required_references
    }));
}

#[tokio::test]
async fn immutable_secret_change_rotates_once_and_commits_the_fresh_reference() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let old_body = "trojan://old-secret@proxy.example.com:443?sni=proxy.example.com#Work";
    let new_body = "trojan://new-secret@proxy.example.com:443?sni=proxy.example.com#Work";
    let initial = validated_subscription_import_with_namespace(
        old_body,
        &EngineSettings::default(),
        Uuid::parse_str("77777777-7777-4777-8777-777777777777").expect("credential namespace"),
    )
    .expect("initial subscription");
    repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Work"),
            &initial.profile,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("seed subscription profile");
    repository
        .select(TRANSACTION_PROFILE_ID)
        .expect("select initial profile");
    let stored = repository
        .load(TRANSACTION_PROFILE_ID)
        .expect("load initial profile")
        .expect("initial profile");
    let reused = validated_subscription_import_with_reusable_references(
        new_body,
        &EngineSettings::default(),
        stored.profile.credential_references_in_outbound_order(),
    )
    .expect("reused-reference candidate");
    assert_eq!(reused.profile.digest(), stored.profile.digest());
    let vault = RotationCredentialVault::new(profiles_dir, RotationVaultMode::ImmutableThenEcho);

    let updated = commit_subscription_update_with_rotation(
        &repository,
        &vault,
        &stored,
        TRANSACTION_SOURCE_URL,
        new_body,
        &EngineSettings::default(),
        &reused,
    )
    .await
    .expect("immutable conflict rotation");

    let requests = vault.requests();
    assert_eq!(requests.len(), 2, "rotation is attempted exactly once");
    assert_eq!(
        requests[0].required_references,
        stored.profile.credential_references_in_outbound_order()
    );
    assert_ne!(
        requests[1].required_references, requests[0].required_references,
        "changed material must receive a fresh UUID"
    );
    assert_eq!(requests[0].entries.len(), requests[1].entries.len());
    assert!(
        requests[0]
            .entries
            .iter()
            .zip(&requests[1].entries)
            .all(|(first, second)| first.1 == second.1),
        "rotation changes only the UUID, not the requested secret"
    );
    assert_ne!(requests[1].profile_digest, requests[0].profile_digest);
    let committed = repository
        .load(TRANSACTION_PROFILE_ID)
        .expect("load rotated profile")
        .expect("rotated profile");
    assert_eq!(updated.id, TRANSACTION_PROFILE_ID);
    assert_eq!(committed.record.digest, requests[1].profile_digest);
    assert_eq!(
        committed.profile.credential_references_in_outbound_order(),
        requests[1].required_references
    );
    assert_eq!(
        repository
            .load_selected()
            .expect("load selected profile")
            .expect("selected rotated profile")
            .record
            .digest,
        requests[1].profile_digest
    );
}

#[tokio::test]
async fn outcome_unknown_replays_exactly_and_never_rotates_references() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let body = "trojan://new-secret@proxy.example.com:443?sni=proxy.example.com#Work";
    let initial = validated_subscription_import_with_namespace(
        body,
        &EngineSettings::default(),
        Uuid::parse_str("88888888-8888-4888-8888-888888888888").expect("credential namespace"),
    )
    .expect("initial subscription");
    repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Work"),
            &initial.profile,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("seed subscription profile");
    let stored = repository
        .load(TRANSACTION_PROFILE_ID)
        .expect("load initial profile")
        .expect("initial profile");
    let reused = validated_subscription_import_with_reusable_references(
        body,
        &EngineSettings::default(),
        stored.profile.credential_references_in_outbound_order(),
    )
    .expect("reused-reference candidate");
    let vault = RotationCredentialVault::new(profiles_dir, RotationVaultMode::AlwaysOutcomeUnknown);

    let error = commit_subscription_update_with_rotation(
        &repository,
        &vault,
        &stored,
        TRANSACTION_SOURCE_URL,
        body,
        &EngineSettings::default(),
        &reused,
    )
    .await
    .expect_err("two unknown outcomes must fail closed");

    assert!(error.contains("after one outcome-unknown replay"));
    let requests = vault.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1], "the replay must be exact");
    assert_eq!(
        repository
            .load(TRANSACTION_PROFILE_ID)
            .expect("load unchanged profile")
            .expect("unchanged profile"),
        stored
    );
}
