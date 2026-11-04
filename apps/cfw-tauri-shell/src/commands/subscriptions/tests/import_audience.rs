//! A subscription import reaches the repository only once its whole
//! credential audience is in the vault; a refused or ambiguous vault answer
//! commits nothing.

use super::*;

#[tokio::test]
async fn subscription_import_provisions_complete_audience_before_repository_visibility() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = credential_subscription("11111111-1111-5111-8111-111111111111");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
    );

    let record = commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        Some("Imported"),
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect("vault-first import");

    assert_eq!(record.id, TRANSACTION_PROFILE_ID);
    let requests = vault.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].profile_id, TRANSACTION_PROFILE_ID);
    assert_eq!(requests[0].profile_digest, imported.profile.digest());
    assert!(!requests[0].repository_profile_visible);
    assert_eq!(requests[0].entries.len(), imported.credentials.len());
    assert_eq!(
        requests[0]
            .required_references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        imported
            .profile
            .credential_references()
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    let catalog = repository
        .credential_snapshot()
        .expect("credential snapshot")
        .catalog;
    let committed = catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == TRANSACTION_PROFILE_ID)
        .expect("committed audience");
    assert_eq!(
        committed.audience.profile_digest(),
        imported.profile.digest()
    );
    assert_eq!(
        committed
            .references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        requests[0]
            .required_references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_gc_cannot_enter_between_vault_success_and_repository_commit() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let stale_preview_snapshot = repository
        .credential_snapshot()
        .expect("pre-provision credential snapshot");
    let imported = credential_subscription("77777777-7777-5777-8777-777777777777");
    let (vault, provision_entered, provision_release) = ScriptedCredentialVault::new_paused(
        profiles_dir,
        Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported)),
    );
    let vault = Arc::new(vault);
    let import_repository = repository.clone();
    let import_vault = Arc::clone(&vault);
    let import_candidate = imported.clone();
    let import_task = tokio::spawn(async move {
        commit_profile_import(
            &import_repository,
            import_vault.as_ref(),
            TRANSACTION_PROFILE_ID,
            Some("Imported"),
            ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
            &import_candidate,
            false,
        )
        .await
    });

    provision_entered
        .recv_timeout(Duration::from_secs(2))
        .expect("vault provision entered while repository lock is held");
    let gc_repository = repository.clone();
    let (gc_sender, gc_receiver) = std::sync::mpsc::channel();
    let gc_reread = std::thread::spawn(move || {
        let locked = gc_repository
            .lock_credential_snapshot()
            .expect("competing GC snapshot lock");
        gc_sender
            .send(locked.snapshot().clone())
            .expect("send competing GC snapshot");
    });
    assert!(matches!(
        gc_receiver.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));

    provision_release
        .send(())
        .expect("release vault provision result");
    let record = import_task
        .await
        .expect("import task")
        .expect("vault-first import commit");
    let current = gc_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("GC reread unblocked after repository commit");
    gc_reread.join().expect("GC reread thread");

    assert_eq!(record.id, TRANSACTION_PROFILE_ID);
    assert_ne!(
        current.snapshot_digest, stale_preview_snapshot.snapshot_digest,
        "a GC commit bound to the pre-provision snapshot must fail closed"
    );
    let live = current
        .catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == TRANSACTION_PROFILE_ID)
        .expect("prepared audience is live before GC can acquire the lock");
    assert_eq!(live.audience.profile_digest(), imported.profile.digest());
    assert!(!vault.requests()[0].repository_profile_visible);
}

#[tokio::test]
async fn vault_rejection_and_two_unknown_outcomes_commit_no_profile() {
    let imported = credential_subscription("22222222-2222-5222-8222-222222222222");

    let deterministic_directory = tempfile::TempDir::new().expect("temporary directory");
    let deterministic_repository =
        ProfileRepository::new(deterministic_directory.path().join("profiles"));
    let deterministic_vault = ScriptedCredentialVault::new(
        deterministic_directory.path().join("profiles"),
        vec![Err(CredentialVaultError::AccessDenied)],
    );
    let deterministic_error = commit_profile_import(
        &deterministic_repository,
        &deterministic_vault,
        TRANSACTION_PROFILE_ID,
        None,
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("deterministic vault rejection");
    assert_eq!(deterministic_vault.requests().len(), 1);
    assert!(
        deterministic_repository
            .snapshot()
            .expect("empty repository snapshot")
            .profiles
            .is_empty()
    );
    assert!(!deterministic_error.contains(IMPORT_SECRET));

    let unknown_directory = tempfile::TempDir::new().expect("temporary directory");
    let unknown_repository = ProfileRepository::new(unknown_directory.path().join("profiles"));
    let unknown_vault = ScriptedCredentialVault::new(
        unknown_directory.path().join("profiles"),
        vec![
            Err(CredentialVaultError::OutcomeUnknown),
            Err(CredentialVaultError::OutcomeUnknown),
        ],
    );
    let unknown_error = commit_profile_import(
        &unknown_repository,
        &unknown_vault,
        TRANSACTION_PROFILE_ID,
        None,
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("two unknown outcomes must fail closed");
    let requests = unknown_vault.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1], "the replay must be exact");
    assert!(
        unknown_repository
            .snapshot()
            .expect("empty repository snapshot")
            .profiles
            .is_empty()
    );
    assert!(unknown_error.contains("after one outcome-unknown replay"));
    assert!(!unknown_error.contains(IMPORT_SECRET));
}

#[tokio::test]
async fn typed_profile_with_refs_requires_vault_confirmation_even_without_entries() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = validated_subscription_import(PROFILE_JSON, &EngineSettings::default())
        .expect("typed credential profile");
    assert!(imported.credentials.is_empty());
    assert_eq!(imported.profile.credential_references().len(), 1);
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Err(CredentialVaultError::AccessDenied)],
    );

    commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        None,
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("missing existing material must not become repository-visible");

    let requests = vault.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].entries.is_empty());
    assert_eq!(requests[0].required_references.len(), 1);
    assert!(
        repository
            .snapshot()
            .expect("empty repository snapshot")
            .profiles
            .is_empty()
    );
}

#[tokio::test]
async fn receipt_audience_mismatch_commits_no_profile_and_is_not_replayed() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = credential_subscription("33333333-3333-5333-8333-333333333333");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(CredentialVaultReceipt {
            profile_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            profile_digest: imported.profile.digest().to_owned(),
        })],
    );

    let error = commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        None,
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("wrong receipt audience");

    assert_eq!(vault.requests().len(), 1);
    assert!(error.contains("different profile audience"));
    assert!(!error.contains(IMPORT_SECRET));
    assert!(
        repository
            .snapshot()
            .expect("empty repository snapshot")
            .profiles
            .is_empty()
    );
}

#[tokio::test]
async fn exact_id_replay_is_not_reported_as_a_new_subscription_import() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = credential_subscription("66666666-6666-5666-8666-666666666666");
    let original = repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Imported"),
            &imported.profile,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("seed exact-ID profile");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
    );

    let error = commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        Some("Imported"),
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("unexpected exact-ID replay");

    assert!(error.contains("unexpected exact-ID replay"));
    assert_eq!(
        repository
            .load(TRANSACTION_PROFILE_ID)
            .expect("load original")
            .expect("original exact-ID profile")
            .record,
        repository
            .load(&original.id)
            .expect("reload original")
            .expect("reloaded original")
            .record
    );
}

#[test]
fn activation_failure_reports_that_the_complete_import_remains_committed() {
    let rendered = profile_import_activation_error("selection storage unavailable");
    assert_eq!(
        rendered,
        "profile import committed, but selection failed: selection storage unavailable"
    );
}
