//! Credential cleanup: a one-shot, expiring preview authority, and a commit
//! that revalidates the exact orphans and refuses live, stale or mismatched
//! answers.

use super::*;

struct OrphanGcVault {
    preview_count: AtomicUsize,
    commit_count: AtomicUsize,
    preview_error: Option<CredentialVaultError>,
    orphan_bindings: Vec<CredentialBinding>,
    orphan_count: u32,
    deleted_count: u32,
    mutate_repository_before_commit: Option<ProfileRepository>,
}

impl OrphanGcVault {
    fn orphan_binding() -> CredentialBinding {
        let audience =
            CredentialAudience::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "ab".repeat(32))
                .expect("synthetic orphan audience");
        let reference = CredentialRef::new(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            cfw_engine_api::CredentialKind::TrojanPassword,
        )
        .expect("synthetic orphan reference");
        CredentialBinding::new(audience, reference)
    }
}

impl CredentialVaultProvisioner for OrphanGcVault {
    fn provision_profile_credentials<'a>(
        &'a self,
        _request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn query_profile_credentials(
        &self,
        _request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn preview_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_> {
        self.preview_count.fetch_add(1, Ordering::SeqCst);
        let snapshot_digest = request.snapshot_digest().to_owned();
        let preview_error = self.preview_error;
        let orphan_bindings = self.orphan_bindings.clone();
        let orphan_count = self.orphan_count;
        if let Some(repository) = &self.mutate_repository_before_commit {
            repository
                .import(Some("Concurrent"), &ValidatedSingBoxProfile::direct())
                .expect("concurrent repository mutation");
        }
        Box::pin(async move {
            if let Some(error) = preview_error {
                return Err(error);
            }
            Ok(CredentialGarbageCollectionPreview {
                snapshot_digest,
                vault_revision: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
                orphan_bindings,
                orphan_count,
            })
        })
    }

    fn commit_credential_garbage_collection(
        &self,
        request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        self.commit_count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.expected_orphan_bindings(), self.orphan_bindings);
        let deleted_count = self.deleted_count;
        Box::pin(async move {
            Ok(cfw_engine_api::CredentialGarbageCollectionReceipt {
                vault_revision: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into(),
                deleted_count,
            })
        })
    }
}

fn gc_authority(created_at: Instant) -> CredentialGcAuthority {
    CredentialGcAuthority {
        preview_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        created_at,
        preview: CredentialGarbageCollectionPreview {
            snapshot_digest: "01".repeat(32),
            vault_revision: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            orphan_bindings: Vec::new(),
            orphan_count: 0,
        },
    }
}

#[test]
fn credential_gc_authority_is_one_shot_expiring_and_not_destroyed_by_wrong_tokens() {
    let now = Instant::now();
    let mut stored = Some(gc_authority(now));
    assert!(take_gc_authority(&mut stored, "wrong", now).is_err());
    assert!(
        stored.is_some(),
        "wrong token must not invalidate real authority"
    );
    assert!(cancel_gc_authority(&mut stored, "wrong").is_err());
    assert!(stored.is_some());

    let accepted = take_gc_authority(&mut stored, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now)
        .expect("matching authority");
    assert_eq!(accepted.preview.orphan_count, 0);
    assert!(stored.is_none(), "accepted authority is one-shot");

    let expired_at = now
        .checked_sub(CREDENTIAL_GC_PREVIEW_TTL + Duration::from_secs(1))
        .expect("representable prior instant");
    let mut expired = Some(gc_authority(expired_at));
    assert!(take_gc_authority(&mut expired, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", now).is_err());
    assert!(expired.is_none(), "expired authority is destroyed");
}

async fn execute_previewed_credential_gc(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
) -> Result<u32, String> {
    let Some(preview) = prepare_credential_gc(repository, vault).await? else {
        return Ok(0);
    };
    complete_credential_gc(repository, vault, &preview).await
}

#[tokio::test]
async fn explicit_credential_cleanup_revalidates_and_commits_exact_orphans() {
    let temporary = TempDir::new().expect("temporary repository");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let vault = OrphanGcVault {
        preview_count: AtomicUsize::new(0),
        commit_count: AtomicUsize::new(0),
        preview_error: None,
        orphan_bindings: vec![OrphanGcVault::orphan_binding()],
        orphan_count: 1,
        deleted_count: 1,
        mutate_repository_before_commit: None,
    };

    assert_eq!(
        execute_previewed_credential_gc(&repository, &vault)
            .await
            .expect("previewed cleanup"),
        1
    );
    assert_eq!(vault.preview_count.load(Ordering::SeqCst), 1);
    assert_eq!(vault.commit_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn explicit_credential_cleanup_accepts_a_missing_empty_vault() {
    let temporary = TempDir::new().expect("temporary repository");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let vault = OrphanGcVault {
        preview_count: AtomicUsize::new(0),
        commit_count: AtomicUsize::new(0),
        preview_error: Some(CredentialVaultError::MissingVault),
        orphan_bindings: Vec::new(),
        orphan_count: 0,
        deleted_count: 0,
        mutate_repository_before_commit: None,
    };

    assert_eq!(
        execute_previewed_credential_gc(&repository, &vault)
            .await
            .expect("an absent vault with no live bindings is already clean"),
        0
    );
    assert_eq!(vault.preview_count.load(Ordering::SeqCst), 1);
    assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_credential_cleanup_rejects_a_missing_vault_with_live_bindings() {
    let temporary = TempDir::new().expect("temporary repository");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let profile = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#,
    )
    .expect("typed profile");
    repository
        .import(Some("Credentials"), &profile)
        .expect("profile import");
    let vault = OrphanGcVault {
        preview_count: AtomicUsize::new(0),
        commit_count: AtomicUsize::new(0),
        preview_error: Some(CredentialVaultError::MissingVault),
        orphan_bindings: Vec::new(),
        orphan_count: 0,
        deleted_count: 0,
        mutate_repository_before_commit: None,
    };

    let error = execute_previewed_credential_gc(&repository, &vault)
        .await
        .expect_err("live references require an existing vault");
    assert_eq!(error, CredentialVaultError::MissingVault.to_string());
    assert_eq!(vault.preview_count.load(Ordering::SeqCst), 1);
    assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_credential_cleanup_is_refused_while_an_invalid_profile_is_listed() {
    let temporary = TempDir::new().expect("temporary repository");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let invalid_id =
        crate::profile_fixtures::store_selected_reality_without_utls(&profiles_dir, &repository);
    let vault = OrphanGcVault {
        preview_count: AtomicUsize::new(0),
        commit_count: AtomicUsize::new(0),
        preview_error: None,
        orphan_bindings: vec![OrphanGcVault::orphan_binding()],
        orphan_count: 1,
        deleted_count: 1,
        mutate_repository_before_commit: None,
    };

    let error = execute_previewed_credential_gc(&repository, &vault)
        .await
        .expect_err("cleanup keeps the credentials of a listed profile");
    assert_eq!(
        error,
        format!(
            "credential cleanup needs every stored profile to pass validation; delete the invalid profiles first: \"Reality node\" ({invalid_id})"
        )
    );
    assert_eq!(vault.preview_count.load(Ordering::SeqCst), 0);
    assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_profile_that_becomes_invalid_after_the_preview_blocks_the_commit() {
    let temporary = TempDir::new().expect("temporary repository");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let vault = OrphanGcVault {
        preview_count: AtomicUsize::new(0),
        commit_count: AtomicUsize::new(0),
        preview_error: None,
        orphan_bindings: vec![OrphanGcVault::orphan_binding()],
        orphan_count: 1,
        deleted_count: 1,
        mutate_repository_before_commit: None,
    };
    let preview = prepare_credential_gc(&repository, &vault)
        .await
        .expect("preview of a valid repository")
        .expect("orphan preview");
    let invalid_id =
        crate::profile_fixtures::store_selected_reality_without_utls(&profiles_dir, &repository);

    let error = complete_credential_gc(&repository, &vault, &preview)
        .await
        .expect_err("the commit re-reads the repository under its lock");
    assert!(error.contains(&invalid_id), "{error}");
    assert!(
        error.starts_with("credential cleanup needs every stored profile"),
        "{error}"
    );
    assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_credential_cleanup_never_commits_a_live_binding_preview() {
    let temporary = TempDir::new().expect("temporary repository");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let profile = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#,
    )
    .expect("typed profile");
    repository
        .import(Some("Credentials"), &profile)
        .expect("profile import");
    let snapshot = repository
        .credential_snapshot()
        .expect("credential snapshot");
    let entry = snapshot.catalog.first().expect("live catalog entry");
    let live = CredentialBinding::new(entry.audience.clone(), entry.references[0].clone());
    let vault = OrphanGcVault {
        preview_count: AtomicUsize::new(0),
        commit_count: AtomicUsize::new(0),
        preview_error: None,
        orphan_bindings: vec![live],
        orphan_count: 1,
        deleted_count: 1,
        mutate_repository_before_commit: None,
    };

    let error = execute_previewed_credential_gc(&repository, &vault)
        .await
        .expect_err("live binding preview must fail closed");
    assert!(error.contains("marks a live reference as orphaned"));
    assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_credential_cleanup_rejects_a_stale_repository_snapshot() {
    let temporary = TempDir::new().expect("temporary repository");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let vault = OrphanGcVault {
        preview_count: AtomicUsize::new(0),
        commit_count: AtomicUsize::new(0),
        preview_error: None,
        orphan_bindings: vec![OrphanGcVault::orphan_binding()],
        orphan_count: 1,
        deleted_count: 1,
        mutate_repository_before_commit: Some(repository.clone()),
    };

    execute_previewed_credential_gc(&repository, &vault)
        .await
        .expect_err("stale repository snapshot must fail closed");
    assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_credential_cleanup_rejects_a_mismatched_delete_receipt() {
    let temporary = TempDir::new().expect("temporary repository");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let vault = OrphanGcVault {
        preview_count: AtomicUsize::new(0),
        commit_count: AtomicUsize::new(0),
        preview_error: None,
        orphan_bindings: vec![OrphanGcVault::orphan_binding()],
        orphan_count: 1,
        deleted_count: 0,
        mutate_repository_before_commit: None,
    };

    let error = execute_previewed_credential_gc(&repository, &vault)
        .await
        .expect_err("delete receipt mismatch must fail closed");
    assert!(error.contains("receipt does not match the preview"));
    assert_eq!(vault.commit_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn explicit_credential_cleanup_skips_commit_for_zero_orphans() {
    let temporary = TempDir::new().expect("temporary repository");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let vault = OrphanGcVault {
        preview_count: AtomicUsize::new(0),
        commit_count: AtomicUsize::new(0),
        preview_error: None,
        orphan_bindings: Vec::new(),
        orphan_count: 0,
        deleted_count: 0,
        mutate_repository_before_commit: None,
    };

    assert_eq!(
        execute_previewed_credential_gc(&repository, &vault)
            .await
            .expect("zero orphan cleanup"),
        0
    );
    assert_eq!(vault.preview_count.load(Ordering::SeqCst), 1);
    assert_eq!(vault.commit_count.load(Ordering::SeqCst), 0);
}
