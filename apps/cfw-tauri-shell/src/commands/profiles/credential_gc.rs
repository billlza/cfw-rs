//! Credential garbage collection: a one-shot, expiring preview authority,
//! and a commit that revalidates the exact orphans under the repository lock.

use super::*;

pub(super) const CREDENTIAL_GC_PREVIEW_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug)]
pub(super) struct CredentialGcAuthority {
    pub(super) preview_id: String,
    pub(super) created_at: Instant,
    pub(super) preview: CredentialGarbageCollectionPreview,
}

pub(super) fn cancel_gc_authority(
    stored: &mut Option<CredentialGcAuthority>,
    preview_id: &str,
) -> Result<(), String> {
    match stored.as_ref() {
        Some(preview) if preview.preview_id == preview_id => {
            *stored = None;
            Ok(())
        }
        _ => Err("CredentialGcPreviewExpired: cleanup preview is missing or stale".into()),
    }
}

pub(super) fn take_gc_authority(
    stored: &mut Option<CredentialGcAuthority>,
    preview_id: &str,
    now: Instant,
) -> Result<CredentialGcAuthority, String> {
    let Some(preview) = stored.as_ref() else {
        return Err("CredentialGcPreviewExpired: cleanup preview is missing".into());
    };
    if preview.preview_id != preview_id {
        return Err("CredentialGcPreviewExpired: cleanup preview token does not match".into());
    }
    if now
        .checked_duration_since(preview.created_at)
        .is_none_or(|elapsed| elapsed > CREDENTIAL_GC_PREVIEW_TTL)
    {
        *stored = None;
        return Err("CredentialGcPreviewExpired: cleanup preview has expired".into());
    }
    stored.take().ok_or_else(|| {
        "CredentialGcPreviewExpired: cleanup preview disappeared during validation".to_owned()
    })
}

pub(super) fn credential_gc_request(
    snapshot: ProfileCredentialSnapshot,
) -> Result<CredentialGarbageCollectionRequest, String> {
    let catalog = snapshot
        .catalog
        .into_iter()
        .map(|entry| CredentialProfileCatalogEntry::new(entry.audience, entry.references))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    CredentialGarbageCollectionRequest::new(snapshot.snapshot_digest, catalog)
        .map_err(|error| error.to_string())
}

/// A missing vault is empty only when the current catalog has no live bindings.
pub(super) async fn prepare_credential_gc(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
) -> Result<Option<CredentialGarbageCollectionPreview>, String> {
    let snapshot = repository
        .credential_snapshot()
        .map_err(|error| error.to_string())?;
    let request = credential_gc_request(snapshot)?;
    let live = request
        .catalog()
        .iter()
        .flat_map(CredentialProfileCatalogEntry::bindings)
        .collect::<BTreeSet<_>>();
    let preview = match vault
        .preview_credential_garbage_collection(request.clone())
        .await
    {
        Ok(preview) => preview,
        Err(CredentialVaultError::MissingVault) if live.is_empty() => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    CredentialGarbageCollectionCommitRequest::new(request, &preview)
        .map_err(|error| error.to_string())?;
    if preview
        .orphan_bindings
        .iter()
        .any(|binding| live.contains(binding))
    {
        return Err(
            "credential garbage-collection preview marks a live reference as orphaned".into(),
        );
    }
    Ok(Some(preview))
}

/// The caller consumes explicit preview authority first. Keep the cross-process
/// repository lock through native CAS and validate the exact deletion receipt.
pub(super) async fn complete_credential_gc(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    preview: &CredentialGarbageCollectionPreview,
) -> Result<u32, String> {
    if preview.orphan_count == 0 {
        return Ok(0);
    }
    let locked = repository
        .lock_credential_snapshot()
        .map_err(|error| error.to_string())?;
    let request = credential_gc_request(locked.snapshot().clone())?;
    let commit = CredentialGarbageCollectionCommitRequest::new(request, preview)
        .map_err(|error| error.to_string())?;
    let receipt = vault
        .commit_credential_garbage_collection(commit)
        .await
        .map_err(|error| error.to_string())?;
    receipt.validate().map_err(|error| error.to_string())?;
    if receipt.deleted_count != preview.orphan_count {
        return Err("credential garbage-collection receipt does not match the preview".into());
    }
    Ok(receipt.deleted_count)
}
