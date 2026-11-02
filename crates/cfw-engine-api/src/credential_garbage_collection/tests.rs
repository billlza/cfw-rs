use cfw_singbox_config::CredentialKind;

use super::*;
use crate::test_support::{
    CREDENTIAL_ID, PROFILE_ID, VAULT_REVISION, audience, trojan_reference, uuid,
};

#[test]
fn garbage_collection_commit_is_bound_to_the_exact_preview_snapshot() {
    let live = CredentialRef::new(CREDENTIAL_ID, CredentialKind::TrojanPassword)
        .expect("canonical reference");
    let audience = CredentialAudience::new(PROFILE_ID, "ef".repeat(32)).expect("audience");
    let catalog = CredentialProfileCatalogEntry::new(audience.clone(), vec![live.clone()])
        .expect("catalog entry");
    let repository = CredentialGarbageCollectionRequest::new("ab".repeat(32), vec![catalog])
        .expect("repository snapshot");
    let preview = CredentialGarbageCollectionPreview {
        snapshot_digest: "ab".repeat(32),
        vault_revision: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
        orphan_bindings: Vec::new(),
        orphan_count: 0,
    };
    let commit =
        CredentialGarbageCollectionCommitRequest::new(repository, &preview).expect("bound commit");
    assert_eq!(commit.snapshot_digest(), preview.snapshot_digest);
    assert_eq!(commit.catalog()[0].audience(), &audience);
    assert_eq!(commit.catalog()[0].references(), &[live]);

    let changed = CredentialGarbageCollectionRequest::new("cd".repeat(32), Vec::new())
        .expect("changed repository snapshot");
    assert_eq!(
        CredentialGarbageCollectionCommitRequest::new(changed, &preview),
        Err(CredentialGarbageCollectionRequestError::SnapshotChanged)
    );
}

const FIRST: &str = "11111111-1111-4111-8111-111111111111";
const SECOND: &str = "22222222-2222-4222-8222-222222222222";

fn entry(profile_id: &str, references: Vec<CredentialRef>) -> CredentialProfileCatalogEntry {
    CredentialProfileCatalogEntry::new(audience(profile_id), references).expect("catalog entry")
}

fn binding(reference: &str) -> CredentialBinding {
    CredentialBinding::new(audience(&uuid(1)), trojan_reference(reference))
}

fn preview() -> CredentialGarbageCollectionPreview {
    CredentialGarbageCollectionPreview {
        snapshot_digest: "ab".repeat(32),
        vault_revision: VAULT_REVISION.into(),
        orphan_bindings: vec![binding(FIRST), binding(SECOND)],
        orphan_count: 2,
    }
}

fn many_references(count: usize) -> Vec<CredentialRef> {
    (0..count).map(|n| trojan_reference(&uuid(n))).collect()
}

#[test]
fn a_catalog_entry_sorts_its_references_and_rejects_reused_ids() {
    let catalog = entry(
        &uuid(1),
        vec![trojan_reference(SECOND), trojan_reference(FIRST)],
    );
    assert_eq!(
        catalog.references(),
        &[trojan_reference(FIRST), trojan_reference(SECOND)]
    );
    assert_eq!(
        catalog.bindings().collect::<Vec<_>>(),
        [binding(FIRST), binding(SECOND)]
    );

    let reused = CredentialRef::new(FIRST, CredentialKind::TuicPassword).expect("reference");
    assert_eq!(
        CredentialProfileCatalogEntry::new(
            audience(&uuid(1)),
            vec![trojan_reference(FIRST), reused]
        ),
        Err(CredentialGarbageCollectionRequestError::DuplicateReference)
    );
    assert!(
        CredentialProfileCatalogEntry::new(
            audience(&uuid(1)),
            many_references(MAX_CREDENTIAL_SLOTS)
        )
        .is_ok()
    );
    assert_eq!(
        CredentialProfileCatalogEntry::new(
            audience(&uuid(1)),
            many_references(MAX_CREDENTIAL_SLOTS + 1)
        ),
        Err(CredentialGarbageCollectionRequestError::TooManyBindings)
    );
}

#[test]
fn a_repository_snapshot_needs_a_lowercase_digest() {
    for digest in [
        "AB".repeat(32),
        "ab".repeat(31),
        "ab".repeat(33),
        format!("{}g", "a".repeat(63)),
    ] {
        assert_eq!(
            CredentialGarbageCollectionRequest::new(digest, Vec::new()),
            Err(CredentialGarbageCollectionRequestError::InvalidSnapshotDigest)
        );
    }
}

#[test]
fn a_repository_catalog_is_sorted_unique_and_bounded() {
    let first = entry(&uuid(1), vec![trojan_reference(FIRST)]);
    let second = entry(&uuid(2), Vec::new());
    let request = CredentialGarbageCollectionRequest::new(
        "ab".repeat(32),
        vec![second.clone(), first.clone()],
    )
    .expect("catalog");
    assert_eq!(request.snapshot_digest(), "ab".repeat(32));
    assert_eq!(request.catalog(), &[first.clone(), second]);

    let same_profile = CredentialProfileCatalogEntry::new(
        CredentialAudience::new(uuid(1), "12".repeat(32)).expect("audience"),
        Vec::new(),
    )
    .expect("entry");
    assert_eq!(
        CredentialGarbageCollectionRequest::new("ab".repeat(32), vec![first, same_profile]),
        Err(CredentialGarbageCollectionRequestError::DuplicateProfile)
    );

    let profiles = |count: usize| {
        (0..count)
            .map(|n| entry(&uuid(n), Vec::new()))
            .collect::<Vec<_>>()
    };
    assert!(
        CredentialGarbageCollectionRequest::new(
            "ab".repeat(32),
            profiles(MAX_CREDENTIAL_CATALOG_PROFILES)
        )
        .is_ok()
    );
    assert_eq!(
        CredentialGarbageCollectionRequest::new(
            "ab".repeat(32),
            profiles(MAX_CREDENTIAL_CATALOG_PROFILES + 1)
        ),
        Err(CredentialGarbageCollectionRequestError::TooManyProfiles)
    );
}

#[test]
fn every_profile_binding_counts_toward_the_vault_limit() {
    let full = MAX_CREDENTIAL_VAULT_BINDINGS / MAX_CREDENTIAL_SLOTS;
    let catalog = |profiles: usize| {
        (0..profiles)
            .map(|n| entry(&uuid(n), many_references(MAX_CREDENTIAL_SLOTS)))
            .collect::<Vec<_>>()
    };
    assert!(CredentialGarbageCollectionRequest::new("ab".repeat(32), catalog(full)).is_ok());
    let mut over = catalog(full);
    over.push(entry(&uuid(full), many_references(1)));
    assert_eq!(
        CredentialGarbageCollectionRequest::new("ab".repeat(32), over),
        Err(CredentialGarbageCollectionRequestError::TooManyBindings)
    );
}

#[test]
fn a_preview_must_be_canonical_counted_and_bound_to_a_revision() {
    assert_eq!(preview().validate(), Ok(()));
    let rejected = |change: fn(&mut CredentialGarbageCollectionPreview)| {
        let mut preview = preview();
        change(&mut preview);
        preview.validate()
    };
    assert_eq!(
        rejected(|preview| preview.snapshot_digest = "AB".repeat(32)),
        Err(CredentialGarbageCollectionRequestError::InvalidSnapshotDigest)
    );
    assert_eq!(
        rejected(|preview| preview.vault_revision = VAULT_REVISION.to_uppercase()),
        Err(CredentialGarbageCollectionRequestError::InvalidVaultRevision)
    );
    assert_eq!(
        rejected(|preview| preview.orphan_bindings.reverse()),
        Err(CredentialGarbageCollectionRequestError::InvalidPreview)
    );
    assert_eq!(
        rejected(|preview| preview.orphan_count = 3),
        Err(CredentialGarbageCollectionRequestError::InvalidPreview)
    );
    assert_eq!(
        rejected(|preview| preview.orphan_bindings[1] = preview.orphan_bindings[0].clone()),
        Err(CredentialGarbageCollectionRequestError::DuplicateBinding)
    );
    let mut oversized = preview();
    oversized.orphan_bindings = (0..=MAX_CREDENTIAL_VAULT_BINDINGS)
        .map(|n| CredentialBinding::new(audience(&uuid(1)), trojan_reference(&uuid(n))))
        .collect();
    oversized.orphan_count = u32::try_from(oversized.orphan_bindings.len()).expect("count");
    assert_eq!(
        oversized.validate(),
        Err(CredentialGarbageCollectionRequestError::TooManyBindings)
    );
}

#[test]
fn a_commit_carries_the_exact_canonical_preview() {
    let repository =
        || CredentialGarbageCollectionRequest::new("ab".repeat(32), Vec::new()).expect("snapshot");
    let commit =
        CredentialGarbageCollectionCommitRequest::new(repository(), &preview()).expect("commit");
    assert_eq!(commit.expected_vault_revision(), VAULT_REVISION);
    assert_eq!(commit.expected_orphan_bindings(), preview().orphan_bindings);

    let rejected = |change: fn(&mut CredentialGarbageCollectionPreview)| {
        let mut preview = preview();
        change(&mut preview);
        CredentialGarbageCollectionCommitRequest::new(repository(), &preview)
    };
    assert_eq!(
        rejected(|preview| preview.vault_revision = "not-a-revision".into()),
        Err(CredentialGarbageCollectionRequestError::InvalidVaultRevision)
    );
    assert_eq!(
        rejected(|preview| preview.orphan_bindings.reverse()),
        Err(CredentialGarbageCollectionRequestError::InvalidPreview)
    );
    assert_eq!(
        rejected(|preview| preview.orphan_count = 1),
        Err(CredentialGarbageCollectionRequestError::InvalidPreview)
    );
    assert_eq!(
        rejected(|preview| preview.orphan_bindings[1] = preview.orphan_bindings[0].clone()),
        Err(CredentialGarbageCollectionRequestError::DuplicateBinding)
    );
}

#[test]
fn a_receipt_names_a_canonical_vault_revision() {
    let receipt = |vault_revision: &str| CredentialGarbageCollectionReceipt {
        vault_revision: vault_revision.into(),
        deleted_count: 1,
    };
    assert_eq!(receipt(VAULT_REVISION).validate(), Ok(()));
    for revision in [
        VAULT_REVISION.to_uppercase(),
        "not-a-revision".into(),
        String::new(),
    ] {
        assert_eq!(
            receipt(&revision).validate(),
            Err(CredentialGarbageCollectionRequestError::InvalidVaultRevision)
        );
    }
}
