use cfw_singbox_config::CredentialKind;

use super::*;
use crate::test_support::{CREDENTIAL_ID, PROFILE_ID};

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
