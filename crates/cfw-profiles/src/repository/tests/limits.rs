//! The repository's aggregate byte and credential-reference limits.

use super::*;

#[test]
fn aggregate_repository_limit_is_checked_before_a_new_write() {
    ensure_repository_bytes(MAX_REPOSITORY_BYTES - 1, 1).expect("exact limit is admitted");
    assert!(matches!(
        ensure_repository_bytes(MAX_REPOSITORY_BYTES, 1),
        Err(ProfileError::RepositoryTooLarge { actual })
            if actual == MAX_REPOSITORY_BYTES + 1
    ));
    assert!(matches!(
        ensure_repository_bytes(u64::MAX, 1),
        Err(ProfileError::RepositoryTooLarge { actual: u64::MAX })
    ));
}

#[test]
fn aggregate_credential_refs_cannot_exceed_the_native_vault_capacity() {
    ensure_credential_reference_capacity(MAX_REPOSITORY_CREDENTIAL_REFERENCES)
        .expect("exact vault capacity is admitted");
    assert!(matches!(
        ensure_credential_reference_capacity(MAX_REPOSITORY_CREDENTIAL_REFERENCES + 1),
        Err(ProfileError::TooManyCredentialReferences)
    ));
}
