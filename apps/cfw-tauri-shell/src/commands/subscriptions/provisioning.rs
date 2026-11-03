//! Imported credentials reach the vault before the repository commits a
//! profile that references them.

use super::*;

pub(super) async fn provision_subscription_credentials(
    vault: &impl CredentialVaultProvisioner,
    profile_id: &str,
    profile: &ValidatedSingBoxProfile,
    credentials: &[ImportedCredential],
) -> Result<(), String> {
    provision_subscription_credentials_attempt(vault, profile_id, profile, credentials)
        .await
        .map_err(|error| {
            format!("imported credential provisioning failed before repository commit: {error}")
        })
}

pub(super) async fn provision_subscription_credentials_attempt(
    vault: &impl CredentialVaultProvisioner,
    profile_id: &str,
    profile: &ValidatedSingBoxProfile,
    credentials: &[ImportedCredential],
) -> Result<(), ImportedCredentialProvisionError> {
    if credentials.is_empty() && profile.credential_references().is_empty() {
        return Ok(());
    }
    provision_imported_credentials_with_exact_replay(vault, profile_id, profile, credentials).await
}
