//! A subscription update: credentials first, then a commit only if the stored
//! profile is unchanged, and one reference rotation after an immutable
//! conflict.

use super::*;

#[derive(Debug)]
pub(in crate::commands) enum SubscriptionUpdateCommitError {
    Mutation(String),
    Credential(ImportedCredentialProvisionError),
    Repository(String),
}

impl SubscriptionUpdateCommitError {
    pub(in crate::commands) fn is_immutable_conflict(&self) -> bool {
        matches!(
            self,
            Self::Credential(ImportedCredentialProvisionError::Rejected(
                ImportedCredentialProvisionAttemptError::Vault(
                    cfw_engine_api::CredentialVaultError::ImmutableConflict
                )
            ))
        )
    }
}

impl fmt::Display for SubscriptionUpdateCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mutation(error) => write!(
                formatter,
                "subscription repository mutation could not begin before credential provisioning: {error}"
            ),
            Self::Credential(error) => write!(
                formatter,
                "subscription credential provisioning failed before repository commit: {error}"
            ),
            Self::Repository(error) => write!(
                formatter,
                "subscription repository update failed after credential provisioning; the unreferenced vault audience is eligible for credential garbage collection: {error}"
            ),
        }
    }
}

pub(in crate::commands) async fn prepare_subscription_update_attempt(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    expected: &StoredProfile,
    source_url: Option<&str>,
    imported: &crate::subscription_import::ImportedSubscription,
    rebind_settings: Option<&EngineSettings>,
) -> Result<cfw_application::ProfileChange<ProfileImportResult>, SubscriptionUpdateCommitError> {
    let profile_id = &expected.record.id;
    let mutation = repository
        .begin_credential_profile_mutation_if_unchanged(expected)
        .map_err(|error| SubscriptionUpdateCommitError::Mutation(error.to_string()))?;
    if let Some(settings) = rebind_settings
        && imported.profile.digest() != expected.profile.digest()
        && let Some(request) = cfw_engine_api::CredentialRebindRequest::for_retained_credentials(
            profile_id,
            &expected.profile,
            &imported.profile,
            settings,
        )
        .map_err(SubscriptionUpdateCommitError::Mutation)?
    {
        crate::commands::imported_credentials::rebind_with_exact_replay(vault, request)
            .await
            .map_err(SubscriptionUpdateCommitError::Mutation)?;
    }
    provision_subscription_credentials_attempt(
        vault,
        profile_id,
        &imported.profile,
        &imported.credentials,
    )
    .await
    .map_err(SubscriptionUpdateCommitError::Credential)?;
    let previous = mutation
        .selected_profile()
        .map_err(|error| SubscriptionUpdateCommitError::Mutation(error.to_string()))?
        .into_valid();
    let activate = previous
        .as_ref()
        .is_some_and(|prior| prior.record.id == *profile_id);
    let expected = expected.clone();
    let source_url = source_url.map(str::to_owned);
    let (profile, _) = imported
        .profile
        .inherit_proxy_selections(&expected.profile)
        .map_err(|error| SubscriptionUpdateCommitError::Mutation(error.to_string()))?;
    let commit_profile = profile.clone();
    Ok(cfw_application::ProfileChange {
        profile_id: profile_id.clone(),
        profile,
        activate,
        previous_profile: previous.map(|prior| (prior.record.id, prior.profile)),
        commit: Box::new(move || {
            mutation
                .commit_replace_if_unchanged(
                    &expected,
                    None,
                    &commit_profile,
                    source_url.as_deref(),
                )
                .map(|(updated, _committed)| updated)
                .map_err(|error| {
                    SubscriptionUpdateCommitError::Repository(error.to_string()).to_string()
                })
        }),
    })
}

pub(super) async fn prepare_subscription_update_with_rotation(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    expected: &StoredProfile,
    source_url: &str,
    body: &str,
    settings: &EngineSettings,
    imported: &crate::subscription_import::ImportedSubscription,
) -> Result<cfw_application::ProfileChange<ProfileImportResult>, String> {
    match prepare_subscription_update_attempt(
        repository,
        vault,
        expected,
        Some(source_url),
        imported,
        None,
    )
    .await
    {
        Ok(profile) => Ok(profile),
        Err(error) if error.is_immutable_conflict() => {
            let rotated = validated_subscription_import(body, settings)?;
            prepare_subscription_update_attempt(
                repository,
                vault,
                expected,
                Some(source_url),
                &rotated,
                None,
            )
            .await
            .map_err(|error| error.to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
pub(super) async fn commit_subscription_update_attempt(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    expected: &StoredProfile,
    source_url: &str,
    imported: &crate::subscription_import::ImportedSubscription,
) -> Result<ProfileImportResult, SubscriptionUpdateCommitError> {
    let candidate = prepare_subscription_update_attempt(
        repository,
        vault,
        expected,
        Some(source_url),
        imported,
        None,
    )
    .await?;
    (candidate.commit)().map_err(SubscriptionUpdateCommitError::Repository)
}

#[cfg(test)]
pub(super) async fn commit_subscription_update_with_rotation(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    expected: &StoredProfile,
    source_url: &str,
    body: &str,
    settings: &EngineSettings,
    imported: &crate::subscription_import::ImportedSubscription,
) -> Result<ProfileImportResult, String> {
    let candidate = prepare_subscription_update_with_rotation(
        repository, vault, expected, source_url, body, settings, imported,
    )
    .await?;
    (candidate.commit)()
}

#[cfg(test)]
pub(super) async fn commit_subscription_update(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    expected: &StoredProfile,
    source_url: &str,
    imported: &crate::subscription_import::ImportedSubscription,
) -> Result<ProfileImportResult, String> {
    commit_subscription_update_attempt(repository, vault, expected, source_url, imported)
        .await
        .map_err(|error| error.to_string())
}
