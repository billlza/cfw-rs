//! A subscription update: credentials first, then a commit only if the stored
//! profile is unchanged, and one reference rotation after an immutable
//! conflict. An update that must keep the running engine declines a changed
//! document of the running profile before the vault is written.

use super::*;

/// A subscription document downloaded for one stored profile.
pub(super) struct FetchedUpdate {
    /// The profile as it was stored when the download began.
    pub(super) before_fetch: StoredProfile,
    pub(super) target: reqwest::Url,
    pub(super) body: String,
}

/// What an update may do to the profile a running engine uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RunningProfile {
    /// An update by hand: the engine is restarted onto the download.
    Replaceable,
    /// A background update: the profile is saved again only when the download
    /// is the document the engine already runs.
    Kept,
}

/// Why a download was not prepared as the replacement of its profile.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum UpdatePreparationError {
    /// The engine runs this profile and the download is not what it runs.
    /// Nothing was written to the vault.
    RunningProfileChanged,
    Failed(String),
}

impl fmt::Display for UpdatePreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunningProfileChanged => formatter.write_str(
                "the subscription differs from the profile the engine is running; the profile was kept",
            ),
            Self::Failed(message) => formatter.write_str(message),
        }
    }
}

/// Prepares a download as the replacement of the profile it was fetched for:
/// compare the stored profile with the one the download began from, preserve
/// manual selections, and stage credentials without collecting the old
/// audience needed for runtime recovery.
///
/// With [`RunningProfile::Kept`] the engine is on, so a selected profile is
/// the one it runs. Its replacement is prepared only when the download is the
/// same document under the same credentials, which needs no restart. Anything
/// else is declined before the vault is written: an audience staged for a
/// document that is never committed would be left behind by every attempt.
pub(super) async fn prepare_update(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    fetched: &FetchedUpdate,
    settings: &EngineSettings,
    running_profile: RunningProfile,
) -> Result<
    cfw_application::ProfileChange<(ProfileImportResult, Vec<String>)>,
    UpdatePreparationError,
> {
    let failed = UpdatePreparationError::Failed;
    let before_fetch = &fetched.before_fetch;
    let stored = load_profile(repository, &before_fetch.record.id).map_err(failed)?;
    if stored.profile.as_json() != before_fetch.profile.as_json()
        || stored.profile.provider_sources() != before_fetch.profile.provider_sources()
        || stored.source_url != before_fetch.source_url
        || stored.record.name != before_fetch.record.name
    {
        return Err(failed(
            "subscription profile changed while downloading; the response was not applied".into(),
        ));
    }
    let imported = validated_subscription_import_with_reusable_references(
        &fetched.body,
        settings,
        stored.profile.credential_references_in_outbound_order(),
    )
    .map_err(failed)?;
    let (_, reset_groups) = imported
        .profile
        .inherit_proxy_selections(&stored.profile)
        .map_err(|error| failed(error.to_string()))?;
    let running = running_profile == RunningProfile::Kept
        && is_selected(repository, &stored.record.id).map_err(failed)?;
    let candidate = if running {
        if imported.profile.digest() != stored.profile.digest() {
            return Err(UpdatePreparationError::RunningProfileChanged);
        }
        // The same document: the vault confirms the same credentials, or
        // answers an immutable conflict for different ones.
        match prepare_subscription_update_attempt(
            repository,
            vault,
            &stored,
            Some(fetched.target.as_str()),
            &imported,
            None,
        )
        .await
        {
            Ok(candidate) => candidate,
            Err(error) if error.is_immutable_conflict() => {
                return Err(UpdatePreparationError::RunningProfileChanged);
            }
            Err(error) => return Err(failed(error.to_string())),
        }
    } else {
        prepare_subscription_update_with_rotation(
            repository,
            vault,
            &stored,
            fetched.target.as_str(),
            &fetched.body,
            settings,
            &imported,
        )
        .await
        .map_err(failed)?
    };
    Ok(cfw_application::ProfileChange {
        profile_id: candidate.profile_id,
        profile: candidate.profile,
        activate: candidate.activate,
        previous_profile: candidate.previous_profile,
        commit: Box::new(move || (candidate.commit)().map(|profile| (profile, reset_groups))),
    })
}

/// Prepares a download as an update by hand does: whatever the engine runs,
/// the download replaces the stored profile, and a running engine is
/// restarted onto a changed document of its profile.
pub(super) async fn prepare_update_by_hand(
    repository: ProfileRepository,
    vault: impl CredentialVaultProvisioner,
    fetched: FetchedUpdate,
    settings: EngineSettings,
) -> Result<cfw_application::ProfileChange<(ProfileImportResult, Vec<String>)>, String> {
    prepare_update(
        &repository,
        &vault,
        &fetched,
        &settings,
        RunningProfile::Replaceable,
    )
    .await
    .map_err(|error| error.to_string())
}

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

async fn prepare_subscription_update_with_rotation(
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
