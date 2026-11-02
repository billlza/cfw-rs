//! A new profile's import: its credentials reach the vault before the
//! repository commits it.

use super::*;

/// Local canonical profiles can intentionally omit secret material for later
/// manual provisioning. Converted sources with extracted credentials, and all
/// remote subscriptions, must confirm their complete vault audience first.
#[derive(Clone, Copy)]
pub(super) enum ProfileImportSource<'a> {
    Local,
    Subscription(&'a str),
}

pub(super) async fn prepare_profile_import(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    profile_id: &str,
    name: Option<&str>,
    source: ProfileImportSource<'_>,
    imported: &crate::subscription_import::ImportedSubscription,
    activate: bool,
) -> Result<cfw_application::ProfileChange<ProfileImportResult>, String> {
    let mutation = repository
        .begin_credential_profile_mutation()
        .map_err(|error| {
            format!(
                "profile repository mutation could not begin before credential provisioning: {error}"
            )
        })?;
    if matches!(source, ProfileImportSource::Subscription(_)) || !imported.credentials.is_empty() {
        provision_subscription_credentials(
            vault,
            profile_id,
            &imported.profile,
            &imported.credentials,
        )
        .await?;
    }
    let source_url = match source {
        ProfileImportSource::Local => None,
        ProfileImportSource::Subscription(url) => Some(url),
    };
    let previous = mutation
        .selected_profile()
        .map_err(|error| error.to_string())?
        .into_valid();
    let profile_id = profile_id.to_owned();
    let name = name.map(ToOwned::to_owned);
    let source_url = source_url.map(ToOwned::to_owned);
    let profile = imported.profile.clone();
    let commit_profile = profile.clone();
    Ok(cfw_application::ProfileChange {
        profile_id: profile_id.clone(),
        profile,
        activate,
        previous_profile: previous.map(|prior| (prior.record.id, prior.profile)),
        commit: Box::new(move || {
            let ExactProfileImportOutcome { profile, created } = mutation
        .commit_exact_import_and_select(&profile_id, name.as_deref(), &commit_profile, source_url.as_deref(), activate)
        .map_err(|error| {
            format!(
                "profile repository import failed; any unreferenced vault audience is eligible for credential garbage collection: {error}"
            )
        })?;
            if !created {
                return Err(
                    "profile repository import rejected an unexpected exact-ID replay".into(),
                );
            }
            Ok(profile)
        }),
    })
}

#[cfg(test)]
pub(super) async fn commit_profile_import(
    repository: &ProfileRepository,
    vault: &impl CredentialVaultProvisioner,
    profile_id: &str,
    name: Option<&str>,
    source: ProfileImportSource<'_>,
    imported: &crate::subscription_import::ImportedSubscription,
    activate: bool,
) -> Result<ProfileImportResult, String> {
    let candidate = prepare_profile_import(
        repository, vault, profile_id, name, source, imported, activate,
    )
    .await?;
    (candidate.commit)()
}

#[cfg(test)]
pub(super) fn profile_import_activation_error(error: impl fmt::Display) -> String {
    format!("profile import committed, but selection failed: {error}")
}
