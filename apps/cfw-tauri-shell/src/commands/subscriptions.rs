//! Profile text, files, and subscriptions restored from 0.3.5.
//!
//! Every document that reaches the repository is a validated sing-box profile:
//! remote and local imports parse into [`ValidatedSingBoxProfile`] and are
//! projected for both modes before they are stored, exactly like the existing
//! text import. Subscription bodies in other syntaxes (Clash Meta YAML
//! `proxies`, Shadowsocks SIP008 JSON, node-URI bundles) are converted into
//! that closed schema at the import boundary by
//! [`import_subscription_document`]; only the node list is
//! converted, because the projection owns listeners, logging, the
//! experimental controller, and DNS. There is no template engine and no
//! mixin.
//!
//! A subscription URL is stored inside the profile envelope, so it is deleted
//! with the profile and cannot drift. Because it can carry an access token it is
//! never part of a profile list: only an explicit single-profile read returns
//! it.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use cfw_engine_api::CredentialVaultProvisioner;
use cfw_profiles::{
    ExactProfileImportOutcome, ProfileImportResult, ProfileRepository, StoredProfile,
};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use qrcode::QrCode;
use qrcode::render::svg;
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

mod fetch;
#[cfg(test)]
mod proxy_tests;
pub(super) use fetch::{SubscriptionRoute, fetch_provider_resources, validate_subscription_url};
use fetch::{fetch_subscription_bounded, resolve_provider_documents};

use super::ManagedProfiles;
use super::imported_credentials::{
    ImportedCredentialProvisionAttemptError, ImportedCredentialProvisionError,
    provision_imported_credentials_with_exact_replay,
};
use super::profiles::read_repository;
use super::shell_ops::{open_path, owned_profile_path};
use crate::engine::{ManagedEngine, apply_profile_change};
use crate::legacy::LegacyRetirementGate;
use crate::settings_store;
use crate::subscription_import::{
    ImportedCredential, MAX_SUBSCRIPTION_DOCUMENT_BYTES, import_subscription_document,
    import_subscription_document_with_credential_namespace,
    import_subscription_document_with_reusable_references,
};

/// 0.3.5 returned `ProfileText`; the fields that survive the new profile model
/// keep their names. `generated_body` is gone: the materialised engine
/// configuration is a projection that carries the app-owned controller secret
/// and is never handed to the renderer as profile text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiProfileText {
    digest: String,
    id: String,
    name: String,
    body: String,
    proxy_selections: std::collections::BTreeMap<String, String>,
    active: bool,
    source_url: Option<String>,
    bytes: usize,
    updated_epoch_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiProfileSaveResult {
    id: String,
    name: String,
    bytes: usize,
    digest: String,
    active: bool,
    reset_proxy_groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiSubscriptionUpdateResult {
    #[serde(flatten)]
    profile: ProfileImportResult,
    credential_cleanup_removed: u32,
    credential_cleanup_pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_cleanup_error: Option<String>,
    reset_proxy_groups: Vec<String>,
}

#[tauri::command]
pub(crate) async fn import_profile_url(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    url: String,
    name: Option<String>,
    activate: bool,
) -> Result<ProfileImportResult, String> {
    let target = validate_subscription_url(&url)?;
    let body = fetch_subscription_bounded(
        &target,
        MAX_SUBSCRIPTION_DOCUMENT_BYTES,
        SubscriptionRoute::for_engine(&engine)?,
    )
    .await?;
    import_online(
        &engine,
        &retirement,
        &profiles,
        body,
        name,
        Some(target.to_string()),
        activate,
    )
    .await
}

#[tauri::command]
pub(crate) async fn import_profile_text(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    name: Option<String>,
    body: String,
) -> Result<ProfileImportResult, String> {
    import_online(&engine, &retirement, &profiles, body, name, None, false).await
}

#[tauri::command]
pub(crate) async fn import_profile_file(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    path: String,
    name: Option<String>,
    activate: bool,
) -> Result<ProfileImportResult, String> {
    let body = read_local_profile(Path::new(&path))?;
    let name = name.or_else(|| {
        Path::new(&path)
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
    });
    import_online(&engine, &retirement, &profiles, body, name, None, activate).await
}

async fn import_online(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    body: String,
    name: Option<String>,
    source_url: Option<String>,
    activate: bool,
) -> Result<ProfileImportResult, String> {
    let body = resolve_provider_documents(body, SubscriptionRoute::for_engine(engine)?).await?;
    let repository = profiles.repository().clone();
    let vault = profiles.credential_vault().clone();
    apply_profile_change(engine, retirement, move |settings| async move {
        let imported = validated_subscription_import(&body, &settings)?;
        let id = Uuid::new_v4().hyphenated().to_string();
        let source = match source_url.as_deref() {
            Some(url) => ProfileImportSource::Subscription(url),
            None => ProfileImportSource::Local,
        };
        prepare_profile_import(
            &repository,
            &vault,
            &id,
            name.as_deref(),
            source,
            &imported,
            activate,
        )
        .await
    })
    .await
}

/// Fetch outside the engine queue. At admission, compare the current document,
/// preserve manual selections, and stage credentials without collecting the
/// old audience needed for runtime recovery.
#[tauri::command]
pub(crate) async fn update_profile(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<UiSubscriptionUpdateResult, String> {
    let read_id = id.clone();
    let before_fetch = read_repository(profiles.repository(), move |repository| {
        load_profile(repository, &read_id)
    })
    .await?;
    let source_url = before_fetch
        .source_url
        .as_deref()
        .ok_or_else(|| format!("profile has no subscription URL to update: {id}"))?;
    let target = validate_subscription_url(source_url)?;
    let route = SubscriptionRoute::for_engine(&engine)?;
    let body = fetch_subscription_bounded(&target, MAX_SUBSCRIPTION_DOCUMENT_BYTES, route).await?;
    let body = resolve_provider_documents(body, route).await?;
    let repository = profiles.repository().clone();
    let vault = profiles.credential_vault().clone();
    let (profile, reset_proxy_groups) =
        apply_profile_change(&engine, &retirement, move |settings| async move {
            let stored = load_profile(&repository, &id)?;
            if stored.profile.as_json() != before_fetch.profile.as_json()
                || stored.profile.provider_sources() != before_fetch.profile.provider_sources()
                || stored.source_url != before_fetch.source_url
                || stored.record.name != before_fetch.record.name
            {
                return Err(
                    "subscription profile changed while downloading; the response was not applied"
                        .into(),
                );
            }
            let imported = validated_subscription_import_with_reusable_references(
                &body,
                &settings,
                stored.profile.credential_references_in_outbound_order(),
            )?;
            let (_, reset_groups) = imported
                .profile
                .inherit_proxy_selections(&stored.profile)
                .map_err(|error| error.to_string())?;
            let candidate = prepare_subscription_update_with_rotation(
                &repository,
                &vault,
                &stored,
                target.as_str(),
                &body,
                &settings,
                &imported,
            )
            .await?;
            Ok(cfw_application::ProfileChange {
                profile_id: candidate.profile_id,
                profile: candidate.profile,
                activate: candidate.activate,
                previous_profile: candidate.previous_profile,
                commit: Box::new(move || {
                    (candidate.commit)().map(|profile| (profile, reset_groups))
                }),
            })
        })
        .await?;
    Ok(UiSubscriptionUpdateResult {
        profile,
        credential_cleanup_removed: 0,
        credential_cleanup_pending: true,
        credential_cleanup_error: None,
        reset_proxy_groups,
    })
}

/// Renames a profile and rebinds its subscription URL. The validated document
/// is untouched, so neither the digest nor the selection changes.
#[tauri::command]
pub(crate) fn update_profile_info(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    id: String,
    name: String,
    url: Option<String>,
) -> Result<(), String> {
    let source_url = url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(validate_subscription_url)
        .transpose()?;
    let _maintenance = engine
        .reserve_maintenance()
        .map_err(|error| error.to_string())?;
    profiles
        .repository()
        .update_metadata(
            &id,
            Some(&name),
            source_url.as_ref().map(|url| url.as_str()),
        )
        .map(|_record| ())
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) async fn read_profile_text(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<UiProfileText, String> {
    read_repository(profiles.repository(), move |repository| {
        let stored = load_profile(repository, &id)?;
        Ok(UiProfileText {
            digest: stored.record.digest,
            active: is_selected(repository, &id)?,
            id: stored.record.id,
            name: stored.record.name,
            bytes: stored.record.bytes,
            updated_epoch_secs: stored.record.created_epoch_secs,
            source_url: stored.source_url,
            body: stored.profile.as_json().to_owned(),
            proxy_selections: stored.profile.proxy_selections().clone(),
        })
    })
    .await
}

/// Replaces the document of an existing profile with edited text.
#[tauri::command]
pub(crate) async fn save_profile_text(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    id: String,
    expected_digest: String,
    body: String,
) -> Result<UiProfileSaveResult, String> {
    let repository = profiles.repository().clone();
    let vault = profiles.credential_vault().clone();
    apply_profile_change(&engine, &retirement, move |settings| async move {
        let mutation = repository
            .begin_credential_profile_mutation()
            .map_err(|error| error.to_string())?;
        let stored = mutation.profile(&id).map_err(|error| error.to_string())?;
        if stored.record.digest != expected_digest {
            return Err(
                "this profile changed while the editor was open; reload it before saving".into(),
            );
        }
        let previous = mutation
            .selected_profile()
            .map_err(|error| error.to_string())?;
        let active = previous.as_ref().is_some_and(|prior| prior.record.id == id);
        let (profile, reset_proxy_groups) = validated_profile(&body, &settings)?
            .inherit_proxy_selections(&stored.profile)
            .map_err(|error| error.to_string())?;
        let mut sources = stored.profile.provider_sources();
        sources.extend(profile.provider_sources());
        let valid_sources = profile
            .providers()
            .map(|catalog| {
                catalog
                    .proxies
                    .iter()
                    .map(|provider| format!("proxy:{}", provider.name))
                    .chain(
                        catalog
                            .rules
                            .iter()
                            .map(|provider| format!("rule:{}", provider.name)),
                    )
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default();
        sources.retain(|key, _| valid_sources.contains(key));
        let profile = profile
            .with_provider_sources(sources)
            .map_err(|error| error.to_string())?;
        if profile.digest() != stored.profile.digest()
            && !profile.credential_references().is_empty()
        {
            let request = cfw_engine_api::CredentialRebindRequest::new(
                &id,
                &stored.profile,
                &profile,
                &settings,
            )?;
            super::imported_credentials::rebind_with_exact_replay(&vault, request).await?;
        }
        let commit_profile = profile.clone();
        Ok(cfw_application::ProfileChange {
            profile_id: id,
            profile,
            activate: active,
            previous_profile: previous.map(|prior| (prior.record.id, prior.profile)),
            commit: Box::new(move || {
                let (saved, _) = mutation
                    .commit_replace_if_unchanged(
                        &stored,
                        None,
                        &commit_profile,
                        stored.source_url.as_deref(),
                    )
                    .map_err(|error| error.to_string())?;
                Ok(UiProfileSaveResult {
                    active,
                    id: saved.id,
                    name: saved.name,
                    bytes: saved.bytes,
                    digest: saved.digest,
                    reset_proxy_groups,
                })
            }),
        })
    })
    .await
}

#[tauri::command]
pub(crate) async fn profile_qrcode_svg(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<String, String> {
    let stored = read_repository(profiles.repository(), move |repository| {
        load_profile(repository, &id)
    })
    .await?;
    let source_url = stored
        .source_url
        .ok_or_else(|| "local profiles do not have subscription URLs to encode".to_owned())?;
    let code = QrCode::new(source_url.as_bytes()).map_err(|error| error.to_string())?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(190, 190)
        .dark_color(svg::Color("#2c3e50"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[tauri::command]
pub(crate) async fn reveal_profile(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<(), String> {
    let path = read_repository(profiles.repository(), move |repository| {
        existing_profile_path(repository, &id)
    })
    .await?;
    open_path(&path, true)
}

/// Opens the stored profile envelope with the user's default application.
///
/// The envelope is integrity-checked, so an external edit is rejected on the
/// next read; `save_profile_text` is the supported way to change a profile.
#[tauri::command]
pub(crate) async fn open_profile_externally(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<(), String> {
    let path = read_repository(profiles.repository(), move |repository| {
        existing_profile_path(repository, &id)
    })
    .await?;
    open_path(&path, false)
}

/// Parses and validates a document, and proves it projects for both modes before
/// it can be stored, so an unstartable profile is rejected at import time.
fn validated_profile(
    body: &str,
    settings: &EngineSettings,
) -> Result<ValidatedSingBoxProfile, String> {
    let profile = ValidatedSingBoxProfile::parse(body).map_err(|error| error.to_string())?;
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        profile
            .project("00000000-0000-4000-8000-000000000000", mode, settings)
            .map_err(|error| error.to_string())?;
    }
    Ok(profile)
}

fn validated_subscription_import(
    body: &str,
    settings: &EngineSettings,
) -> Result<crate::subscription_import::ImportedSubscription, String> {
    let imported = import_subscription_document(body)?;
    validate_subscription_projection(&imported, settings)?;
    Ok(imported)
}

pub(super) fn validated_subscription_import_with_namespace(
    body: &str,
    settings: &EngineSettings,
    credential_namespace: uuid::Uuid,
) -> Result<crate::subscription_import::ImportedSubscription, String> {
    let imported =
        import_subscription_document_with_credential_namespace(body, credential_namespace)?;
    validate_subscription_projection(&imported, settings)?;
    Ok(imported)
}

fn validated_subscription_import_with_reusable_references(
    body: &str,
    settings: &EngineSettings,
    references: Vec<cfw_singbox_config::CredentialRef>,
) -> Result<crate::subscription_import::ImportedSubscription, String> {
    let imported = import_subscription_document_with_reusable_references(body, references)?;
    validate_subscription_projection(&imported, settings)?;
    Ok(imported)
}

fn validate_subscription_projection(
    imported: &crate::subscription_import::ImportedSubscription,
    settings: &EngineSettings,
) -> Result<(), String> {
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        imported
            .profile
            .project("00000000-0000-4000-8000-000000000000", mode, settings)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Local canonical profiles can intentionally omit secret material for later
/// manual provisioning. Converted sources with extracted credentials, and all
/// remote subscriptions, must confirm their complete vault audience first.
#[derive(Clone, Copy)]
enum ProfileImportSource<'a> {
    Local,
    Subscription(&'a str),
}

async fn prepare_profile_import(
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
        .map_err(|error| error.to_string())?;
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
async fn commit_profile_import(
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
fn profile_import_activation_error(error: impl fmt::Display) -> String {
    format!("profile import committed, but selection failed: {error}")
}

#[derive(Debug)]
pub(super) enum SubscriptionUpdateCommitError {
    Mutation(String),
    Credential(ImportedCredentialProvisionError),
    Repository(String),
}

impl SubscriptionUpdateCommitError {
    pub(super) fn is_immutable_conflict(&self) -> bool {
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

pub(super) async fn prepare_subscription_update_attempt(
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
        super::imported_credentials::rebind_with_exact_replay(vault, request)
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
        .map_err(|error| SubscriptionUpdateCommitError::Mutation(error.to_string()))?;
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
async fn commit_subscription_update_attempt(
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
async fn commit_subscription_update_with_rotation(
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
async fn commit_subscription_update(
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

async fn provision_subscription_credentials(
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

async fn provision_subscription_credentials_attempt(
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

fn load_profile(repository: &ProfileRepository, id: &str) -> Result<StoredProfile, String> {
    repository
        .load(id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("profile does not exist: {id}"))
}

fn is_selected(repository: &ProfileRepository, id: &str) -> Result<bool, String> {
    Ok(repository
        .snapshot()
        .map_err(|error| error.to_string())?
        .selected_profile_id
        .as_deref()
        == Some(id))
}

fn existing_profile_path(repository: &ProfileRepository, id: &str) -> Result<PathBuf, String> {
    let file_name = repository
        .profile_entry_name(id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("profile does not exist: {id}"))?;
    let store = settings_store()?;
    owned_profile_path(&store.paths().profiles_dir, &file_name)
}

fn read_local_profile(path: &Path) -> Result<String, String> {
    read_opened_local_profile(open_local_profile(path)?)
}

fn open_local_profile(path: &Path) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("profile path must be absolute".into());
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())
}

fn read_opened_local_profile(file: File) -> Result<String, String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("profile path is not a regular file".into());
    }
    if metadata.len() > MAX_SUBSCRIPTION_DOCUMENT_BYTES as u64 {
        return Err(format!(
            "profile file exceeds the {MAX_SUBSCRIPTION_DOCUMENT_BYTES}-byte limit"
        ));
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_SUBSCRIPTION_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() > MAX_SUBSCRIPTION_DOCUMENT_BYTES {
        return Err(format!(
            "profile file exceeds the {MAX_SUBSCRIPTION_DOCUMENT_BYTES}-byte limit"
        ));
    }
    String::from_utf8(body).map_err(|_| "profile document is not UTF-8".to_owned())
}

#[cfg(test)]
mod tests;
