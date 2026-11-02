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
use std::path::{Path, PathBuf};

use cfw_engine_api::CredentialVaultProvisioner;
use cfw_profiles::{
    ExactProfileImportOutcome, ProfileImportResult, ProfileRepository, StoredProfile,
};
use cfw_singbox_config::{AppSelector, EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use qrcode::QrCode;
use qrcode::render::svg;
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

mod fetch;
mod import_transaction;
mod local_file;
mod provisioning;
#[cfg(test)]
mod proxy_tests;
mod update_transaction;
mod validation;
pub(super) use fetch::{SubscriptionRoute, fetch_provider_resources, validate_subscription_url};
use fetch::{fetch_subscription_bounded, resolve_provider_documents};
use import_transaction::{ProfileImportSource, prepare_profile_import};
#[cfg(test)]
use import_transaction::{commit_profile_import, profile_import_activation_error};
use provisioning::{
    provision_subscription_credentials, provision_subscription_credentials_attempt,
};
pub(super) use update_transaction::prepare_subscription_update_attempt;
use update_transaction::prepare_subscription_update_with_rotation;
#[cfg(test)]
use update_transaction::{
    SubscriptionUpdateCommitError, commit_subscription_update, commit_subscription_update_attempt,
    commit_subscription_update_with_rotation,
};
pub(super) use validation::validated_subscription_import_with_namespace;
use validation::{
    validated_profile, validated_subscription_import,
    validated_subscription_import_with_reusable_references,
};

use super::ManagedProfiles;
use super::imported_credentials::{
    ImportedCredentialProvisionAttemptError, ImportedCredentialProvisionError,
    provision_imported_credentials_with_exact_replay,
};
use super::profiles::read_repository;
use super::shell_ops::{open_path, owned_profile_path};
use crate::engine::{ManagedEngine, apply_profile_change};
use crate::platform_maintenance::PlatformMaintenanceGate;
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
    app_selector: Option<UiAppSelector>,
    active: bool,
    source_url: Option<String>,
    bytes: usize,
    updated_epoch_secs: u64,
}

/// The selector the running core puts in front of a profile that names no
/// final route. The saved profile view offers it like a selector group, so a
/// node can be chosen while the core is off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiAppSelector {
    tag: String,
    members: Vec<String>,
    default: String,
}

impl From<AppSelector> for UiAppSelector {
    fn from(selector: AppSelector) -> Self {
        Self {
            tag: selector.tag,
            members: selector.members,
            default: selector.default,
        }
    }
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
    retirement: State<'_, PlatformMaintenanceGate>,
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
    retirement: State<'_, PlatformMaintenanceGate>,
    profiles: State<'_, ManagedProfiles>,
    name: Option<String>,
    body: String,
) -> Result<ProfileImportResult, String> {
    import_online(&engine, &retirement, &profiles, body, name, None, false).await
}

#[tauri::command]
pub(crate) async fn import_profile_file(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
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
    retirement: &PlatformMaintenanceGate,
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
    retirement: State<'_, PlatformMaintenanceGate>,
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
pub(crate) async fn update_profile_info(
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
    let repository = profiles.repository().clone();
    crate::startup_state::prepare_off_main(move || {
        repository
            .update_metadata(
                &id,
                Some(&name),
                source_url.as_ref().map(|url| url.as_str()),
            )
            .map(|_record| ())
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub(crate) async fn read_profile_text(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<UiProfileText, String> {
    read_repository(profiles.repository(), move |repository| {
        profile_text(repository, &id)
    })
    .await
}

fn profile_text(repository: &ProfileRepository, id: &str) -> Result<UiProfileText, String> {
    let stored = load_profile(repository, id)?;
    Ok(UiProfileText {
        digest: stored.record.digest,
        active: is_selected(repository, id)?,
        id: stored.record.id,
        name: stored.record.name,
        bytes: stored.record.bytes,
        updated_epoch_secs: stored.record.created_epoch_secs,
        source_url: stored.source_url,
        body: stored.profile.as_json().to_owned(),
        app_selector: stored.profile.app_selector().map(UiAppSelector::from),
        proxy_selections: stored.profile.proxy_selections().clone(),
    })
}

/// Replaces the document of an existing profile with edited text.
#[tauri::command]
pub(crate) async fn save_profile_text(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, PlatformMaintenanceGate>,
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
            .map_err(|error| error.to_string())?
            .into_valid();
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
    crate::startup_state::prepare_off_main(move || open_path(&path, true)).await
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
    crate::startup_state::prepare_off_main(move || open_path(&path, false)).await
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
    local_file::read(path, MAX_SUBSCRIPTION_DOCUMENT_BYTES)
}

#[cfg(test)]
mod tests;
