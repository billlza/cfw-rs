//! Application-owned materialized resources. Fetching never takes the engine
//! lease; validation, credential binding, runtime replacement and storage commit
//! use the same serialized transaction as ordinary profile updates.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use cfw_controller::{ProviderBatchFailure, ProviderBatchResult, ProviderEntry, ProvidersSnapshot};
use cfw_profiles::StoredProfile;
use cfw_singbox_config::{ProviderSource, sha256_hex};
use serde_json::json;
use tauri::State;

use super::ManagedProfiles;
use super::profiles::read_repository;
use super::subscriptions::{fetch_provider_resources, prepare_subscription_update_attempt};
use crate::engine::{ManagedEngine, apply_profile_change};
use crate::legacy::LegacyRetirementGate;
use crate::subscription_import::{
    ProviderKind, ProviderRequest, replace_provider_resources, stored_provider_requests,
};

mod refresh;
pub(crate) use refresh::start_provider_refresh;

#[derive(Default)]
pub(crate) struct ManagedProviders {
    status: Mutex<BTreeMap<ResourceKey, ResourceStatus>>,
    update: tokio::sync::Mutex<()>,
    probe: tokio::sync::Mutex<()>,
    refresh_task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ResourceKey {
    profile: String,
    kind: ProviderKind,
    name: String,
    fingerprint: String,
}

#[derive(Clone)]
struct ResourceStatus {
    updated: u64,
    attempted: u64,
    update_error: Option<String>,
    health: Option<String>,
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".into())
}

fn key(
    stored: &StoredProfile,
    kind: ProviderKind,
    name: &str,
    source: &ProviderSource,
    content: &impl serde::Serialize,
) -> Result<ResourceKey, String> {
    let mut bytes = serde_json::to_vec(content).map_err(|error| error.to_string())?;
    bytes.push(0);
    bytes.extend_from_slice(source.url.as_deref().unwrap_or_default().as_bytes());
    Ok(ResourceKey {
        profile: stored.record.id.clone(),
        kind,
        name: name.into(),
        fingerprint: sha256_hex(&bytes),
    })
}

fn keys(stored: &StoredProfile) -> Result<Vec<ResourceKey>, String> {
    let mut result = Vec::new();
    if let Some(catalog) = stored.profile.providers() {
        for provider in &catalog.proxies {
            result.push(key(
                stored,
                ProviderKind::Proxy,
                &provider.name,
                &provider.source,
                provider,
            )?);
        }
        for provider in &catalog.rules {
            result.push(key(
                stored,
                ProviderKind::Rule,
                &provider.name,
                &provider.source,
                provider,
            )?);
        }
    }
    Ok(result)
}

impl ManagedProviders {
    fn synchronized(
        &self,
        stored: &StoredProfile,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<ResourceKey, ResourceStatus>>, String> {
        let keys = keys(stored)?;
        let mut status = self
            .status
            .lock()
            .map_err(|_| "provider status lock is unavailable")?;
        // At most the selected profile's bounded catalog is retained.
        status.retain(|key, _| keys.contains(key));
        for key in keys {
            status.entry(key).or_insert(ResourceStatus {
                updated: stored.record.created_epoch_secs,
                attempted: 0,
                update_error: None,
                health: None,
            });
        }
        Ok(status)
    }

    fn record_update(
        &self,
        stored: &StoredProfile,
        requests: &[ProviderRequest],
        result: Result<(), &str>,
    ) -> Result<(), String> {
        let time = now()?;
        for (key, status) in self.synchronized(stored)?.iter_mut() {
            if requests
                .iter()
                .any(|request| request.kind == key.kind && request.name == key.name)
            {
                status.attempted = time;
                status.update_error = result.err().map(str::to_owned);
                if result.is_ok() {
                    status.updated = time;
                }
            }
        }
        Ok(())
    }
}

fn snapshot(
    stored: &StoredProfile,
    manager: &ManagedProviders,
) -> Result<ProvidersSnapshot, String> {
    let status = manager.synchronized(stored)?;
    let mut snapshot = ProvidersSnapshot {
        proxy_providers: Vec::new(),
        rule_providers: Vec::new(),
    };
    let Some(catalog) = stored.profile.providers() else {
        return Ok(snapshot);
    };
    let extra = |kind, name: &str, source: &ProviderSource| {
        let mut extra = HashMap::new();
        extra.insert("updatable".into(), json!(source.url.is_some()));
        extra.insert("interval_seconds".into(), json!(source.interval_seconds));
        if let Some((_, status)) = status
            .iter()
            .find(|(key, _)| key.kind == kind && key.name == name)
        {
            extra.insert("updated_epoch_secs".into(), json!(status.updated));
            extra.insert("update_error".into(), json!(status.update_error));
            extra.insert("health".into(), json!(status.health));
        }
        extra
    };
    for provider in &catalog.proxies {
        snapshot.proxy_providers.push(ProviderEntry {
            name: provider.name.clone(),
            kind: "Proxy".into(),
            vehicle_type: if provider.source.url.is_some() {
                "HTTP"
            } else {
                "Inline"
            }
            .into(),
            behavior: None,
            updated_at: None,
            proxies: provider
                .members
                .iter()
                .map(|member| member.name.clone())
                .collect(),
            rules: Vec::new(),
            extra: extra(ProviderKind::Proxy, &provider.name, &provider.source),
        });
    }
    for provider in &catalog.rules {
        snapshot.rule_providers.push(ProviderEntry {
            name: provider.name.clone(),
            kind: "Rule".into(),
            vehicle_type: if provider.source.url.is_some() {
                "HTTP"
            } else {
                "Inline"
            }
            .into(),
            behavior: Some(
                match provider.behavior {
                    cfw_singbox_config::ProviderRuleBehavior::Domain => "domain",
                    cfw_singbox_config::ProviderRuleBehavior::IpCidr => "ipcidr",
                    cfw_singbox_config::ProviderRuleBehavior::Classical => "classical",
                }
                .into(),
            ),
            updated_at: None,
            proxies: Vec::new(),
            rules: provider
                .rules
                .iter()
                .map(|rule| rule.value.clone())
                .collect(),
            extra: extra(ProviderKind::Rule, &provider.name, &provider.source),
        });
    }
    Ok(snapshot)
}

async fn selected(profiles: &ManagedProfiles) -> Result<StoredProfile, String> {
    read_repository(profiles.repository(), |repository| {
        repository
            .require_selected()
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub(crate) async fn providers_snapshot(
    profiles: State<'_, ManagedProfiles>,
    providers: State<'_, ManagedProviders>,
) -> Result<ProvidersSnapshot, String> {
    let stored = read_repository(profiles.repository(), |repository| {
        match repository
            .snapshot()
            .map_err(|error| error.to_string())?
            .selected_profile_id
        {
            Some(id) => repository
                .load(&id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "selected provider profile disappeared".to_owned())
                .map(Some),
            None => Ok(None),
        }
    })
    .await?;
    match stored {
        Some(stored) => snapshot(&stored, &providers),
        None => Ok(ProvidersSnapshot {
            proxy_providers: Vec::new(),
            rule_providers: Vec::new(),
        }),
    }
}

fn unchanged_source(before: &StoredProfile, current: &StoredProfile) -> bool {
    before.record.id == current.record.id
        && before.record.name == current.record.name
        && before.profile.as_json() == current.profile.as_json()
        && before.profile.provider_sources() == current.profile.provider_sources()
        && before.source_url == current.source_url
}

async fn update_resources(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    manager: &ManagedProviders,
    stored: StoredProfile,
    requests: Vec<ProviderRequest>,
) -> Result<ProviderBatchResult, String> {
    let _guard = manager
        .update
        .try_lock()
        .map_err(|_| "another provider update is already in progress")?;
    let names = requests
        .iter()
        .map(|request| request.name.clone())
        .collect::<Vec<_>>();
    if requests.is_empty() {
        return Ok(ProviderBatchResult {
            action: "update".into(),
            requested: 0,
            succeeded: names,
            failed: Vec::new(),
        });
    }
    let operation = async {
        let route = super::subscriptions::SubscriptionRoute::for_engine(engine)?;
        let resources = fetch_provider_resources(requests.clone(), 0, route).await?;
        let repository = profiles.repository().clone();
        let vault = profiles.credential_vault().clone();
        let before = stored.clone();
        apply_profile_change(engine, retirement, move |settings| async move {
            let current = repository.require_selected().map_err(|error| error.to_string())?;
            if !unchanged_source(&before, &current) {
                return Err("selected provider configuration changed while downloading; the response was not applied".into());
            }
            let mut imported = replace_provider_resources(&current.profile, &resources, false)?;
            // An endpoint change must never copy an old secret to that endpoint.
            // Only the freshly downloaded provider rotates; retained nodes keep
            // their original references and are rebound natively.
            if imported.profile.retained_credential_references(&current.profile).is_err() {
                imported = replace_provider_resources(&current.profile, &resources, true)?;
            }
            match prepare_subscription_update_attempt(&repository, &vault, &current, current.source_url.as_deref(), &imported, Some(&settings)).await {
                Ok(candidate) => Ok(candidate),
                Err(error) if error.is_immutable_conflict() => {
                    let rotated = replace_provider_resources(&current.profile, &resources, true)?;
                    prepare_subscription_update_attempt(&repository, &vault, &current, current.source_url.as_deref(), &rotated, Some(&settings)).await.map_err(|error| error.to_string())
                }
                Err(error) => Err(error.to_string()),
            }
        }).await?;
        Ok::<_, String>(())
    }.await;
    match operation {
        Ok(()) => {
            let current = selected(profiles).await?;
            if current.record.id == stored.record.id {
                manager.record_update(&current, &requests, Ok(()))?;
            }
            Ok(ProviderBatchResult {
                action: "update".into(),
                requested: names.len(),
                succeeded: names,
                failed: Vec::new(),
            })
        }
        Err(error) => {
            manager.record_update(&stored, &requests, Err(&error))?;
            Err(error)
        }
    }
}

async fn update_kind(
    engine: &ManagedEngine,
    retirement: &LegacyRetirementGate,
    profiles: &ManagedProfiles,
    providers: &ManagedProviders,
    kind: ProviderKind,
    name: Option<&str>,
) -> Result<ProviderBatchResult, String> {
    let stored = selected(profiles).await?;
    let requests = stored_provider_requests(&stored.profile, kind, name)?;
    update_resources(engine, retirement, profiles, providers, stored, requests).await
}

#[tauri::command]
pub(crate) async fn update_proxy_provider(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    providers: State<'_, ManagedProviders>,
    name: String,
) -> Result<(), String> {
    update_kind(
        &engine,
        &retirement,
        &profiles,
        &providers,
        ProviderKind::Proxy,
        Some(&name),
    )
    .await
    .map(|_| ())
}
#[tauri::command]
pub(crate) async fn update_rule_provider(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    providers: State<'_, ManagedProviders>,
    name: String,
) -> Result<(), String> {
    update_kind(
        &engine,
        &retirement,
        &profiles,
        &providers,
        ProviderKind::Rule,
        Some(&name),
    )
    .await
    .map(|_| ())
}
#[tauri::command]
pub(crate) async fn update_all_proxy_providers(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    providers: State<'_, ManagedProviders>,
) -> Result<ProviderBatchResult, String> {
    update_kind(
        &engine,
        &retirement,
        &profiles,
        &providers,
        ProviderKind::Proxy,
        None,
    )
    .await
}
#[tauri::command]
pub(crate) async fn update_all_rule_providers(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    providers: State<'_, ManagedProviders>,
) -> Result<ProviderBatchResult, String> {
    update_kind(
        &engine,
        &retirement,
        &profiles,
        &providers,
        ProviderKind::Rule,
        None,
    )
    .await
}

async fn health_check(
    engine: &ManagedEngine,
    profiles: &ManagedProfiles,
    manager: &ManagedProviders,
    name: Option<&str>,
) -> Result<ProviderBatchResult, String> {
    let _guard = manager
        .probe
        .try_lock()
        .map_err(|_| "another provider health check is in progress")?;
    let stored = selected(profiles).await?;
    let catalog = stored
        .profile
        .providers()
        .ok_or("selected profile has no providers")?;
    let candidates = catalog
        .proxies
        .iter()
        .filter(|provider| name.is_none_or(|name| name == provider.name))
        .collect::<Vec<_>>();
    if name.is_some() && candidates.is_empty() {
        return Err("proxy provider is not in the selected profile".into());
    }
    let mut result = ProviderBatchResult {
        action: "health-check".into(),
        requested: candidates.len(),
        succeeded: Vec::new(),
        failed: Vec::new(),
    };
    let operation = async {
        for provider in candidates {
            let mut usable = 0;
            let mut completed = 0;
            let target = provider.health_check.as_ref();
            // Eight requests share each transient runtime. It closes before the
            // next batch; there is one bounded whole-operation deadline too.
            for members in provider.members.chunks(8) {
                let delays = super::controller::probe_saved_nodes(
                    engine,
                    profiles,
                    Some(stored.record.id.clone()),
                    members.iter().map(|member| member.tag.clone()).collect(),
                    super::controller::ProbePolicy {
                        url: target
                            .map(|health| health.url.clone())
                            .unwrap_or_else(|| "https://www.gstatic.com/generate_204".into()),
                        timeout_ms: target.map(|health| health.timeout_ms).unwrap_or(5000),
                        concurrency: 8,
                        expected_status: target
                            .and_then(|health| health.expected_status.clone())
                            .unwrap_or_default(),
                    },
                )
                .await?;
                completed += delays.len();
                usable += delays.iter().filter(|delay| delay.delay.is_some()).count();
            }
            let current = selected(profiles).await?;
            if !unchanged_source(&stored, &current) {
                return Err(
                    "selected provider configuration changed during the health check".into(),
                );
            }
            let label = format!("{usable}/{completed} reachable");
            if let Some(status) = manager.synchronized(&current)?.get_mut(&key(
                &current,
                ProviderKind::Proxy,
                &provider.name,
                &provider.source,
                provider,
            )?) {
                status.health = Some(label.clone());
            }
            if usable == completed {
                result.succeeded.push(provider.name.clone());
            } else {
                result.failed.push(ProviderBatchFailure {
                    name: provider.name.clone(),
                    error: label,
                });
            }
        }
        Ok(result)
    };
    tokio::time::timeout(std::time::Duration::from_secs(120), operation)
        .await
        .map_err(|_| "provider health checks exceeded their 120-second deadline".to_owned())?
}

#[tauri::command]
pub(crate) async fn health_check_proxy_provider(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    providers: State<'_, ManagedProviders>,
    name: String,
) -> Result<(), String> {
    let result = health_check(&engine, &profiles, &providers, Some(&name)).await?;
    if result.is_complete_success() {
        Ok(())
    } else {
        Err(result
            .failed
            .iter()
            .map(|failure| format!("{}: {}", failure.name, failure.error))
            .collect::<Vec<_>>()
            .join("; "))
    }
}

#[tauri::command]
pub(crate) async fn health_check_all_proxy_providers(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    providers: State<'_, ManagedProviders>,
) -> Result<ProviderBatchResult, String> {
    health_check(&engine, &profiles, &providers, None).await
}

#[tauri::command]
pub(crate) async fn update_all_providers(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    providers: State<'_, ManagedProviders>,
) -> Result<ProviderBatchResult, String> {
    let stored = selected(&profiles).await?;
    let mut requests = stored_provider_requests(&stored.profile, ProviderKind::Proxy, None)?;
    requests.extend(stored_provider_requests(
        &stored.profile,
        ProviderKind::Rule,
        None,
    )?);
    update_resources(
        &engine,
        &retirement,
        &profiles,
        &providers,
        stored,
        requests,
    )
    .await
}
