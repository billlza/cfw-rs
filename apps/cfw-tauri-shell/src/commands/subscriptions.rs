//! Profile text, files, and subscriptions restored from 0.3.5.
//!
//! Every document that reaches the repository is a validated sing-box profile:
//! remote and local imports parse into [`ValidatedSingBoxProfile`] and are
//! projected for both modes before they are stored, exactly like the existing
//! text import. Subscription bodies in other syntaxes (Clash Meta YAML
//! `proxies`, node-URI bundles) are converted into that closed schema at the
//! import boundary by [`import_subscription_document`]; only the node list is
//! converted, because the projection owns listeners, logging, the
//! experimental controller, and DNS. There is no template engine and no
//! mixin.
//!
//! A subscription URL is stored inside the profile envelope, so it is deleted
//! with the profile and cannot drift. Because it can carry an access token it is
//! never part of a profile list: only an explicit single-profile read returns
//! it.

use std::error::Error as StdError;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cfw_engine_api::{CredentialProvision, CredentialProvisionRequest, CredentialVaultProvisioner};
use cfw_profiles::{ProfileImportResult, ProfileRepository, StoredProfile};
use cfw_singbox_config::{
    CredentialSecret, EngineSettings, MAX_PROFILE_BYTES, ProjectionMode, ValidatedSingBoxProfile,
};
use futures_util::StreamExt as _;
use qrcode::QrCode;
use qrcode::render::svg;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use reqwest::{Client, Url};
use serde::Serialize;
use tauri::State;

use super::ManagedProfiles;
use super::shell_ops::{open_path, owned_profile_path};
use crate::engine::ManagedEngine;
use crate::settings_store;
use crate::subscription_import::{ImportedCredential, import_subscription_document};

const SUBSCRIPTION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SUBSCRIPTION_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Subscription panels negotiate the response format on this header. The
/// `clash.meta` product token makes them serve Clash Meta YAML with the full
/// modern protocol set (VLESS/Reality, Hysteria2), which the importer
/// converts into the closed schema. It must not contain `sing-box`: panels
/// answer that token with raw sing-box JSON whose inline secrets the closed
/// schema deliberately rejects.
const SUBSCRIPTION_USER_AGENT: &str = concat!("clash.meta cfw-rs/", env!("CARGO_PKG_VERSION"));
const MAX_SUBSCRIPTION_REDIRECTS: usize = 5;
/// Subscription URLs may carry credentials in their query string. Never let
/// reqwest synthesize a Referer header while following a redirect, including
/// redirects between otherwise-valid public HTTPS origins.
const FORWARD_SUBSCRIPTION_REFERER: bool = false;
const MAX_SUBSCRIPTION_DNS_ADDRESSES: usize = 64;
const IANA_IPV4_PROTOCOL_ASSIGNMENTS: ([u8; 4], u8) = ([192, 0, 0, 0], 24);
const IANA_IPV6_GLOBAL_UNICAST: ([u8; 16], u8) =
    ([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 3);
const IANA_IPV6_PROTOCOL_ASSIGNMENTS: ([u8; 16], u8) =
    ([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 23);
const WELL_KNOWN_NAT64_PREFIX: ([u8; 16], u8) = (
    [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    96,
);
/// Legacy Clash for Windows profile directory, read only to explain why its
/// documents cannot be imported.
const LEGACY_CFW_PROFILES_DIR: &str = ".config/clash/profiles";
const MAX_LEGACY_ENTRIES_REPORTED: usize = 4_096;

/// 0.3.5 returned `ProfileText`; the fields that survive the new profile model
/// keep their names. `generated_body` is gone: the materialised engine
/// configuration is a projection that carries the app-owned controller secret
/// and is never handed to the renderer as profile text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UiProfileText {
    id: String,
    name: String,
    body: String,
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
}

#[tauri::command]
pub(crate) async fn import_profile_url(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    url: String,
    name: Option<String>,
    activate: bool,
) -> Result<ProfileImportResult, String> {
    let target = validate_subscription_url(&url)?;
    let body = fetch_subscription(&target).await?;
    let settings = engine.engine_settings().clone();
    let imported = validated_subscription_import(&body, &settings)?;
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let imported_record = profiles
        .repository()
        .import_with_source(name.as_deref(), &imported.profile, Some(target.as_str()))
        .map_err(|error| error.to_string())?;
    let mut rollback =
        SubscriptionMutationRollback::delete(profiles.repository(), imported_record.id.clone());
    if let Err(error) = provision_imported_credentials(
        &profiles,
        &imported_record.id,
        &imported.profile,
        &imported.credentials,
    )
    .await
    {
        return Err(rollback.rollback_import(error));
    }
    activate_if_requested(profiles.repository(), &imported_record.id, activate)?;
    rollback.disarm();
    Ok(imported_record)
}

#[tauri::command]
pub(crate) async fn import_profile_file(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    path: String,
    name: Option<String>,
    activate: bool,
) -> Result<ProfileImportResult, String> {
    let body = read_local_profile(Path::new(&path))?;
    let settings = engine.engine_settings().clone();
    let profile = validated_profile(&body, &settings)?;
    let fallback_name = Path::new(&path)
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string());
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let imported = profiles
        .repository()
        .import_with_source(name.as_deref().or(fallback_name.as_deref()), &profile, None)
        .map_err(|error| error.to_string())?;
    activate_if_requested(profiles.repository(), &imported.id, activate)?;
    Ok(imported)
}

/// Re-fetches a stored subscription and replaces the profile in place, keeping
/// its identity, its credentials, and its selection.
#[tauri::command]
pub(crate) async fn update_profile(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<ProfileImportResult, String> {
    let stored = load_profile(profiles.repository(), &id)?;
    let source_url = stored
        .source_url
        .as_deref()
        .ok_or_else(|| format!("profile has no subscription URL to update: {id}"))?;
    let target = validate_subscription_url(source_url)?;
    let body = fetch_subscription(&target).await?;
    let settings = engine.engine_settings().clone();
    let imported = validated_subscription_import(&body, &settings)?;
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let updated = profiles
        .repository()
        .replace(&id, None, &imported.profile, Some(target.as_str()))
        .map_err(|error| error.to_string())?;
    let mut rollback =
        SubscriptionMutationRollback::restore(profiles.repository(), id.clone(), stored);
    if let Err(error) =
        provision_imported_credentials(&profiles, &id, &imported.profile, &imported.credentials)
            .await
    {
        return Err(rollback.rollback_update(error));
    }
    rollback.disarm();
    Ok(updated)
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
        .reserve_profile_mutation()
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
pub(crate) fn read_profile_text(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<UiProfileText, String> {
    let stored = load_profile(profiles.repository(), &id)?;
    Ok(UiProfileText {
        active: is_selected(profiles.repository(), &id)?,
        id: stored.record.id,
        name: stored.record.name,
        bytes: stored.record.bytes,
        updated_epoch_secs: stored.record.created_epoch_secs,
        source_url: stored.source_url,
        body: stored.profile.as_json().to_owned(),
    })
}

/// Replaces the document of an existing profile with edited text.
#[tauri::command]
pub(crate) fn save_profile_text(
    engine: State<'_, ManagedEngine>,
    profiles: State<'_, ManagedProfiles>,
    id: String,
    body: String,
) -> Result<UiProfileSaveResult, String> {
    let stored = load_profile(profiles.repository(), &id)?;
    let settings = engine.engine_settings().clone();
    let profile = validated_profile(&body, &settings)?;
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let saved = profiles
        .repository()
        .replace(&id, None, &profile, stored.source_url.as_deref())
        .map_err(|error| error.to_string())?;
    Ok(UiProfileSaveResult {
        active: is_selected(profiles.repository(), &id)?,
        id: saved.id,
        name: saved.name,
        bytes: saved.bytes,
        digest: saved.digest,
    })
}

#[tauri::command]
pub(crate) fn profile_qrcode_svg(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<String, String> {
    let stored = load_profile(profiles.repository(), &id)?;
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
pub(crate) fn reveal_profile(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<(), String> {
    open_path(&existing_profile_path(&profiles, &id)?, true)
}

/// Opens the stored profile envelope with the user's default application.
///
/// The envelope is integrity-checked, so an external edit is rejected on the
/// next read; `save_profile_text` is the supported way to change a profile.
#[tauri::command]
pub(crate) fn open_profile_externally(
    profiles: State<'_, ManagedProfiles>,
    id: String,
) -> Result<(), String> {
    open_path(&existing_profile_path(&profiles, &id)?, false)
}

/// Reports the legacy Clash for Windows profile documents that were found and
/// refuses to convert them in place.
///
/// Subscription import converts Clash Meta YAML fetched from a live URL, so
/// re-importing is lossless and yields fresh credentials. Bulk-converting
/// stale on-disk documents here would silently resurrect dead nodes and
/// expired secrets without their subscription URL, so the migration path
/// deliberately reports instead of writing. 0.3.5 also returned an error when
/// nothing could be imported, so the failure shape is unchanged.
#[tauri::command]
pub(crate) fn migrate_legacy_cfw_profiles() -> Result<Vec<ProfileImportResult>, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not available")?;
    let legacy_dir = PathBuf::from(home).join(LEGACY_CFW_PROFILES_DIR);
    let found = count_legacy_documents(&legacy_dir);
    if found == 0 {
        return Err(format!(
            "no importable legacy profiles found in {}",
            legacy_dir.display()
        ));
    }
    Err(format!(
        "found {found} legacy Clash for Windows profile document(s) in {}; these on-disk copies carry no subscription URL and may hold stale nodes, so nothing was converted or written. Re-import each subscription with Import from URL",
        legacy_dir.display()
    ))
}

fn count_legacy_documents(legacy_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(legacy_dir) else {
        return 0;
    };
    entries
        .flatten()
        .take(MAX_LEGACY_ENTRIES_REPORTED)
        .filter(|entry| {
            entry
                .file_type()
                .is_ok_and(|kind| kind.is_file() || kind.is_symlink())
        })
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name != "list.yml" && (name.ends_with(".yml") || name.ends_with(".yaml"))
        })
        .count()
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
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        imported
            .profile
            .project("00000000-0000-4000-8000-000000000000", mode, settings)
            .map_err(|error| error.to_string())?;
    }
    Ok(imported)
}

async fn provision_imported_credentials(
    profiles: &ManagedProfiles,
    profile_id: &str,
    profile: &ValidatedSingBoxProfile,
    credentials: &[ImportedCredential],
) -> Result<(), String> {
    if credentials.is_empty() {
        return Ok(());
    }
    let entries = credentials
        .iter()
        .map(|credential| {
            CredentialSecret::new(&credential.secret)
                .map(|secret| CredentialProvision::new(&credential.reference, secret))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let request = CredentialProvisionRequest::new(profile_id, profile, entries)
        .map_err(|error| error.to_string())?;
    let receipt = profiles
        .credential_vault()
        .clone()
        .provision_profile_credentials(request)
        .await
        .map_err(|error| error.to_string())?;
    if receipt.profile_id != profile_id || receipt.profile_digest != profile.digest() {
        return Err(
            "credential vault receipt does not match the imported subscription profile".into(),
        );
    }
    Ok(())
}

enum SubscriptionRollbackAction {
    Delete,
    Restore(Box<StoredProfile>),
}

struct SubscriptionMutationRollback<'a> {
    repository: &'a ProfileRepository,
    profile_id: String,
    action: Option<SubscriptionRollbackAction>,
}

impl<'a> SubscriptionMutationRollback<'a> {
    fn delete(repository: &'a ProfileRepository, profile_id: String) -> Self {
        Self {
            repository,
            profile_id,
            action: Some(SubscriptionRollbackAction::Delete),
        }
    }

    fn restore(
        repository: &'a ProfileRepository,
        profile_id: String,
        stored: StoredProfile,
    ) -> Self {
        Self {
            repository,
            profile_id,
            action: Some(SubscriptionRollbackAction::Restore(Box::new(stored))),
        }
    }

    fn disarm(&mut self) {
        self.action = None;
    }

    fn rollback_import(&mut self, error: String) -> String {
        match self.rollback() {
            Ok(()) => format!("subscription import failed: {error}"),
            Err(rollback_error) => {
                format!(
                    "subscription import failed: {error}; cleanup also failed: {rollback_error}"
                )
            }
        }
    }

    fn rollback_update(&mut self, error: String) -> String {
        match self.rollback() {
            Ok(()) => format!("subscription update failed and was rolled back: {error}"),
            Err(rollback_error) => format!(
                "subscription update failed: {error}; rollback also failed: {rollback_error}"
            ),
        }
    }

    fn rollback(&mut self) -> Result<(), String> {
        let Some(action) = self.action.take() else {
            return Ok(());
        };
        match action {
            SubscriptionRollbackAction::Delete => self
                .repository
                .delete(&self.profile_id)
                .map(|_| ())
                .map_err(|error| error.to_string()),
            SubscriptionRollbackAction::Restore(stored) => self
                .repository
                .replace(
                    &self.profile_id,
                    None,
                    &stored.profile,
                    stored.source_url.as_deref(),
                )
                .map(|_| ())
                .map_err(|error| error.to_string()),
        }
    }
}

impl Drop for SubscriptionMutationRollback<'_> {
    fn drop(&mut self) {
        let _ = self.rollback();
    }
}

fn activate_if_requested(
    repository: &ProfileRepository,
    id: &str,
    activate: bool,
) -> Result<(), String> {
    if !activate {
        return Ok(());
    }
    repository
        .select(id)
        .map(|_record| ())
        .map_err(|error| error.to_string())
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

fn existing_profile_path(profiles: &ManagedProfiles, id: &str) -> Result<PathBuf, String> {
    let file_name = profiles
        .repository()
        .profile_entry_name(id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("profile does not exist: {id}"))?;
    let store = settings_store()?;
    owned_profile_path(&store.paths().profiles_dir, &file_name)
}

/// Accepts only a bounded `https` subscription URL with a routable host.
///
/// Plain HTTP is refused: a configuration fetched over an unauthenticated
/// transport can be replaced in flight. Loopback and private literals are
/// refused so a subscription cannot be aimed at this app's own loopback
/// controller or at a host-local service.
fn validate_subscription_url(url: &str) -> Result<Url, String> {
    let trimmed = url.trim();
    if trimmed.len() > 2_048 {
        return Err("subscription URL is too long".into());
    }
    let parsed = Url::parse(trimmed).map_err(|_| "subscription URL is not a valid URL")?;
    if parsed.scheme() != "https" {
        return Err("subscription URL must use https".into());
    }
    if parsed.as_str() != trimmed
        || trimmed
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("subscription URL is not a plain absolute https URL".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("subscription URL must not carry embedded credentials".into());
    }
    let host = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or("subscription URL has no host")?;
    if host_is_public(host) {
        Ok(parsed)
    } else {
        Err("subscription URL host is not a public endpoint".into())
    }
}

/// True when the host is a routable domain or a public IP literal.
///
/// `Url::host_str` returns an IPv6 literal in brackets, so both forms are
/// examined. A name is accepted without resolving it; a literal is checked so a
/// subscription cannot be aimed at loopback or a host-local network.
fn host_is_public(host: &str) -> bool {
    let literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    match literal.parse::<std::net::IpAddr>() {
        Ok(address) => is_public_ip(address),
        Err(_) => {
            !host.eq_ignore_ascii_case("localhost")
                && !host.to_ascii_lowercase().ends_with(".localhost")
                && host.contains('.')
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
        }
    }
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

/// Public subscription endpoints are restricted to globally reachable unicast
/// addresses. This table follows the IANA IPv4 Special-Purpose Address Registry
/// and additionally excludes multicast, which is never a valid HTTPS origin for
/// this product. Keep it aligned with
/// <https://www.iana.org/assignments/iana-ipv4-special-registry/>.
fn is_public_ipv4(address: Ipv4Addr) -> bool {
    if matches!(address.octets(), [192, 0, 0, 9 | 10]) {
        return true;
    }
    const NON_PUBLIC: &[([u8; 4], u8)] = &[
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        IANA_IPV4_PROTOCOL_ASSIGNMENTS,
        ([192, 0, 2, 0], 24),
        // Deprecated 6to4 relay space has no generally reachable assignment;
        // the sole specific 192.88.99.2 registration is explicitly non-global.
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ];
    !NON_PUBLIC
        .iter()
        .any(|(network, prefix)| ipv4_has_prefix(address, *network, *prefix))
}

/// IPv4-mapped and well-known NAT64 addresses inherit the classification of
/// their embedded IPv4 address. Native IPv6 is admitted only from IANA's global
/// unicast 2000::/3 allocation and then has every non-global special-purpose
/// subrange removed. Everything else fails closed, including multicast, ULA,
/// link-local, site-local, discard-only and future-reserved ranges. Keep the
/// exceptions aligned with
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/>.
fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    if ipv6_has_prefix(
        address,
        WELL_KNOWN_NAT64_PREFIX.0,
        WELL_KNOWN_NAT64_PREFIX.1,
    ) {
        let octets = address.octets();
        return is_public_ipv4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    if !ipv6_has_prefix(
        address,
        IANA_IPV6_GLOBAL_UNICAST.0,
        IANA_IPV6_GLOBAL_UNICAST.1,
    ) {
        return false;
    }

    if ipv6_has_prefix(
        address,
        IANA_IPV6_PROTOCOL_ASSIGNMENTS.0,
        IANA_IPV6_PROTOCOL_ASSIGNMENTS.1,
    ) {
        return is_globally_reachable_ietf_protocol_assignment(address);
    }

    const NON_PUBLIC_GLOBAL_UNICAST: &[([u8; 16], u8)] = &[
        // Documentation ranges.
        (
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        ),
        ([0x3f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 20),
        // 6to4 has no unconditional globally-reachable guarantee.
        ([0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 16),
    ];
    !NON_PUBLIC_GLOBAL_UNICAST
        .iter()
        .any(|(network, prefix)| ipv6_has_prefix(address, *network, *prefix))
}

fn is_globally_reachable_ietf_protocol_assignment(address: Ipv6Addr) -> bool {
    let value = u128::from_be_bytes(address.octets());
    const PCP_ANYCAST: u128 = 0x2001_0001_0000_0000_0000_0000_0000_0001;
    const TURN_ANYCAST: u128 = 0x2001_0001_0000_0000_0000_0000_0000_0002;
    const DNS_SD_ANYCAST: u128 = 0x2001_0001_0000_0000_0000_0000_0000_0003;
    if matches!(value, PCP_ANYCAST | TURN_ANYCAST | DNS_SD_ANYCAST) {
        return true;
    }
    const GLOBAL_EXCEPTIONS: &[([u8; 16], u8)] = &[
        (
            [0x20, 0x01, 0, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        ),
        (
            [
                0x20, 0x01, 0, 0x04, 0x01, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            48,
        ),
        (
            [0x20, 0x01, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            28,
        ),
        (
            [0x20, 0x01, 0, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            28,
        ),
    ];
    GLOBAL_EXCEPTIONS
        .iter()
        .any(|(network, prefix)| ipv6_has_prefix(address, *network, *prefix))
}

fn ipv4_has_prefix(address: Ipv4Addr, network: [u8; 4], prefix: u8) -> bool {
    debug_assert!(prefix <= 32);
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    u32::from_be_bytes(address.octets()) & mask == u32::from_be_bytes(network) & mask
}

fn ipv6_has_prefix(address: Ipv6Addr, network: [u8; 16], prefix: u8) -> bool {
    debug_assert!(prefix <= 128);
    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
    u128::from_be_bytes(address.octets()) & mask == u128::from_be_bytes(network) & mask
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscriptionResolutionError {
    EmptyAnswer,
    TooManyAnswers,
    NonPublicAnswer,
}

impl fmt::Display for SubscriptionResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAnswer => formatter.write_str("subscription DNS answer was empty"),
            Self::TooManyAnswers => formatter.write_str("subscription DNS answer was too large"),
            Self::NonPublicAnswer => {
                formatter.write_str("subscription DNS answer was not globally reachable")
            }
        }
    }
}

impl StdError for SubscriptionResolutionError {}

fn validate_resolved_addresses(
    addresses: &[SocketAddr],
) -> Result<(), SubscriptionResolutionError> {
    if addresses.is_empty() {
        return Err(SubscriptionResolutionError::EmptyAnswer);
    }
    if addresses.len() > MAX_SUBSCRIPTION_DNS_ADDRESSES {
        return Err(SubscriptionResolutionError::TooManyAnswers);
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(SubscriptionResolutionError::NonPublicAnswer);
    }
    Ok(())
}

#[derive(Debug, Default)]
struct SystemSubscriptionDnsResolver;

impl Resolve for SystemSubscriptionDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|error| Box::new(error) as Box<dyn StdError + Send + Sync>)?
                .take(MAX_SUBSCRIPTION_DNS_ADDRESSES + 1)
                .collect::<Vec<_>>();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[derive(Debug)]
struct PublicSubscriptionDnsResolver<R> {
    inner: R,
}

impl<R> PublicSubscriptionDnsResolver<R> {
    fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R> Resolve for PublicSubscriptionDnsResolver<R>
where
    R: Resolve,
{
    fn resolve(&self, name: Name) -> Resolving {
        let resolving = self.inner.resolve(name);
        Box::pin(async move {
            let addresses = resolving
                .await?
                .take(MAX_SUBSCRIPTION_DNS_ADDRESSES + 1)
                .collect::<Vec<_>>();
            validate_resolved_addresses(&addresses)
                .map_err(|error| Box::new(error) as Box<dyn StdError + Send + Sync>)?;
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

async fn fetch_subscription(url: &Url) -> Result<String, String> {
    let client = subscription_client()?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|error| sanitized_fetch_error("request", &error))?;
    if !response.status().is_success() {
        return Err(format!(
            "subscription download failed with HTTP {}",
            response.status().as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROFILE_BYTES as u64)
    {
        return Err(format!(
            "subscription document exceeds the {MAX_PROFILE_BYTES}-byte limit"
        ));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| sanitized_fetch_error("response body", &error))?;
        if body.len() + chunk.len() > MAX_PROFILE_BYTES {
            return Err(format!(
                "subscription document exceeds the {MAX_PROFILE_BYTES}-byte limit"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        return Err("subscription document is empty".into());
    }
    String::from_utf8(body).map_err(|_| "subscription document is not UTF-8".to_owned())
}

fn subscription_client() -> Result<Client, String> {
    ensure_tls_crypto_provider()?;
    Client::builder()
        .user_agent(SUBSCRIPTION_USER_AGENT)
        .referer(FORWARD_SUBSCRIPTION_REFERER)
        .connect_timeout(SUBSCRIPTION_CONNECT_TIMEOUT)
        .timeout(SUBSCRIPTION_REQUEST_TIMEOUT)
        // A proxy can resolve the target itself and bypass the connector's
        // public-address resolver. Subscription fetching therefore uses a
        // direct connection unless a future explicit trusted-proxy policy is
        // designed and verified end to end.
        .no_proxy()
        .dns_resolver(PublicSubscriptionDnsResolver::new(
            SystemSubscriptionDnsResolver,
        ))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= MAX_SUBSCRIPTION_REDIRECTS {
                return attempt.error("too many subscription redirects");
            }
            match validate_subscription_url(attempt.url().as_str()) {
                Ok(_) => attempt.follow(),
                Err(error) => attempt.error(error),
            }
        }))
        .build()
        .map_err(|error| sanitized_fetch_error("client build", &error))
}

/// reqwest is built without a bundled crypto provider, so a process-global one
/// must exist before any HTTPS client is constructed. Installation is idempotent
/// and shared with the updater and the controller client.
fn ensure_tls_crypto_provider() -> Result<(), String> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _already_installed = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err("the process TLS crypto provider is unavailable".into());
    }
    Ok(())
}

/// Transport failures are reported by category only. A subscription URL can
/// carry an access token, and reqwest errors quote the URL they failed on.
fn sanitized_fetch_error(stage: &str, error: &reqwest::Error) -> String {
    let category = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_redirect() {
        "redirect was rejected"
    } else if error.is_body() || error.is_decode() {
        "response was unreadable"
    } else if error.is_builder() {
        "client could not be built"
    } else {
        "request failed"
    };
    format!("subscription {stage} {category}")
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
    if metadata.len() > MAX_PROFILE_BYTES as u64 {
        return Err(format!(
            "profile file exceeds the {MAX_PROFILE_BYTES}-byte limit"
        ));
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PROFILE_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() > MAX_PROFILE_BYTES {
        return Err(format!(
            "profile file exceeds the {MAX_PROFILE_BYTES}-byte limit"
        ));
    }
    String::from_utf8(body).map_err(|_| "profile document is not UTF-8".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE_JSON: &str = r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#;

    #[derive(Debug)]
    struct FixedDnsResolver {
        addresses: Vec<SocketAddr>,
    }

    impl Resolve for FixedDnsResolver {
        fn resolve(&self, _name: Name) -> Resolving {
            let addresses = self.addresses.clone();
            Box::pin(async move { Ok(Box::new(addresses.into_iter()) as Addrs) })
        }
    }

    #[test]
    fn subscription_urls_must_be_public_https_endpoints() {
        assert_eq!(
            validate_subscription_url(" https://example.com/sub?token=t ")
                .expect("public https URL")
                .as_str(),
            "https://example.com/sub?token=t"
        );
        for rejected in [
            "http://example.com/sub",
            "https://127.0.0.1:9090/configs",
            "https://localhost/sub",
            "https://[::1]/sub",
            "https://10.0.0.5/sub",
            "https://192.168.1.1/sub",
            "https://169.254.1.1/sub",
            "https://100.64.0.1/sub",
            "https://[fc00::1]/sub",
            "https://[::ffff:127.0.0.1]/sub",
            "file:///etc/passwd",
            "clash://install-config?url=x",
            "https://example.com/ sub",
            "example.com/sub",
        ] {
            assert!(
                validate_subscription_url(rejected).is_err(),
                "accepted unsafe subscription URL: {rejected}"
            );
        }
        assert!(
            validate_subscription_url(&format!("https://example.com/{}", "a".repeat(4096)))
                .is_err()
        );
    }

    #[test]
    fn subscription_redirects_never_forward_referer_credentials() {
        const { assert!(!FORWARD_SUBSCRIPTION_REFERER) };
    }

    #[test]
    fn subscription_client_keeps_the_closed_transport_policy_wired() {
        let source = include_str!("subscriptions.rs");
        let builder = source
            .split("Client::builder()")
            .nth(1)
            .expect("subscription client builder")
            .split(".build()")
            .next()
            .expect("bounded subscription client builder");
        for required in [
            ".referer(FORWARD_SUBSCRIPTION_REFERER)",
            ".no_proxy()",
            ".dns_resolver(PublicSubscriptionDnsResolver::new(",
            ".redirect(Policy::custom(",
        ] {
            assert!(
                builder.contains(required),
                "missing transport policy: {required}"
            );
        }
    }

    #[test]
    fn ipv4_special_purpose_ranges_are_classified_fail_closed() {
        for accepted in [
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(100, 128, 0, 1),
            Ipv4Addr::new(172, 32, 0, 1),
            Ipv4Addr::new(192, 0, 0, 9),
            Ipv4Addr::new(192, 0, 0, 10),
            Ipv4Addr::new(192, 0, 1, 1),
            Ipv4Addr::new(198, 20, 0, 1),
        ] {
            assert!(is_public_ipv4(accepted), "rejected public {accepted}");
        }
        for rejected in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 255, 255, 255),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(169, 254, 0, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 127, 255, 255),
            Ipv4Addr::new(192, 0, 0, 8),
            Ipv4Addr::new(192, 88, 99, 2),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 19, 255, 255),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(239, 255, 255, 255),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(203, 0, 113, 1),
        ] {
            assert!(!is_public_ipv4(rejected), "accepted {rejected}");
        }
    }

    #[test]
    fn ipv6_special_mapped_and_translation_ranges_are_classified_fail_closed() {
        for accepted in [
            "2606:4700::1111",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
            "2001:200::1",
            "::ffff:93.184.216.34",
            "64:ff9b::5db8:d822",
        ] {
            let address = accepted.parse().expect("public IPv6 address");
            assert!(is_public_ipv6(address), "rejected public {accepted}");
        }
        for rejected in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "4000::1",
        ] {
            let address = rejected.parse().expect("non-public IPv6 address");
            assert!(!is_public_ipv6(address), "accepted {rejected}");
        }
    }

    #[tokio::test]
    async fn resolver_rejects_empty_and_mixed_public_private_answers() {
        let oversized = std::iter::repeat_n(
            SocketAddr::from(([93, 184, 216, 34], 0)),
            MAX_SUBSCRIPTION_DNS_ADDRESSES + 1,
        )
        .collect();
        for addresses in [
            vec![],
            oversized,
            vec![
                SocketAddr::from(([93, 184, 216, 34], 0)),
                SocketAddr::from(([127, 0, 0, 1], 0)),
            ],
            vec![SocketAddr::from(([100, 64, 0, 1], 0))],
            vec!["[fc00::1]:0".parse().expect("ULA socket address")],
            vec![
                "[::ffff:127.0.0.1]:0"
                    .parse()
                    .expect("mapped loopback socket address"),
            ],
        ] {
            let resolver = PublicSubscriptionDnsResolver::new(FixedDnsResolver { addresses });
            let name = "subscription.example".parse::<Name>().expect("DNS name");
            assert!(resolver.resolve(name).await.is_err());
        }
    }

    #[tokio::test]
    async fn resolver_returns_the_exact_validated_public_answer_set() {
        let expected = vec![
            SocketAddr::from(([93, 184, 216, 34], 0)),
            "[2606:4700::1111]:0"
                .parse()
                .expect("public IPv6 socket address"),
        ];
        let resolver = PublicSubscriptionDnsResolver::new(FixedDnsResolver {
            addresses: expected.clone(),
        });
        let actual = resolver
            .resolve("subscription.example".parse::<Name>().expect("DNS name"))
            .await
            .expect("public answer")
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn imports_require_a_profile_that_projects_for_both_modes() {
        let settings = EngineSettings::default();
        let profile = validated_profile(PROFILE_JSON, &settings).expect("valid profile");
        assert_eq!(profile.credential_references().len(), 1);

        // The projection owns listeners, logging, DNS and the experimental
        // controller, so a document that tries to supply them is refused before
        // anything is stored.
        for rejected in [
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}"#,
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"inbounds":[{"type":"mixed","listen":"0.0.0.0","listen_port":7890}]}"#,
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"log":{"level":"debug"}}"#,
            "not json",
            "{}",
        ] {
            assert!(
                validated_profile(rejected, &settings).is_err(),
                "accepted unsupported document: {rejected}"
            );
        }
    }

    #[test]
    fn profile_text_payload_carries_no_projection_or_path() {
        let payload = serde_json::to_value(UiProfileText {
            id: "34db18b6-9903-4e9f-8854-15648e19e4f3".into(),
            name: "Work".into(),
            body: PROFILE_JSON.to_owned(),
            active: true,
            source_url: Some("https://example.com/sub?token=t".into()),
            bytes: PROFILE_JSON.len(),
            updated_epoch_secs: 42,
        })
        .expect("serialize profile text");
        let keys = payload
            .as_object()
            .expect("object payload")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            [
                "active",
                "body",
                "bytes",
                "id",
                "name",
                "source_url",
                "updated_epoch_secs",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>()
        );
        assert!(!payload.to_string().contains("generated_body"));
        assert!(!payload.to_string().contains("clash_api"));
    }

    #[tokio::test]
    async fn fetch_errors_never_echo_the_subscription_url() {
        let secret = "token-must-not-leak";
        let host = "malformed host";
        ensure_tls_crypto_provider().expect("test TLS provider");
        let error = Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .expect("test client")
            .get(format!("http://{host}/sub?token={secret}"))
            .send()
            .await
            .expect_err("malformed URL must be rejected");
        let rendered = sanitized_fetch_error("request", &error);
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains(host));
        assert!(rendered.starts_with("subscription request "));
    }

    #[test]
    fn local_imports_reject_directories_symlinks_and_relative_paths() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let file = temporary.path().join("profile.json");
        std::fs::write(&file, PROFILE_JSON).expect("write profile");
        assert_eq!(
            read_local_profile(&file).expect("read profile"),
            PROFILE_JSON
        );

        let link = temporary.path().join("link.json");
        std::os::unix::fs::symlink(&file, &link).expect("create symlink");
        assert!(read_local_profile(&link).is_err());
        assert!(read_local_profile(temporary.path()).is_err());
        assert!(read_local_profile(Path::new("relative.json")).is_err());
    }

    #[test]
    fn opened_profile_inode_is_stable_across_path_replacement() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let profile = temporary.path().join("profile.json");
        let retained = temporary.path().join("opened-profile.json");
        let replacement = temporary.path().join("replacement.json");
        std::fs::write(&profile, PROFILE_JSON).expect("write original profile");
        std::fs::write(&replacement, "replacement").expect("write replacement");

        let opened = open_local_profile(&profile).expect("open original profile once");
        std::fs::rename(&profile, &retained).expect("retain opened inode under another name");
        std::os::unix::fs::symlink(&replacement, &profile).expect("replace original path");

        assert_eq!(
            read_opened_local_profile(opened).expect("read the already-opened inode"),
            PROFILE_JSON
        );
        assert!(read_local_profile(&profile).is_err());
    }

    #[test]
    fn opened_profile_read_is_bounded_even_when_metadata_exceeds_the_limit() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let profile = temporary.path().join("oversized.json");
        std::fs::write(&profile, vec![b'x'; MAX_PROFILE_BYTES + 1])
            .expect("write oversized profile");
        assert!(read_local_profile(&profile).is_err());
    }

    #[test]
    fn subscription_mutation_guard_rolls_back_import_and_update_when_dropped() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let original = validated_profile(PROFILE_JSON, &EngineSettings::default())
            .expect("validated original profile");
        let replacement = ValidatedSingBoxProfile::parse(
            r#"{"route":{"final":"direct"},"outbounds":[{"tag":"direct","type":"direct"}]}"#,
        )
        .expect("validated replacement profile");

        let imported = repository
            .import_with_source(None, &original, Some("https://subscription.example/import"))
            .expect("import profile awaiting vault provision");
        {
            let _rollback = SubscriptionMutationRollback::delete(&repository, imported.id.clone());
        }
        assert!(
            repository
                .load(&imported.id)
                .expect("load rolled-back import")
                .is_none()
        );

        let stored = repository
            .import_with_source(
                None,
                &original,
                Some("https://subscription.example/original"),
            )
            .and_then(|record| {
                repository
                    .load(&record.id)
                    .map(|stored| stored.expect("stored original profile"))
            })
            .expect("import original update target");
        repository
            .replace(
                &stored.record.id,
                None,
                &replacement,
                Some("https://subscription.example/replacement"),
            )
            .expect("persist replacement awaiting vault provision");
        {
            let _rollback = SubscriptionMutationRollback::restore(
                &repository,
                stored.record.id.clone(),
                stored.clone(),
            );
        }
        assert_eq!(
            repository
                .load(&stored.record.id)
                .expect("load rolled-back update")
                .expect("restored original profile"),
            stored
        );
    }

    #[test]
    fn explicit_rollback_errors_are_position_and_key_redacted() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let imported = repository
            .import_with_source(
                None,
                &validated_profile(PROFILE_JSON, &EngineSettings::default())
                    .expect("validated profile"),
                Some("https://subscription.example/token-must-not-leak"),
            )
            .expect("import profile");
        let mut rollback = SubscriptionMutationRollback::delete(&repository, imported.id.clone());
        let rendered = rollback.rollback_import("vault rejected credential at index 1".to_owned());
        assert!(rendered.contains("index 1"));
        assert!(!rendered.contains("token-must-not-leak"));
    }

    #[test]
    fn legacy_clash_documents_are_reported_but_never_converted() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        assert_eq!(count_legacy_documents(temporary.path()), 0);
        std::fs::write(temporary.path().join("list.yml"), b"files: []").expect("write list");
        assert_eq!(count_legacy_documents(temporary.path()), 0);
        std::fs::write(temporary.path().join("1700000000.yml"), b"proxies: []")
            .expect("write legacy profile");
        std::fs::write(temporary.path().join("other.yaml"), b"proxies: []")
            .expect("write legacy profile");
        std::fs::write(temporary.path().join("notes.txt"), b"ignored").expect("write unrelated");
        assert_eq!(count_legacy_documents(temporary.path()), 2);
    }

    #[test]
    fn qrcode_rendering_encodes_only_a_subscription_url() {
        let code = QrCode::new(b"https://example.com/sub?token=t").expect("qr code");
        let rendered = code
            .render::<svg::Color<'_>>()
            .min_dimensions(190, 190)
            .dark_color(svg::Color("#2c3e50"))
            .light_color(svg::Color("#ffffff"))
            .build();
        assert!(rendered.starts_with("<?xml"));
        assert!(rendered.contains("svg"));
        assert!(
            !rendered.contains("token=t"),
            "the URL is encoded, not written"
        );
    }
}
