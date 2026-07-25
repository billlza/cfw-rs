//! Profile text, files, and subscriptions restored from 0.3.5.
//!
//! Every document that reaches the repository is a validated sing-box profile:
//! remote and local imports parse into [`ValidatedSingBoxProfile`] and are
//! projected for both modes before they are stored, exactly like the existing
//! text import. There is no Clash YAML conversion, no parser script, and no
//! mixin, because the projection owns listeners, logging, the experimental
//! controller, and DNS.
//!
//! A subscription URL is stored inside the profile envelope, so it is deleted
//! with the profile and cannot drift. Because it can carry an access token it is
//! never part of a profile list: only an explicit single-profile read returns
//! it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cfw_profiles::{ProfileImportResult, ProfileRepository, StoredProfile};
use cfw_singbox_config::{
    EngineSettings, MAX_PROFILE_BYTES, ProjectionMode, ValidatedSingBoxProfile,
};
use futures_util::StreamExt as _;
use qrcode::QrCode;
use qrcode::render::svg;
use reqwest::redirect::Policy;
use reqwest::{Client, Url};
use serde::Serialize;
use tauri::State;

use super::ManagedProfiles;
use super::shell_ops::{open_path, owned_profile_path};
use crate::engine::ManagedEngine;
use crate::settings_store;

const SUBSCRIPTION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SUBSCRIPTION_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const SUBSCRIPTION_USER_AGENT: &str = concat!("cfw-rs/", env!("CARGO_PKG_VERSION"), " (sing-box)");
const MAX_SUBSCRIPTION_REDIRECTS: usize = 5;
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
    let profile = validated_profile(&body, &settings)?;
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    let imported = profiles
        .repository()
        .import_with_source(name.as_deref(), &profile, Some(target.as_str()))
        .map_err(|error| error.to_string())?;
    activate_if_requested(profiles.repository(), &imported.id, activate)?;
    Ok(imported)
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
    let profile = validated_profile(&body, &settings)?;
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    profiles
        .repository()
        .replace(&id, None, &profile, Some(target.as_str()))
        .map_err(|error| error.to_string())
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
/// refuses to convert them.
///
/// Those documents are Clash YAML. This product imports only validated sing-box
/// profiles, and its migration path deliberately deletes legacy managed
/// profiles instead of interpreting them, so converting them here would
/// reintroduce exactly the input surface the migration removed. 0.3.5 also
/// returned an error when nothing could be imported, so the failure shape is
/// unchanged.
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
        "found {found} legacy Clash for Windows profile document(s) in {}; they are Clash YAML and this release imports only validated sing-box profiles, so nothing was converted or written. Re-import each subscription with Import from URL",
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
            .project(mode, settings)
            .map_err(|error| error.to_string())?;
    }
    Ok(profile)
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
        Ok(std::net::IpAddr::V4(address)) => is_public_ipv4(address),
        Ok(std::net::IpAddr::V6(address)) => is_public_ipv6(address),
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

fn is_public_ipv4(address: std::net::Ipv4Addr) -> bool {
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation())
}

fn is_public_ipv6(address: std::net::Ipv6Addr) -> bool {
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_unicast_link_local()
        || address.is_multicast())
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
        .connect_timeout(SUBSCRIPTION_CONNECT_TIMEOUT)
        .timeout(SUBSCRIPTION_REQUEST_TIMEOUT)
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
    if !path.is_absolute() {
        return Err("profile path must be absolute".into());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("profile path is not a regular file".into());
    }
    if metadata.len() > MAX_PROFILE_BYTES as u64 {
        return Err(format!(
            "profile file exceeds the {MAX_PROFILE_BYTES}-byte limit"
        ));
    }
    std::fs::read_to_string(path).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const PROFILE_JSON: &str = r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#;

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
    fn private_and_loopback_literals_are_classified_as_non_public() {
        assert!(is_public_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
        for rejected in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(169, 254, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(203, 0, 113, 1),
        ] {
            assert!(!is_public_ipv4(rejected), "accepted {rejected}");
        }
        assert!(is_public_ipv6("2606:4700::1111".parse().expect("address")));
        for rejected in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            "fe80::1".parse().expect("address"),
            "ff02::1".parse().expect("address"),
        ] {
            assert!(!is_public_ipv6(rejected), "accepted {rejected}");
        }
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
        ensure_tls_crypto_provider().expect("test TLS provider");
        let error = Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .expect("test client")
            .get(format!("http://127.0.0.1:0/sub?token={secret}"))
            .send()
            .await
            .expect_err("port zero must be rejected");
        let rendered = sanitized_fetch_error("request", &error);
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("127.0.0.1"));
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
