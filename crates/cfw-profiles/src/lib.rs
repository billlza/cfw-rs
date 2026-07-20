use std::fs;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use cfw_core::{MacOsAppPaths, PersistedSettings, RuntimeMode, SettingsStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("profile URL must use http or https: {0}")]
    UnsupportedUrl(String),
    #[error("profile HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("profile download failed with HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("profile I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("profile YAML is invalid: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("profile metadata JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("settings store failed: {0}")]
    Settings(#[from] cfw_core::SettingsStoreError),
    #[error("invalid profile URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("no active profile is selected")]
    NoActiveProfile,
    #[error("active profile is missing from the profiles directory: {0}")]
    ActiveProfileMissing(String),
    #[error("profile YAML root must be a mapping object")]
    InvalidConfigRoot,
    #[error("mixin YAML root must be a mapping object")]
    InvalidMixinRoot,
    #[error("invalid profile parser command at line {line}: {message}")]
    InvalidParserCommand { line: usize, message: String },
    #[error("invalid profile id: {0}")]
    InvalidProfileId(String),
    #[error("profile has no remote source URL metadata: {0}")]
    MissingRemoteSource(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileImportRequest {
    pub url: String,
    pub name: Option<String>,
    pub activate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileImportResult {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub bytes: usize,
    pub activated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRecord {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub rule_count: usize,
    pub updated_epoch_secs: Option<u64>,
    pub active: bool,
    pub source_url: Option<String>,
    pub subscription_userinfo: Option<String>,
    pub update_interval: Option<String>,
    /// From Clash `profile-web-page-url` response header (CFW "Open web page").
    pub home_web: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileText {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub body: String,
    pub generated_body: String,
    pub active: bool,
    pub source_url: Option<String>,
    pub subscription_userinfo: Option<String>,
    pub update_interval: Option<String>,
    pub home_web: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSaveResult {
    pub id: String,
    pub path: PathBuf,
    pub bytes: usize,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileApplyResult {
    pub id: String,
    pub source_path: PathBuf,
    pub config_path: PathBuf,
    pub bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ProfileManager {
    paths: MacOsAppPaths,
    http: reqwest::Client,
}

/// User-Agent sent when fetching remote subscriptions. Many subscription
/// providers gate the Clash node list behind a `clash`/`meta` UA substring and
/// return an HTML landing page (which fails YAML validation) to unknown agents,
/// so we must present a Clash-compatible UA on every profile fetch.
pub const PROFILE_FETCH_USER_AGENT: &str = "clash.meta/v1.19.27 (cfw-rs)";

impl ProfileManager {
    pub fn new(paths: MacOsAppPaths) -> Result<Self, ProfileError> {
        let http = reqwest::Client::builder()
            .user_agent(PROFILE_FETCH_USER_AGENT)
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(18))
            .build()?;
        Ok(Self { paths, http })
    }

    pub async fn import_remote(
        &self,
        store: &SettingsStore,
        request: ProfileImportRequest,
    ) -> Result<ProfileImportResult, ProfileError> {
        let parsed = Url::parse(&request.url)?;
        match parsed.scheme() {
            "http" | "https" => {}
            scheme => return Err(ProfileError::UnsupportedUrl(scheme.into())),
        }

        let response = self.http.get(parsed.clone()).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ProfileError::Status {
                status: status.as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }

        let headers = response.headers().clone();
        let subscription_userinfo = header_to_string(&headers, "subscription-userinfo");
        let update_interval = header_to_string(&headers, "profile-update-interval");
        let home_web = header_to_string(&headers, "profile-web-page-url");
        let body = response.text().await?;
        validate_profile_yaml(&body)?;

        fs::create_dir_all(&self.paths.profiles_dir)?;
        // CFW uses Content-Disposition filename when present (e.g. iKuuu_V2.yaml),
        // not the opaque /link/<token> path segment.
        let name = request
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(ToString::to_string)
            .or_else(|| profile_name_from_content_disposition(&headers))
            .unwrap_or_else(|| profile_name_from_url(&parsed));

        // Same subscription URL → update the existing card in place (stable id).
        let existing = self.find_by_source_url(parsed.as_str())?;
        let id = existing
            .as_ref()
            .map(|profile| profile.id.clone())
            .unwrap_or_else(|| profile_id(&name, parsed.as_str()));
        let path = existing
            .as_ref()
            .map(|profile| profile.path.clone())
            .unwrap_or_else(|| self.paths.profiles_dir.join(format!("{id}.yaml")));
        let tmp_path = path.with_extension("yaml.tmp");
        fs::write(&tmp_path, body.as_bytes())?;
        fs::rename(&tmp_path, &path)?;
        write_profile_metadata(
            &metadata_path_for_profile(&path),
            &ProfileMetadata {
                id: id.clone(),
                name: name.clone(),
                source_url: Some(parsed.to_string()),
                subscription_userinfo,
                update_interval,
                home_web,
            },
        )?;

        if request.activate {
            let mut settings = store.read_or_default()?;
            settings.active_profile = Some(id.clone());
            store.write(&settings)?;
        }

        Ok(ProfileImportResult {
            id,
            name,
            path,
            bytes: body.len(),
            activated: request.activate,
        })
    }

    pub fn list(&self, store: &SettingsStore) -> Result<Vec<ProfileRecord>, ProfileError> {
        let active_profile = store.read_or_default()?.active_profile;
        if !self.paths.profiles_dir.exists() {
            return Ok(Vec::new());
        }

        let mut profiles = fs::read_dir(&self.paths.profiles_dir)?
            .filter_map(Result::ok)
            .filter_map(|entry| profile_record_from_entry(entry, active_profile.as_deref()))
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| {
            right
                .active
                .cmp(&left.active)
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(profiles)
    }

    fn find_by_source_url(&self, source_url: &str) -> Result<Option<ProfileRecord>, ProfileError> {
        if !self.paths.profiles_dir.exists() {
            return Ok(None);
        }
        let target = source_url.trim();
        if target.is_empty() {
            return Ok(None);
        }
        Ok(fs::read_dir(&self.paths.profiles_dir)?
            .filter_map(Result::ok)
            .filter_map(|entry| profile_record_from_entry(entry, None))
            .find(|profile| {
                profile
                    .source_url
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|url| url == target)
            }))
    }

    pub fn import_file(
        &self,
        store: &SettingsStore,
        source_path: PathBuf,
        name: Option<String>,
        activate: bool,
    ) -> Result<ProfileImportResult, ProfileError> {
        let source_path = fs::canonicalize(source_path)?;
        let body = fs::read_to_string(&source_path)?;
        validate_profile_yaml(&body)?;
        fs::create_dir_all(&self.paths.profiles_dir)?;

        let name = name
            .filter(|name| !name.trim().is_empty())
            .or_else(|| {
                source_path
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| "local-profile".into());
        let id = profile_id(&name, source_path.to_string_lossy().as_ref());
        let path = self.paths.profiles_dir.join(format!("{id}.yaml"));
        let tmp_path = path.with_extension("yaml.tmp");
        fs::write(&tmp_path, body.as_bytes())?;
        fs::rename(&tmp_path, &path)?;
        write_profile_metadata(
            &metadata_path_for_profile(&path),
            &ProfileMetadata {
                id: id.clone(),
                name: name.clone(),
                source_url: None,
                ..ProfileMetadata::default()
            },
        )?;

        if activate {
            let mut settings = store.read_or_default()?;
            settings.active_profile = Some(id.clone());
            store.write(&settings)?;
        }

        Ok(ProfileImportResult {
            id,
            name,
            path,
            bytes: body.len(),
            activated: activate,
        })
    }

    pub fn import_text(
        &self,
        store: &SettingsStore,
        name: Option<String>,
        body: String,
        activate: bool,
    ) -> Result<ProfileImportResult, ProfileError> {
        self.import_text_with_source_url(store, name, body, None, activate)
    }

    pub fn import_text_with_source_url(
        &self,
        store: &SettingsStore,
        name: Option<String>,
        body: String,
        source_url: Option<String>,
        activate: bool,
    ) -> Result<ProfileImportResult, ProfileError> {
        validate_profile_yaml(&body)?;
        fs::create_dir_all(&self.paths.profiles_dir)?;
        let source_url = normalize_source_url(source_url)?;

        let name = name
            .filter(|name| !name.trim().is_empty())
            .map(|name| trim_profile_extension(&name).to_string())
            .unwrap_or_else(|| "local-profile".into());
        let identity = source_url
            .clone()
            .unwrap_or_else(|| format!("local:{}:{}", name, content_hash(&body)));
        let id = profile_id(&name, &identity);
        let path = self.paths.profiles_dir.join(format!("{id}.yaml"));
        let tmp_path = path.with_extension("yaml.tmp");
        fs::write(&tmp_path, body.as_bytes())?;
        fs::rename(&tmp_path, &path)?;
        write_profile_metadata(
            &metadata_path_for_profile(&path),
            &ProfileMetadata {
                id: id.clone(),
                name: name.clone(),
                source_url,
                ..ProfileMetadata::default()
            },
        )?;

        if activate {
            let mut settings = store.read_or_default()?;
            settings.active_profile = Some(id.clone());
            store.write(&settings)?;
        }

        Ok(ProfileImportResult {
            id,
            name,
            path,
            bytes: body.len(),
            activated: activate,
        })
    }

    pub async fn update_remote(
        &self,
        store: &SettingsStore,
        id: &str,
    ) -> Result<ProfileImportResult, ProfileError> {
        validate_profile_id(id)?;
        let path = self
            .profile_path(id)?
            .ok_or_else(|| ProfileError::ActiveProfileMissing(id.into()))?;
        let metadata = read_profile_metadata(&metadata_path_for_profile(&path))?;
        let source_url = metadata
            .source_url
            .clone()
            .ok_or_else(|| ProfileError::MissingRemoteSource(id.into()))?;
        let result = self
            .import_remote(
                store,
                ProfileImportRequest {
                    url: source_url,
                    // Let Content-Disposition refresh the display name on update.
                    name: None,
                    activate: store.read_or_default()?.active_profile.as_deref() == Some(id),
                },
            )
            .await?;
        Ok(result)
    }

    pub fn read_text(&self, store: &SettingsStore, id: &str) -> Result<ProfileText, ProfileError> {
        validate_profile_id(id)?;
        let path = self
            .profile_path(id)?
            .ok_or_else(|| ProfileError::ActiveProfileMissing(id.into()))?;
        let body = fs::read_to_string(&path)?;
        validate_profile_yaml(&body)?;
        let settings = store.read_or_default()?;
        let metadata = read_profile_metadata(&metadata_path_for_profile(&path)).ok();
        let name = metadata
            .as_ref()
            .map(|metadata| metadata.name.clone())
            .unwrap_or_else(|| id.to_string());
        let generated_body = render_profile_with_settings(&body, &settings)?;

        Ok(ProfileText {
            id: id.to_string(),
            name,
            path,
            body,
            generated_body,
            active: settings.active_profile.as_deref() == Some(id),
            source_url: metadata
                .as_ref()
                .and_then(|metadata| metadata.source_url.clone()),
            subscription_userinfo: metadata
                .as_ref()
                .and_then(|metadata| metadata.subscription_userinfo.clone()),
            update_interval: metadata
                .as_ref()
                .and_then(|metadata| metadata.update_interval.clone()),
            home_web: metadata.and_then(|metadata| metadata.home_web),
        })
    }

    /// CFW "Settings" / Edit profile information — update display name and optional source URL.
    pub fn update_info(
        &self,
        id: &str,
        name: String,
        source_url: Option<String>,
    ) -> Result<(), ProfileError> {
        validate_profile_id(id)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(ProfileError::InvalidProfileId("profile name is empty".into()));
        }
        let path = self
            .profile_path(id)?
            .ok_or_else(|| ProfileError::ActiveProfileMissing(id.into()))?;
        let meta_path = metadata_path_for_profile(&path);
        let mut metadata = read_profile_metadata(&meta_path).unwrap_or(ProfileMetadata {
            id: id.to_string(),
            name: name.to_string(),
            ..ProfileMetadata::default()
        });
        metadata.id = id.to_string();
        metadata.name = name.to_string();
        if let Some(url) = source_url {
            let url = url.trim();
            if url.is_empty() {
                metadata.source_url = None;
            } else {
                let parsed = Url::parse(url)?;
                match parsed.scheme() {
                    "http" | "https" => metadata.source_url = Some(parsed.to_string()),
                    scheme => return Err(ProfileError::UnsupportedUrl(scheme.into())),
                }
            }
        }
        write_profile_metadata(&meta_path, &metadata)?;
        Ok(())
    }

    pub fn save_text(
        &self,
        store: &SettingsStore,
        id: &str,
        body: String,
    ) -> Result<ProfileSaveResult, ProfileError> {
        validate_profile_id(id)?;
        validate_profile_yaml(&body)?;
        let path = self
            .profile_path(id)?
            .ok_or_else(|| ProfileError::ActiveProfileMissing(id.into()))?;
        let tmp_path = path.with_extension("yaml.tmp");
        fs::write(&tmp_path, body.as_bytes())?;
        fs::rename(&tmp_path, &path)?;
        let active = store.read_or_default()?.active_profile.as_deref() == Some(id);

        Ok(ProfileSaveResult {
            id: id.to_string(),
            path,
            bytes: body.len(),
            active,
        })
    }

    pub fn apply_active(&self, store: &SettingsStore) -> Result<ProfileApplyResult, ProfileError> {
        store.ensure_layout()?;
        let settings = store.read_or_default()?;
        let id = settings
            .active_profile
            .clone()
            .filter(|id| !id.trim().is_empty())
            .ok_or(ProfileError::NoActiveProfile)?;
        let source_path = self
            .active_profile_path(&id)
            .ok_or_else(|| ProfileError::ActiveProfileMissing(id.clone()))?;

        let raw = fs::read_to_string(&source_path)?;
        let rendered = render_profile_with_settings(&raw, &settings)?;

        if let Some(parent) = self.paths.config_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = self.paths.config_file.with_extension("yaml.tmp");
        fs::write(&tmp_path, rendered.as_bytes())?;
        fs::rename(&tmp_path, &self.paths.config_file)?;

        Ok(ProfileApplyResult {
            id,
            source_path,
            config_path: self.paths.config_file.clone(),
            bytes: rendered.len(),
        })
    }

    pub fn delete(&self, store: &SettingsStore, id: &str) -> Result<bool, ProfileError> {
        validate_profile_id(id)?;
        let Some(path) = self.profile_path(id)? else {
            return Ok(false);
        };
        fs::remove_file(path)?;
        let metadata_path = self.paths.profiles_dir.join(format!("{id}.json"));
        if metadata_path.exists() {
            fs::remove_file(metadata_path)?;
        }

        let mut settings = store.read_or_default()?;
        if settings.active_profile.as_deref() == Some(id) {
            settings.active_profile = None;
            store.write(&settings)?;
            if self.paths.config_file.exists() {
                fs::remove_file(&self.paths.config_file)?;
            }
        }

        Ok(true)
    }

    pub fn profile_path(&self, id: &str) -> Result<Option<PathBuf>, ProfileError> {
        validate_profile_id(id)?;
        Ok(self.active_profile_path(id))
    }

    fn active_profile_path(&self, id: &str) -> Option<PathBuf> {
        ["yaml", "yml"]
            .into_iter()
            .map(|extension| self.paths.profiles_dir.join(format!("{id}.{extension}")))
            .find(|path| path.exists())
    }
}

fn validate_profile_id(id: &str) -> Result<(), ProfileError> {
    if id.trim().is_empty()
        || id.contains('/')
        || id.contains('\\')
        || id == "."
        || id == ".."
        || id.contains("..")
    {
        return Err(ProfileError::InvalidProfileId(id.into()));
    }
    Ok(())
}

fn validate_profile_yaml(body: &str) -> Result<(), ProfileError> {
    let value = serde_yaml::from_str::<serde_yaml::Value>(body)?;
    if value.is_mapping() {
        Ok(())
    } else {
        Err(ProfileError::InvalidConfigRoot)
    }
}

fn normalize_source_url(source_url: Option<String>) -> Result<Option<String>, ProfileError> {
    let Some(source_url) = source_url.map(|value| value.trim().to_string()) else {
        return Ok(None);
    };
    if source_url.is_empty() {
        return Ok(None);
    }

    let parsed = Url::parse(&source_url)?;
    match parsed.scheme() {
        "http" | "https" => Ok(Some(parsed.to_string())),
        scheme => Err(ProfileError::UnsupportedUrl(scheme.into())),
    }
}

fn header_to_string(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn profile_name_from_content_disposition(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let raw = header_to_string(headers, "content-disposition")?;
    // Prefer RFC 5987 filename*=UTF-8''... then plain filename=
    if let Some(encoded) = raw
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("filename*="))
    {
        let value = encoded.trim().trim_matches('"');
        if let Some((_charset, rest)) = value.split_once("''") {
            let decoded = percent_decode_str(rest);
            let trimmed = trim_profile_extension(decoded.trim());
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    let filename = raw
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("filename="))
        .map(|value| value.trim().trim_matches('"').trim().to_string())
        .filter(|value| !value.is_empty())?;
    let trimmed = trim_profile_extension(&filename);
    if trimmed.is_empty() {
        None
    } else {
        // Keep the .yaml suffix in the display name when CFW-style filenames include it.
        Some(if filename.to_ascii_lowercase().ends_with(".yaml")
            || filename.to_ascii_lowercase().ends_with(".yml")
        {
            filename
        } else {
            trimmed.to_string()
        })
    }
}

fn percent_decode_str(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[index + 1] as char).to_digit(16),
                (bytes[index + 2] as char).to_digit(16),
            ) {
                out.push(((hi << 4) | lo) as u8);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn inject_runtime_settings(
    config: &mut serde_yaml::Value,
    settings: &PersistedSettings,
) -> Result<(), ProfileError> {
    let mapping = config
        .as_mapping_mut()
        .ok_or(ProfileError::InvalidConfigRoot)?;
    set_yaml_value(mapping, "mixed-port", settings.mixed_port)?;
    mapping.remove(yaml_key("port"));
    mapping.remove(yaml_key("socks-port"));
    set_yaml_value(mapping, "allow-lan", settings.allow_lan)?;
    set_yaml_value(mapping, "ipv6", settings.enable_ipv6)?;
    set_yaml_value(mapping, "mode", runtime_mode_name(settings.runtime_mode))?;
    set_yaml_value(
        mapping,
        "external-controller",
        format!(
            "{}:{}",
            settings.external_controller_host, settings.external_controller_port
        ),
    )?;

    if let Some(secret) = settings
        .secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
    {
        set_yaml_value(mapping, "secret", secret)?;
    } else {
        mapping.remove(yaml_key("secret"));
    }

    if let Some(log_level) = setting_string(settings, &["log-level", "logLevel"]) {
        set_yaml_value(mapping, "log-level", log_level)?;
    }
    if let Some(interface_name) = setting_string(settings, &["interface-name", "interfaceName"]) {
        set_yaml_value(mapping, "interface-name", interface_name)?;
    } else {
        mapping.remove(yaml_key("interface-name"));
    }
    if settings.tun_mode {
        mapping.insert(
            serde_yaml::Value::String("tun".into()),
            mihomo_tun_config()?,
        );
    } else {
        mapping.remove(yaml_key("tun"));
    }

    // Persist selector group choices across core reloads (CFW / mihomo profile.store-selected).
    // Only set the default when the profile did not already declare `profile:`.
    if !mapping.contains_key(&yaml_key("profile")) {
        let mut profile = serde_yaml::Mapping::new();
        set_yaml_value(&mut profile, "store-selected", true)?;
        mapping.insert(
            serde_yaml::Value::String("profile".into()),
            serde_yaml::Value::Mapping(profile),
        );
    }

    Ok(())
}

fn render_profile_with_settings(
    body: &str,
    settings: &PersistedSettings,
) -> Result<String, ProfileError> {
    let mut config = serde_yaml::from_str::<serde_yaml::Value>(body)?;
    apply_profile_parser_script(&mut config, settings)?;
    apply_mixin_if_enabled(&mut config, settings)?;
    inject_runtime_settings(&mut config, settings)?;
    Ok(serde_yaml::to_string(&config)?)
}

fn mihomo_tun_config() -> Result<serde_yaml::Value, ProfileError> {
    let mut tun = serde_yaml::Mapping::new();
    set_yaml_value(&mut tun, "enable", true)?;
    set_yaml_value(&mut tun, "stack", "system")?;
    set_yaml_value(&mut tun, "auto-route", true)?;
    set_yaml_value(&mut tun, "auto-detect-interface", true)?;
    set_yaml_value(&mut tun, "strict-route", false)?;
    set_yaml_value(&mut tun, "dns-hijack", vec!["any:53"])?;
    Ok(serde_yaml::Value::Mapping(tun))
}

fn apply_profile_parser_script(
    config: &mut serde_yaml::Value,
    settings: &PersistedSettings,
) -> Result<(), ProfileError> {
    let Some(script) = setting_string(
        settings,
        &[
            "profile-parser-script",
            "profileParserScript",
            "profile_parser_script",
        ],
    ) else {
        return Ok(());
    };

    for (index, raw_line) in script.lines().enumerate() {
        let line = index + 1;
        let command_line = raw_line.trim();
        if command_line.is_empty() || command_line.starts_with('#') {
            continue;
        }

        let (command, payload) = split_parser_command(command_line, line)?;
        match command {
            "prepend-rule" => prepend_sequence_value(
                config,
                "rules",
                serde_yaml::Value::String(payload.to_string()),
                line,
            )?,
            "append-rule" => append_sequence_value(
                config,
                "rules",
                serde_yaml::Value::String(payload.to_string()),
                line,
            )?,
            "prepend" => {
                let (path, value) = split_parser_path_value(payload, line)?;
                prepend_sequence_value(config, path, parse_parser_value(value, line)?, line)?;
            }
            "append" => {
                let (path, value) = split_parser_path_value(payload, line)?;
                append_sequence_value(config, path, parse_parser_value(value, line)?, line)?;
            }
            "set" => {
                let (path, value) = split_parser_path_value(payload, line)?;
                set_yaml_path(config, path, parse_parser_value(value, line)?, line)?;
            }
            "delete" => delete_yaml_path(config, payload, line)?,
            "merge" => {
                let mut patch = parse_parser_value(payload, line)?;
                if !patch.is_mapping() {
                    return Err(ProfileError::InvalidParserCommand {
                        line,
                        message: "merge expects an inline YAML mapping".into(),
                    });
                }
                merge_yaml(config, &mut patch)?;
            }
            other => {
                return Err(ProfileError::InvalidParserCommand {
                    line,
                    message: format!("unsupported command '{other}'"),
                });
            }
        }
    }

    Ok(())
}

fn split_parser_command(line: &str, line_number: usize) -> Result<(&str, &str), ProfileError> {
    let Some((command, payload)) = split_first_whitespace(line) else {
        return Err(ProfileError::InvalidParserCommand {
            line: line_number,
            message: "expected '<command> <payload>'".into(),
        });
    };
    let payload = payload.trim();
    if payload.is_empty() {
        return Err(ProfileError::InvalidParserCommand {
            line: line_number,
            message: "payload must not be empty".into(),
        });
    }
    Ok((command.trim(), payload))
}

fn split_parser_path_value(payload: &str, line: usize) -> Result<(&str, &str), ProfileError> {
    let Some((path, value)) = split_first_whitespace(payload) else {
        return Err(ProfileError::InvalidParserCommand {
            line,
            message: "expected '<path> <yaml-value>'".into(),
        });
    };
    let path = path.trim();
    let value = value.trim();
    if path.is_empty() || value.is_empty() {
        return Err(ProfileError::InvalidParserCommand {
            line,
            message: "path and value must not be empty".into(),
        });
    }
    Ok((path, value))
}

fn split_first_whitespace(value: &str) -> Option<(&str, &str)> {
    let index = value
        .char_indices()
        .find_map(|(index, character)| character.is_whitespace().then_some(index))?;
    Some((&value[..index], &value[index..]))
}

fn parse_parser_value(value: &str, line: usize) -> Result<serde_yaml::Value, ProfileError> {
    serde_yaml::from_str::<serde_yaml::Value>(value).map_err(|error| {
        ProfileError::InvalidParserCommand {
            line,
            message: format!("invalid YAML value: {error}"),
        }
    })
}

fn yaml_path_keys(path: &str, line: usize) -> Result<Vec<&str>, ProfileError> {
    let keys = path
        .split('.')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .collect::<Vec<_>>();
    if keys.is_empty() {
        Err(ProfileError::InvalidParserCommand {
            line,
            message: "path must not be empty".into(),
        })
    } else {
        Ok(keys)
    }
}

fn set_yaml_path(
    config: &mut serde_yaml::Value,
    path: &str,
    value: serde_yaml::Value,
    line: usize,
) -> Result<(), ProfileError> {
    let keys = yaml_path_keys(path, line)?;
    set_yaml_path_keys(config, &keys, value, line)
}

fn set_yaml_path_keys(
    value: &mut serde_yaml::Value,
    keys: &[&str],
    new_value: serde_yaml::Value,
    line: usize,
) -> Result<(), ProfileError> {
    let mapping = value
        .as_mapping_mut()
        .ok_or(ProfileError::InvalidConfigRoot)?;
    let key = serde_yaml::Value::String(keys[0].into());
    if keys.len() == 1 {
        mapping.insert(key, new_value);
        return Ok(());
    }
    if !mapping.contains_key(&key) {
        mapping.insert(
            key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
    let child = mapping
        .get_mut(&key)
        .ok_or_else(|| ProfileError::InvalidParserCommand {
            line,
            message: format!("cannot create path '{}'", keys.join(".")),
        })?;
    if !child.is_mapping() {
        return Err(ProfileError::InvalidParserCommand {
            line,
            message: format!(
                "path '{}' crosses existing {} value at '{}'",
                keys.join("."),
                yaml_value_kind(child),
                keys[0]
            ),
        });
    }
    set_yaml_path_keys(child, &keys[1..], new_value, line)
}

fn delete_yaml_path(
    config: &mut serde_yaml::Value,
    path: &str,
    line: usize,
) -> Result<(), ProfileError> {
    let keys = yaml_path_keys(path, line)?;
    delete_yaml_path_keys(config, &keys)
}

fn delete_yaml_path_keys(value: &mut serde_yaml::Value, keys: &[&str]) -> Result<(), ProfileError> {
    let mapping = value
        .as_mapping_mut()
        .ok_or(ProfileError::InvalidConfigRoot)?;
    let key = serde_yaml::Value::String(keys[0].into());
    if keys.len() == 1 {
        mapping.remove(&key);
        return Ok(());
    }
    if let Some(child) = mapping.get_mut(&key) {
        delete_yaml_path_keys(child, &keys[1..])?;
    }
    Ok(())
}

fn append_sequence_value(
    config: &mut serde_yaml::Value,
    path: &str,
    value: serde_yaml::Value,
    line: usize,
) -> Result<(), ProfileError> {
    sequence_at_yaml_path(config, path, line)?.push(value);
    Ok(())
}

fn prepend_sequence_value(
    config: &mut serde_yaml::Value,
    path: &str,
    value: serde_yaml::Value,
    line: usize,
) -> Result<(), ProfileError> {
    sequence_at_yaml_path(config, path, line)?.insert(0, value);
    Ok(())
}

fn sequence_at_yaml_path<'a>(
    config: &'a mut serde_yaml::Value,
    path: &str,
    line: usize,
) -> Result<&'a mut Vec<serde_yaml::Value>, ProfileError> {
    let keys = yaml_path_keys(path, line)?;
    sequence_at_yaml_path_keys(config, &keys, line)
}

fn sequence_at_yaml_path_keys<'a>(
    value: &'a mut serde_yaml::Value,
    keys: &[&str],
    line: usize,
) -> Result<&'a mut Vec<serde_yaml::Value>, ProfileError> {
    let mapping = value
        .as_mapping_mut()
        .ok_or(ProfileError::InvalidConfigRoot)?;
    let key = serde_yaml::Value::String(keys[0].into());
    if !mapping.contains_key(&key) {
        let default_value = if keys.len() == 1 {
            serde_yaml::Value::Sequence(Vec::new())
        } else {
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
        };
        mapping.insert(key.clone(), default_value);
    }
    let child = mapping
        .get_mut(&key)
        .ok_or_else(|| ProfileError::InvalidParserCommand {
            line,
            message: format!("cannot create path '{}'", keys.join(".")),
        })?;
    if keys.len() == 1 {
        if !child.is_sequence() {
            return Err(ProfileError::InvalidParserCommand {
                line,
                message: format!(
                    "path '{}' expected sequence but found {}",
                    keys.join("."),
                    yaml_value_kind(child)
                ),
            });
        }
        return child
            .as_sequence_mut()
            .ok_or(ProfileError::InvalidConfigRoot);
    }
    if !child.is_mapping() {
        return Err(ProfileError::InvalidParserCommand {
            line,
            message: format!(
                "path '{}' crosses existing {} value at '{}'",
                keys.join("."),
                yaml_value_kind(child),
                keys[0]
            ),
        });
    }
    sequence_at_yaml_path_keys(child, &keys[1..], line)
}

fn yaml_value_kind(value: &serde_yaml::Value) -> &'static str {
    match value {
        serde_yaml::Value::Null => "null",
        serde_yaml::Value::Bool(_) => "boolean",
        serde_yaml::Value::Number(_) => "number",
        serde_yaml::Value::String(_) => "string",
        serde_yaml::Value::Sequence(_) => "sequence",
        serde_yaml::Value::Mapping(_) => "mapping",
        serde_yaml::Value::Tagged(_) => "tagged",
    }
}

fn apply_mixin_if_enabled(
    config: &mut serde_yaml::Value,
    settings: &PersistedSettings,
) -> Result<(), ProfileError> {
    if !settings.mixin || settings.mixin_yaml.trim().is_empty() {
        return Ok(());
    }

    let mut mixin = serde_yaml::from_str::<serde_yaml::Value>(&settings.mixin_yaml)?;
    if !mixin.is_mapping() {
        return Err(ProfileError::InvalidMixinRoot);
    }
    merge_yaml(config, &mut mixin)?;
    Ok(())
}

fn merge_yaml(
    target: &mut serde_yaml::Value,
    source: &mut serde_yaml::Value,
) -> Result<(), ProfileError> {
    let target_mapping = target
        .as_mapping_mut()
        .ok_or(ProfileError::InvalidConfigRoot)?;
    let source_mapping = source
        .as_mapping_mut()
        .ok_or(ProfileError::InvalidMixinRoot)?;

    for (key, value) in std::mem::take(source_mapping) {
        if value.is_null() {
            target_mapping.remove(&key);
            continue;
        }

        match target_mapping.get_mut(&key) {
            Some(existing) if existing.is_mapping() && value.is_mapping() => {
                let mut nested = value;
                merge_yaml(existing, &mut nested)?;
            }
            _ => {
                target_mapping.insert(key, value);
            }
        }
    }
    Ok(())
}

fn set_yaml_value<T: Serialize>(
    mapping: &mut serde_yaml::Mapping,
    key: &str,
    value: T,
) -> Result<(), ProfileError> {
    mapping.insert(yaml_key(key), serde_yaml::to_value(value)?);
    Ok(())
}

fn yaml_key(key: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(key.into())
}

fn setting_string(settings: &PersistedSettings, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match settings.extra.get(*key) {
        Some(serde_yaml::Value::String(value)) if !value.trim().is_empty() => Some(value.clone()),
        _ => None,
    })
}

fn runtime_mode_name(mode: RuntimeMode) -> &'static str {
    match mode {
        RuntimeMode::Global => "global",
        RuntimeMode::Rule => "rule",
        RuntimeMode::Direct => "direct",
        RuntimeMode::Script => "script",
    }
}

fn profile_record_from_entry(
    entry: fs::DirEntry,
    active_profile: Option<&str>,
) -> Option<ProfileRecord> {
    let path = entry.path();
    let ext = path.extension()?.to_string_lossy().to_ascii_lowercase();
    if ext != "yaml" && ext != "yml" {
        return None;
    }

    let id = path.file_stem()?.to_string_lossy().to_string();
    let file_metadata = entry.metadata().ok()?;
    let updated_epoch_secs = file_metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs());
    let profile_metadata = read_profile_metadata(&metadata_path_for_profile(&path)).ok();
    let rule_count = count_profile_rules(&path).unwrap_or(0);
    let source_url = profile_metadata
        .as_ref()
        .and_then(|metadata| metadata.source_url.clone());
    let subscription_userinfo = profile_metadata
        .as_ref()
        .and_then(|metadata| metadata.subscription_userinfo.clone());
    let update_interval = profile_metadata
        .as_ref()
        .and_then(|metadata| metadata.update_interval.clone());
    let home_web = profile_metadata
        .as_ref()
        .and_then(|metadata| metadata.home_web.clone());
    Some(ProfileRecord {
        name: profile_metadata
            .as_ref()
            .map(|metadata| metadata.name.clone())
            .unwrap_or_else(|| id.clone()),
        active: active_profile == Some(id.as_str()),
        id,
        path,
        bytes: file_metadata.len(),
        rule_count,
        updated_epoch_secs,
        source_url,
        subscription_userinfo,
        update_interval,
        home_web,
    })
}

fn count_profile_rules(path: &std::path::Path) -> Result<usize, ProfileError> {
    let raw = fs::read_to_string(path)?;
    let config = serde_yaml::from_str::<serde_yaml::Value>(&raw)?;
    Ok(config
        .as_mapping()
        .and_then(|mapping| mapping.get(yaml_key("rules")))
        .and_then(serde_yaml::Value::as_sequence)
        .map_or(0, Vec::len))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
struct ProfileMetadata {
    id: String,
    name: String,
    source_url: Option<String>,
    subscription_userinfo: Option<String>,
    update_interval: Option<String>,
    home_web: Option<String>,
}

fn metadata_path_for_profile(path: &std::path::Path) -> PathBuf {
    path.with_extension("json")
}

fn read_profile_metadata(path: &std::path::Path) -> Result<ProfileMetadata, ProfileError> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn write_profile_metadata(
    path: &std::path::Path,
    metadata: &ProfileMetadata,
) -> Result<(), ProfileError> {
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, serde_json::to_vec_pretty(metadata)?)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn profile_name_from_url(url: &Url) -> String {
    url.path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|segment| !segment.trim().is_empty())
        .map(trim_profile_extension)
        .filter(|segment| !segment.is_empty())
        .unwrap_or_else(|| url.host_str().unwrap_or("remote-profile"))
        .to_string()
}

fn trim_profile_extension(value: &str) -> &str {
    value.trim_end_matches(".yaml").trim_end_matches(".yml")
}

fn content_hash(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let digest = hasher.finalize();
    short_hex(&digest[..8])
}

fn profile_id(name: &str, url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let digest = hasher.finalize();
    format!("{}-{}", slugify(name), short_hex(&digest[..4]))
}

fn slugify(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else if ch.is_whitespace() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "remote-profile".into()
    } else {
        trimmed
    }
}

fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn profile_id_is_safe_and_stable() {
        let id = profile_id("Work Proxy.yaml", "https://example.com/sub.yaml");
        assert!(id.starts_with("work-proxy.yaml-"));
        assert!(id.ends_with("38661c2d"));
    }

    #[test]
    fn profile_name_falls_back_to_last_path_segment() {
        let url = Url::parse("https://example.com/a/b/sub.yaml?token=1").unwrap();
        assert_eq!(profile_name_from_url(&url), "sub");
    }

    #[test]
    fn content_disposition_filename_is_preferred() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_DISPOSITION,
            "attachment; filename=iKuuu_V2.yaml"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            profile_name_from_content_disposition(&headers).as_deref(),
            Some("iKuuu_V2.yaml")
        );
    }

    #[test]
    fn active_profile_is_applied_to_runtime_config() {
        let paths = test_paths("apply-active");
        let store = SettingsStore::new(paths.clone());
        store.ensure_layout().unwrap();
        fs::write(
            paths.profiles_dir.join("demo.yaml"),
            "port: 7890\nsocks-port: 7891\nproxies: []\nproxy-groups: []\nrules: []\nsecret: stale\n",
        )
        .unwrap();

        let mut settings = PersistedSettings {
            active_profile: Some("demo".into()),
            mixed_port: 7899,
            allow_lan: true,
            enable_ipv6: true,
            runtime_mode: RuntimeMode::Global,
            external_controller_port: 19090,
            secret: Some("runtime-secret".into()),
            ..PersistedSettings::default()
        };
        settings.extra = BTreeMap::from([
            ("logLevel".into(), serde_yaml::Value::String("debug".into())),
            (
                "interface-name".into(),
                serde_yaml::Value::String("en0".into()),
            ),
        ]);
        store.write(&settings).unwrap();

        let result = ProfileManager::new(paths.clone())
            .unwrap()
            .apply_active(&store)
            .unwrap();
        let config = fs::read_to_string(&result.config_path).unwrap();
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&config).unwrap();
        let mapping = yaml.as_mapping().unwrap();

        assert_eq!(
            mapping.get(yaml_key("mixed-port")),
            Some(&serde_yaml::to_value(7899_u16).unwrap())
        );
        assert!(!mapping.contains_key(yaml_key("port")));
        assert!(!mapping.contains_key(yaml_key("socks-port")));
        assert_eq!(
            mapping.get(yaml_key("allow-lan")),
            Some(&serde_yaml::to_value(true).unwrap())
        );
        assert_eq!(
            mapping.get(yaml_key("ipv6")),
            Some(&serde_yaml::to_value(true).unwrap())
        );
        assert_eq!(
            mapping.get(yaml_key("mode")),
            Some(&serde_yaml::Value::String("global".into()))
        );
        assert_eq!(
            mapping.get(yaml_key("external-controller")),
            Some(&serde_yaml::Value::String("127.0.0.1:19090".into()))
        );
        assert_eq!(
            mapping.get(yaml_key("secret")),
            Some(&serde_yaml::Value::String("runtime-secret".into()))
        );
        assert_eq!(
            mapping.get(yaml_key("log-level")),
            Some(&serde_yaml::Value::String("debug".into()))
        );
        assert_eq!(
            mapping.get(yaml_key("interface-name")),
            Some(&serde_yaml::Value::String("en0".into()))
        );

        fs::remove_dir_all(paths.app_home).unwrap();
    }

    #[test]
    fn mixin_yaml_is_merged_before_runtime_injection() {
        let paths = test_paths("mixin-merge");
        let store = SettingsStore::new(paths.clone());
        store.ensure_layout().unwrap();
        fs::write(
            paths.profiles_dir.join("demo.yaml"),
            "mixed-port: 1\ndns:\n  enable: false\nprofile:\n  store-selected: false\nproxies: []\nproxy-groups: []\nrules: []\n",
        )
        .unwrap();
        store
            .write(&PersistedSettings {
                active_profile: Some("demo".into()),
                mixin: true,
                mixin_yaml: "dns:\n  enable: true\nprofile: null\nunified-delay: true\n".into(),
                mixed_port: 7899,
                ..PersistedSettings::default()
            })
            .unwrap();

        let result = ProfileManager::new(paths.clone())
            .unwrap()
            .apply_active(&store)
            .unwrap();
        let config = fs::read_to_string(&result.config_path).unwrap();
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&config).unwrap();
        let mapping = yaml.as_mapping().unwrap();

        assert_eq!(
            mapping
                .get(yaml_key("dns"))
                .and_then(|value| value.as_mapping())
                .and_then(|dns| dns.get(yaml_key("enable"))),
            Some(&serde_yaml::Value::Bool(true))
        );
        // Mixin deleted `profile:`; runtime injection restores store-selected default.
        assert_eq!(
            mapping
                .get(yaml_key("profile"))
                .and_then(|value| value.as_mapping())
                .and_then(|profile| profile.get(yaml_key("store-selected"))),
            Some(&serde_yaml::Value::Bool(true))
        );
        assert_eq!(
            mapping.get(yaml_key("mixed-port")),
            Some(&serde_yaml::to_value(7899_u16).unwrap())
        );
        assert_eq!(
            mapping.get(yaml_key("unified-delay")),
            Some(&serde_yaml::Value::Bool(true))
        );

        fs::remove_dir_all(paths.app_home).unwrap();
    }

    #[test]
    fn parser_script_runs_before_mixin_and_runtime_injection() {
        let paths = test_paths("parser-script");
        let store = SettingsStore::new(paths.clone());
        store.ensure_layout().unwrap();
        fs::write(
            paths.profiles_dir.join("demo.yaml"),
            "proxy-providers:\n  old: {}\ndns:\n  enable: false\nrules:\n  - MATCH,Proxy\n",
        )
        .unwrap();
        let mut settings = PersistedSettings {
            active_profile: Some("demo".into()),
            mixin: true,
            mixin_yaml: "dns:\n  prefer-h3: true\n".into(),
            ..PersistedSettings::default()
        };
        settings.extra.insert(
            "profile_parser_script".into(),
            serde_yaml::Value::String(
                "prepend-rule DOMAIN-SUFFIX,example.com,DIRECT\nset dns.enable true\ndelete proxy-providers\nappend rules MATCH,DIRECT\n".into(),
            ),
        );
        store.write(&settings).unwrap();

        let result = ProfileManager::new(paths.clone())
            .unwrap()
            .apply_active(&store)
            .unwrap();
        let config = fs::read_to_string(&result.config_path).unwrap();
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&config).unwrap();
        let mapping = yaml.as_mapping().unwrap();
        let rules = mapping
            .get(yaml_key("rules"))
            .and_then(|value| value.as_sequence())
            .unwrap();

        assert_eq!(
            rules.first().and_then(|value| value.as_str()),
            Some("DOMAIN-SUFFIX,example.com,DIRECT")
        );
        assert_eq!(
            rules.last().and_then(|value| value.as_str()),
            Some("MATCH,DIRECT")
        );
        assert!(!mapping.contains_key(yaml_key("proxy-providers")));
        assert_eq!(
            mapping
                .get(yaml_key("dns"))
                .and_then(|value| value.as_mapping())
                .and_then(|dns| dns.get(yaml_key("enable"))),
            Some(&serde_yaml::Value::Bool(true))
        );
        assert_eq!(
            mapping
                .get(yaml_key("dns"))
                .and_then(|value| value.as_mapping())
                .and_then(|dns| dns.get(yaml_key("prefer-h3"))),
            Some(&serde_yaml::Value::Bool(true))
        );

        fs::remove_dir_all(paths.app_home).unwrap();
    }

    #[test]
    fn parser_set_refuses_to_replace_existing_scalar_path() {
        let mut config = serde_yaml::from_str::<serde_yaml::Value>("dns: disabled\n").unwrap();
        let err =
            set_yaml_path(&mut config, "dns.enable", serde_yaml::Value::Bool(true), 7).unwrap_err();

        assert!(matches!(
            err,
            ProfileError::InvalidParserCommand { line: 7, .. }
        ));
        assert_eq!(
            config
                .as_mapping()
                .and_then(|mapping| mapping.get(yaml_key("dns")))
                .and_then(|value| value.as_str()),
            Some("disabled")
        );
    }

    #[test]
    fn parser_append_refuses_to_replace_existing_scalar_sequence() {
        let mut config =
            serde_yaml::from_str::<serde_yaml::Value>("rules: MATCH,DIRECT\n").unwrap();
        let err = append_sequence_value(
            &mut config,
            "rules",
            serde_yaml::Value::String("DOMAIN,example.com,DIRECT".into()),
            11,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ProfileError::InvalidParserCommand { line: 11, .. }
        ));
        assert_eq!(
            config
                .as_mapping()
                .and_then(|mapping| mapping.get(yaml_key("rules")))
                .and_then(|value| value.as_str()),
            Some("MATCH,DIRECT")
        );
    }

    #[test]
    fn tun_mode_injects_mihomo_tun_config() {
        let rendered = render_profile_with_settings(
            "tun:\n  enable: false\nrules: []\n",
            &PersistedSettings {
                tun_mode: true,
                ..PersistedSettings::default()
            },
        )
        .unwrap();
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&rendered).unwrap();
        let tun = yaml
            .as_mapping()
            .unwrap()
            .get(yaml_key("tun"))
            .and_then(|value| value.as_mapping())
            .unwrap();

        assert_eq!(
            tun.get(yaml_key("enable")),
            Some(&serde_yaml::Value::Bool(true))
        );
        assert_eq!(
            tun.get(yaml_key("stack")),
            Some(&serde_yaml::Value::String("system".into()))
        );
        assert_eq!(
            tun.get(yaml_key("dns-hijack"))
                .and_then(|value| value.as_sequence())
                .and_then(|values| values.first())
                .and_then(|value| value.as_str()),
            Some("any:53")
        );
    }

    #[test]
    fn mixin_yaml_root_must_be_mapping() {
        let paths = test_paths("mixin-invalid-root");
        let store = SettingsStore::new(paths.clone());
        store.ensure_layout().unwrap();
        fs::write(paths.profiles_dir.join("demo.yaml"), "proxies: []\n").unwrap();
        store
            .write(&PersistedSettings {
                active_profile: Some("demo".into()),
                mixin: true,
                mixin_yaml: "- not-a-map\n".into(),
                ..PersistedSettings::default()
            })
            .unwrap();

        let error = ProfileManager::new(paths.clone())
            .unwrap()
            .apply_active(&store)
            .unwrap_err();
        assert!(matches!(error, ProfileError::InvalidMixinRoot));

        fs::remove_dir_all(paths.app_home).unwrap();
    }

    #[test]
    fn store_selected_defaults_when_profile_block_missing() {
        let paths = test_paths("store-selected");
        let store = SettingsStore::new(paths.clone());
        store.ensure_layout().unwrap();
        fs::write(
            paths.profiles_dir.join("demo.yaml"),
            "proxies: []\nproxy-groups: []\nrules: []\n",
        )
        .unwrap();
        store
            .write(&PersistedSettings {
                active_profile: Some("demo".into()),
                ..PersistedSettings::default()
            })
            .unwrap();

        let result = ProfileManager::new(paths.clone())
            .unwrap()
            .apply_active(&store)
            .unwrap();
        let rendered = fs::read_to_string(result.config_path).unwrap();
        assert!(
            rendered.contains("store-selected: true"),
            "expected default store-selected, got:\n{rendered}"
        );

        fs::remove_dir_all(paths.app_home).unwrap();
    }

    #[test]
    fn applying_without_active_profile_is_explicit() {
        let paths = test_paths("no-active");
        let store = SettingsStore::new(paths.clone());
        store.ensure_layout().unwrap();

        let error = ProfileManager::new(paths.clone())
            .unwrap()
            .apply_active(&store)
            .unwrap_err();
        assert!(matches!(error, ProfileError::NoActiveProfile));

        fs::remove_dir_all(paths.app_home).unwrap();
    }

    #[test]
    fn deleting_active_profile_clears_pointer() {
        let paths = test_paths("delete-active");
        let store = SettingsStore::new(paths.clone());
        store.ensure_layout().unwrap();
        fs::write(paths.profiles_dir.join("demo.yaml"), "proxies: []\n").unwrap();
        fs::write(paths.config_file.clone(), "mixed-port: 7890\n").unwrap();
        store
            .write(&PersistedSettings {
                active_profile: Some("demo".into()),
                ..PersistedSettings::default()
            })
            .unwrap();

        let deleted = ProfileManager::new(paths.clone())
            .unwrap()
            .delete(&store, "demo")
            .unwrap();
        assert!(deleted);
        assert!(!paths.profiles_dir.join("demo.yaml").exists());
        assert!(!paths.config_file.exists());
        assert_eq!(store.read_or_default().unwrap().active_profile, None);

        fs::remove_dir_all(paths.app_home).unwrap();
    }

    #[test]
    fn import_text_validates_root_and_records_metadata() {
        let paths = test_paths("import-text");
        let store = SettingsStore::new(paths.clone());
        store.ensure_layout().unwrap();

        let result = ProfileManager::new(paths.clone())
            .unwrap()
            .import_text(
                &store,
                Some("Local YAML.yaml".into()),
                "proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n  - DOMAIN-SUFFIX,example.com,Proxy\n".into(),
                true,
            )
            .unwrap();

        assert_eq!(result.name, "Local YAML");
        assert!(result.path.exists());
        assert_eq!(
            store.read_or_default().unwrap().active_profile.as_deref(),
            Some(result.id.as_str())
        );
        let profiles = ProfileManager::new(paths.clone())
            .unwrap()
            .list(&store)
            .unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].source_url, None);
        assert_eq!(profiles[0].rule_count, 2);
        assert!(profiles[0].active);

        fs::remove_dir_all(paths.app_home).unwrap();
    }

    #[test]
    fn read_and_save_text_roundtrip_through_runtime_preview() {
        let paths = test_paths("edit-text");
        let store = SettingsStore::new(paths.clone());
        store.ensure_layout().unwrap();
        fs::write(paths.profiles_dir.join("demo.yaml"), "proxies: []\n").unwrap();
        store
            .write(&PersistedSettings {
                active_profile: Some("demo".into()),
                mixed_port: 7897,
                ..PersistedSettings::default()
            })
            .unwrap();

        let manager = ProfileManager::new(paths.clone()).unwrap();
        let profile = manager.read_text(&store, "demo").unwrap();
        assert!(profile.active);
        assert!(profile.generated_body.contains("mixed-port: 7897"));

        let saved = manager
            .save_text(&store, "demo", "proxies: []\nproxy-groups: []\n".into())
            .unwrap();
        assert!(saved.active);
        assert_eq!(
            fs::read_to_string(paths.profiles_dir.join("demo.yaml")).unwrap(),
            "proxies: []\nproxy-groups: []\n"
        );

        fs::remove_dir_all(paths.app_home).unwrap();
    }

    #[test]
    fn profile_yaml_root_must_be_mapping() {
        assert!(validate_profile_yaml("proxies: []\n").is_ok());
        assert!(matches!(
            validate_profile_yaml("- proxies\n"),
            Err(ProfileError::InvalidConfigRoot)
        ));
    }

    #[test]
    fn profile_id_rejects_path_traversal() {
        assert!(matches!(
            validate_profile_id("../demo"),
            Err(ProfileError::InvalidProfileId(_))
        ));
    }

    fn test_paths(name: &str) -> MacOsAppPaths {
        let dir = std::env::temp_dir().join(format!("cfm-profiles-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        MacOsAppPaths::from_app_home(dir)
    }
}
