use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::settings_storage::{FileIdentity, FilePolicy, SecureDirectory};
use crate::{
    AppearanceTheme, FontFamily, LEGACY_SETTINGS_FILE_NAME, MacOsAppPaths, SettingsStoreError,
    UiPreferences,
};

const MAX_LEGACY_SETTINGS_BYTES: usize = 1024 * 1024;
const MAX_DNS_SERVERS: usize = 32;
const MAX_LEGACY_PROFILE_ID_BYTES: usize = 128;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyNetworkState {
    pub system_proxy: bool,
    pub tun_mode: bool,
    pub mixed_port: Option<u16>,
    pub restore_dns_servers: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct LegacySettingsMigration {
    pub preferences: UiPreferences,
    pub network: LegacyNetworkState,
    /// Exact basename selected by the legacy writer. This is migration
    /// authority, not a preference that survives the one-way cutover.
    pub active_profile: Option<String>,
    source_identity: FileIdentity,
}

impl LegacySettingsMigration {
    pub fn read(paths: &MacOsAppPaths) -> Result<Option<Self>, SettingsStoreError> {
        let Some(directory) = SecureDirectory::open_existing(&paths.app_home)? else {
            return Ok(None);
        };
        let Some(stored) = directory.read_optional(
            LEGACY_SETTINGS_FILE_NAME,
            MAX_LEGACY_SETTINGS_BYTES,
            FilePolicy::LegacyReadOnly,
        )?
        else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&stored.bytes).map_err(|error| {
            SettingsStoreError::InvalidLegacySettings {
                line: 1,
                message: format!("legacy settings are not UTF-8: {error}"),
            }
        })?;
        let (preferences, network, active_profile) = parse_legacy_settings(text)?;
        Ok(Some(Self {
            preferences,
            network,
            active_profile,
            source_identity: stored.identity,
        }))
    }

    pub fn remove_source(&self, paths: &MacOsAppPaths) -> Result<(), SettingsStoreError> {
        SecureDirectory::open_or_create(&paths.app_home)?.remove_matching(
            LEGACY_SETTINGS_FILE_NAME,
            &self.source_identity,
            MAX_LEGACY_SETTINGS_BYTES,
            FilePolicy::LegacyReadOnly,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LegacyKey {
    Theme,
    FontFamily,
    RetainWindowBounds,
    LaunchAtLogin,
    SilentStart,
    CheckForUpdates,
    SystemProxy,
    TunMode,
    MixedPort,
    RestoreDnsServers,
    ActiveProfile,
}

fn parse_legacy_settings(
    input: &str,
) -> Result<(UiPreferences, LegacyNetworkState, Option<String>), SettingsStoreError> {
    let mut preferences = UiPreferences::default();
    let mut network = LegacyNetworkState::default();
    let mut active_profile = None;
    let mut seen = HashSet::new();
    let mut dns_sequence: Option<(usize, Vec<String>)> = None;
    let mut saw_content = false;
    let mut unknown_continuation = false;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.contains('\t') {
            return legacy_error(line_number, "tabs are not accepted");
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "---" && !saw_content {
            saw_content = true;
            continue;
        }
        if trimmed == "---" || trimmed == "..." {
            return legacy_error(line_number, "multiple YAML documents are not accepted");
        }
        saw_content = true;

        let indentation = line.len() - line.trim_start_matches(' ').len();
        let sequence_item = trimmed.strip_prefix("- ");
        if let Some((sequence_line, values)) = dns_sequence.as_mut()
            && sequence_item.is_some()
            && matches!(indentation, 0 | 2)
        {
            let value = parse_scalar(sequence_item.expect("checked above"), line_number)?;
            push_dns_values(values, &value, line_number)?;
            *sequence_line = line_number;
            continue;
        }

        if indentation > 0 {
            if let Some((key, _)) = split_mapping_entry(trimmed)
                && recognized_key(key).is_some()
            {
                return legacy_error(
                    line_number,
                    "whitelisted settings must be top-level, not nested",
                );
            }
            if dns_sequence.is_some() {
                return legacy_error(line_number, "restore DNS sequence is malformed");
            }
            if unknown_continuation {
                continue;
            }
            return legacy_error(line_number, "unexpected nested YAML content");
        }

        finish_dns_sequence(&mut network, dns_sequence.take())?;
        if sequence_item.is_some() {
            if unknown_continuation {
                continue;
            }
            return legacy_error(line_number, "unexpected root sequence item");
        }
        let Some((raw_key, raw_value)) = split_mapping_entry(line) else {
            return legacy_error(line_number, "expected a top-level key and scalar value");
        };
        let Some(key) = recognized_key(raw_key) else {
            unknown_continuation = raw_value.trim().is_empty()
                || matches!(raw_value.trim(), "|" | ">" | "|-" | ">-" | "|+" | ">+");
            continue;
        };
        unknown_continuation = false;
        if !seen.insert(key) {
            return Err(SettingsStoreError::AmbiguousLegacySetting {
                key: canonical_key(key).to_string(),
            });
        }

        match key {
            LegacyKey::Theme => {
                preferences.theme = match parse_scalar(raw_value, line_number)?.as_str() {
                    "system" => AppearanceTheme::System,
                    "light" => AppearanceTheme::Light,
                    "dark" => AppearanceTheme::Dark,
                    _ => return legacy_error(line_number, "theme value is unsupported"),
                };
            }
            LegacyKey::FontFamily => {
                preferences.font_family = match parse_scalar(raw_value, line_number)?.as_str() {
                    "" => FontFamily::System,
                    "Avenir Next" => FontFamily::AvenirNext,
                    "SF Mono" => FontFamily::SfMono,
                    _ => return legacy_error(line_number, "font value is unsupported"),
                };
            }
            LegacyKey::RetainWindowBounds => {
                preferences.retain_window_bounds = parse_bool(raw_value, line_number)?;
            }
            LegacyKey::LaunchAtLogin => {
                preferences.launch_at_login = parse_bool(raw_value, line_number)?;
            }
            LegacyKey::SilentStart => {
                preferences.silent_start = parse_bool(raw_value, line_number)?;
            }
            LegacyKey::CheckForUpdates => {
                preferences.check_for_updates = parse_bool(raw_value, line_number)?;
            }
            LegacyKey::SystemProxy => {
                network.system_proxy = parse_bool(raw_value, line_number)?;
            }
            LegacyKey::TunMode => {
                network.tun_mode = parse_bool(raw_value, line_number)?;
            }
            LegacyKey::MixedPort => {
                let value = parse_scalar(raw_value, line_number)?;
                network.mixed_port = Some(value.parse::<u16>().map_err(|error| {
                    SettingsStoreError::InvalidLegacySettings {
                        line: line_number,
                        message: format!("mixed_port is not a valid u16: {error}"),
                    }
                })?);
                if network.mixed_port == Some(0) {
                    return legacy_error(line_number, "mixed_port must be non-zero");
                }
            }
            LegacyKey::RestoreDnsServers => {
                if raw_value.trim().is_empty() {
                    dns_sequence = Some((line_number, Vec::new()));
                } else {
                    let mut values = Vec::new();
                    push_dns_values(
                        &mut values,
                        &parse_scalar(raw_value, line_number)?,
                        line_number,
                    )?;
                    network.restore_dns_servers = Some(values);
                }
            }
            LegacyKey::ActiveProfile => {
                let value = parse_scalar(raw_value, line_number)?;
                if value.is_empty()
                    || value.len() > MAX_LEGACY_PROFILE_ID_BYTES
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return legacy_error(
                        line_number,
                        "active_profile must be a bounded basename containing only ASCII letters, digits, '-' or '_'",
                    );
                }
                active_profile = Some(value);
            }
        }
    }
    finish_dns_sequence(&mut network, dns_sequence)?;
    for required in [
        LegacyKey::RetainWindowBounds,
        LegacyKey::LaunchAtLogin,
        LegacyKey::SilentStart,
        LegacyKey::SystemProxy,
    ] {
        if !seen.contains(&required) {
            return legacy_error(
                input.lines().count().max(1),
                format!(
                    "required legacy writer field is missing: {}",
                    canonical_key(required)
                ),
            );
        }
    }
    Ok((preferences, network, active_profile))
}

fn split_mapping_entry(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    if key.is_empty()
        || key.trim() != key
        || key
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-')))
    {
        return None;
    }
    Some((key, value.trim_start_matches(' ')))
}

fn recognized_key(key: &str) -> Option<LegacyKey> {
    match key {
        "theme" => Some(LegacyKey::Theme),
        "font_family" | "fontFamily" => Some(LegacyKey::FontFamily),
        "retain_window_bounds" | "retainWindowBounds" => Some(LegacyKey::RetainWindowBounds),
        "launch_at_login" | "launchAtLogin" => Some(LegacyKey::LaunchAtLogin),
        "silent_start" | "silentStart" => Some(LegacyKey::SilentStart),
        "check_for_updates" | "checkForUpdates" => Some(LegacyKey::CheckForUpdates),
        "system_proxy" | "systemProxy" => Some(LegacyKey::SystemProxy),
        "tun_mode" | "tunMode" => Some(LegacyKey::TunMode),
        "mixed_port" | "mixedPort" => Some(LegacyKey::MixedPort),
        "restore-dns-servers" | "restoreDnsServers" => Some(LegacyKey::RestoreDnsServers),
        "active_profile" | "activeProfile" => Some(LegacyKey::ActiveProfile),
        _ => None,
    }
}

fn canonical_key(key: LegacyKey) -> &'static str {
    match key {
        LegacyKey::Theme => "theme",
        LegacyKey::FontFamily => "font_family",
        LegacyKey::RetainWindowBounds => "retain_window_bounds",
        LegacyKey::LaunchAtLogin => "launch_at_login",
        LegacyKey::SilentStart => "silent_start",
        LegacyKey::CheckForUpdates => "check_for_updates",
        LegacyKey::SystemProxy => "system_proxy",
        LegacyKey::TunMode => "tun_mode",
        LegacyKey::MixedPort => "mixed_port",
        LegacyKey::RestoreDnsServers => "restore-dns-servers",
        LegacyKey::ActiveProfile => "active_profile",
    }
}

fn parse_bool(value: &str, line: usize) -> Result<bool, SettingsStoreError> {
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => legacy_error(line, "boolean must be exactly true or false"),
    }
}

fn parse_scalar(value: &str, line: usize) -> Result<String, SettingsStoreError> {
    if value.trim() != value || value.chars().any(char::is_control) {
        return legacy_error(line, "scalar has invalid whitespace or control characters");
    }
    if value.starts_with('"') {
        return serde_json::from_str::<String>(value).map_err(|error| {
            SettingsStoreError::InvalidLegacySettings {
                line,
                message: format!("double-quoted scalar is invalid: {error}"),
            }
        });
    }
    if value.starts_with('\'') {
        if !value.ends_with('\'') || value.len() < 2 {
            return legacy_error(line, "single-quoted scalar is unterminated");
        }
        let inner = &value[1..value.len() - 1];
        let mut output = String::with_capacity(inner.len());
        let mut characters = inner.chars().peekable();
        while let Some(character) = characters.next() {
            if character == '\'' && characters.next_if_eq(&'\'').is_none() {
                return legacy_error(line, "single quote must be escaped by doubling");
            }
            output.push(character);
        }
        return Ok(output);
    }
    if value.is_empty() {
        return legacy_error(line, "empty strings must use explicit quotes");
    }
    if value.starts_with(['[', '{', '&', '*', '!', '|', '>', '@', '`'])
        || value.contains('#')
        || value.contains(": ")
    {
        return legacy_error(line, "plain scalar uses unsupported YAML syntax");
    }
    Ok(value.to_string())
}

fn push_dns_values(
    output: &mut Vec<String>,
    scalar: &str,
    line: usize,
) -> Result<(), SettingsStoreError> {
    for value in scalar
        .split([',', ' '])
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !value.eq_ignore_ascii_case("empty") && IpAddr::from_str(value).is_err() {
            return legacy_error(line, "restore DNS value must be an IP address or empty");
        }
        if output.len() >= MAX_DNS_SERVERS {
            return legacy_error(line, "restore DNS sequence is too large");
        }
        output.push(value.to_string());
    }
    if output.is_empty() {
        return legacy_error(line, "restore DNS value is empty");
    }
    Ok(())
}

fn finish_dns_sequence(
    network: &mut LegacyNetworkState,
    sequence: Option<(usize, Vec<String>)>,
) -> Result<(), SettingsStoreError> {
    let Some((line, values)) = sequence else {
        return Ok(());
    };
    if values.is_empty() {
        return legacy_error(line, "restore DNS sequence is empty");
    }
    if values
        .iter()
        .any(|value| value.eq_ignore_ascii_case("empty"))
        && values.len() != 1
    {
        return legacy_error(line, "empty cannot be combined with DNS server addresses");
    }
    network.restore_dns_servers = Some(values);
    Ok(())
}

fn legacy_error<T>(line: usize, message: impl Into<String>) -> Result<T, SettingsStoreError> {
    Err(SettingsStoreError::InvalidLegacySettings {
        line,
        message: message.into(),
    })
}

#[cfg(test)]
#[path = "legacy_settings_tests.rs"]
mod tests;
