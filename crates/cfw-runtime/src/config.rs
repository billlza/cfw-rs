//! Default mihomo config generation, shared by the desktop shell and the CLI so
//! the two never drift. This covers the *no active profile* case — when a
//! profile is selected, `cfw-profiles` materializes the full config instead.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{self, AtomicU64};

use cfw_core::{MacOsAppPaths, PersistedSettings, RuntimeMode};

use crate::CoreRuntimeError;

/// Process-wide counter making each config temp file name unique.
static WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Render a minimal, valid mihomo config from settings and write it atomically
/// to `paths.config_file` (tmp + rename). Returns the written path.
pub fn write_default_config(
    paths: &MacOsAppPaths,
    settings: &PersistedSettings,
) -> Result<PathBuf, CoreRuntimeError> {
    let config = default_config_mapping(settings)?;
    let rendered = serde_yaml::to_string(&serde_yaml::Value::Mapping(config))
        .map_err(|err| CoreRuntimeError::Config(err.to_string()))?;
    if let Some(parent) = paths.config_file.parent() {
        fs::create_dir_all(parent)?;
    }
    // Unique temp name per writer so a CLI and the shell writing concurrently
    // never clobber each other's staging file; rename is atomic.
    let unique = format!(
        "{}.{}.tmp",
        std::process::id(),
        WRITE_COUNTER.fetch_add(1, atomic::Ordering::Relaxed)
    );
    let tmp_path = paths.config_file.with_extension(unique);
    fs::write(&tmp_path, rendered)?;
    fs::rename(&tmp_path, &paths.config_file)?;
    Ok(paths.config_file.clone())
}

/// Build the mihomo config mapping from settings without touching the filesystem.
pub fn default_config_mapping(
    settings: &PersistedSettings,
) -> Result<serde_yaml::Mapping, CoreRuntimeError> {
    let mut config = serde_yaml::Mapping::new();
    insert_yaml(&mut config, "mixed-port", settings.mixed_port)?;
    insert_yaml(&mut config, "allow-lan", settings.allow_lan)?;
    insert_yaml(&mut config, "ipv6", settings.enable_ipv6)?;
    insert_yaml(
        &mut config,
        "mode",
        match settings.runtime_mode {
            RuntimeMode::Global => "global",
            RuntimeMode::Rule => "rule",
            RuntimeMode::Direct => "direct",
            RuntimeMode::Script => "script",
        },
    )?;
    insert_yaml(
        &mut config,
        "external-controller",
        format!(
            "{}:{}",
            settings.external_controller_host, settings.external_controller_port
        ),
    )?;
    if let Some(secret) = settings.secret.as_deref().filter(|value| !value.is_empty()) {
        insert_yaml(&mut config, "secret", secret)?;
    }
    insert_yaml(
        &mut config,
        "log-level",
        settings
            .extra
            .get("logLevel")
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("info"),
    )?;
    if let Some(interface_name) = settings
        .extra
        .get("interface-name")
        .or_else(|| settings.extra.get("interfaceName"))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        insert_yaml(&mut config, "interface-name", interface_name)?;
    }
    if let Some(bind_address) = settings
        .extra
        .get("bind-address")
        .or_else(|| settings.extra.get("bindAddress"))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        insert_yaml(&mut config, "bind-address", bind_address)?;
    }
    if settings.tun_mode {
        let mut tun = serde_yaml::Mapping::new();
        insert_yaml(&mut tun, "enable", true)?;
        let stack = settings
            .extra
            .get("tun-stack")
            .or_else(|| settings.extra.get("tunStack"))
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("mixed");
        insert_yaml(&mut tun, "stack", stack)?;
        let auto_route = settings
            .extra
            .get("tun-auto-route")
            .or_else(|| settings.extra.get("tunAutoRoute"))
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(true);
        insert_yaml(&mut tun, "auto-route", auto_route)?;
        insert_yaml(&mut tun, "auto-detect-interface", true)?;
        let strict_route = settings
            .extra
            .get("tun-strict-route")
            .or_else(|| settings.extra.get("tunStrictRoute"))
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(true);
        insert_yaml(&mut tun, "strict-route", strict_route)?;
        let dns_hijack = settings
            .extra
            .get("tun-dns-hijack")
            .or_else(|| settings.extra.get("tunDnsHijack"))
            .and_then(serde_yaml::Value::as_str)
            .map(|value| {
                value
                    .split(|ch| ch == '\n' || ch == ',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| item.to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|items| !items.is_empty())
            .unwrap_or_else(|| vec!["any:53".into(), "[::]:53".into()]);
        insert_yaml(&mut tun, "dns-hijack", dns_hijack)?;
        config.insert("tun",
            serde_yaml::Value::Mapping(tun),
        );
    }
    let mut profile = serde_yaml::Mapping::new();
    insert_yaml(&mut profile, "store-selected", true)?;
    config.insert("profile",
        serde_yaml::Value::Mapping(profile),
    );
    insert_yaml(&mut config, "proxies", Vec::<serde_yaml::Value>::new())?;
    insert_yaml(&mut config, "proxy-groups", Vec::<serde_yaml::Value>::new())?;
    insert_yaml(&mut config, "rules", vec!["MATCH,DIRECT"])?;
    Ok(config)
}

fn insert_yaml<T: serde::Serialize>(
    mapping: &mut serde_yaml::Mapping,
    key: &str,
    value: T,
) -> Result<(), CoreRuntimeError> {
    mapping.insert(
        key,
        serde_yaml::to_value(value).map_err(|err| CoreRuntimeError::Config(err.to_string()))?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_core_keys_and_match_rule() {
        let mapping = default_config_mapping(&PersistedSettings::default()).unwrap();
        assert!(mapping.contains_key("mixed-port"));
        assert!(mapping.contains_key("external-controller"));
        let profile = mapping
            .get("profile")
            .and_then(serde_yaml::Value::as_mapping)
            .unwrap();
        assert_eq!(
            profile
                .get("store-selected")
                .and_then(serde_yaml::Value::as_bool),
            Some(true)
        );
        let rules = mapping
            .get("rules")
            .and_then(serde_yaml::Value::as_sequence)
            .unwrap();
        assert_eq!(rules.last().unwrap().as_str(), Some("MATCH,DIRECT"));
    }

    #[test]
    fn tun_block_present_only_when_enabled() {
        let without = default_config_mapping(&PersistedSettings::default()).unwrap();
        assert!(!without.contains_key("tun"));

        let settings = PersistedSettings {
            tun_mode: true,
            ..PersistedSettings::default()
        };
        let with = default_config_mapping(&settings).unwrap();
        let tun = with
            .get("tun")
            .and_then(serde_yaml::Value::as_mapping)
            .unwrap();
        assert_eq!(
            tun.get("enable")
                .and_then(serde_yaml::Value::as_bool),
            Some(true)
        );
    }
}
