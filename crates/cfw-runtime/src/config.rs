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
    if settings.tun_mode {
        let mut tun = serde_yaml::Mapping::new();
        insert_yaml(&mut tun, "enable", true)?;
        insert_yaml(&mut tun, "stack", "system")?;
        insert_yaml(&mut tun, "auto-route", true)?;
        insert_yaml(&mut tun, "auto-detect-interface", true)?;
        insert_yaml(&mut tun, "strict-route", false)?;
        insert_yaml(&mut tun, "dns-hijack", vec!["any:53"])?;
        config.insert(
            serde_yaml::Value::String("tun".into()),
            serde_yaml::Value::Mapping(tun),
        );
    }
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
        serde_yaml::Value::String(key.into()),
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
        assert!(mapping.contains_key(serde_yaml::Value::String("mixed-port".into())));
        assert!(mapping.contains_key(serde_yaml::Value::String("external-controller".into())));
        let rules = mapping
            .get(serde_yaml::Value::String("rules".into()))
            .and_then(serde_yaml::Value::as_sequence)
            .unwrap();
        assert_eq!(rules.last().unwrap().as_str(), Some("MATCH,DIRECT"));
    }

    #[test]
    fn tun_block_present_only_when_enabled() {
        let without = default_config_mapping(&PersistedSettings::default()).unwrap();
        assert!(!without.contains_key(serde_yaml::Value::String("tun".into())));

        let settings = PersistedSettings {
            tun_mode: true,
            ..PersistedSettings::default()
        };
        let with = default_config_mapping(&settings).unwrap();
        let tun = with
            .get(serde_yaml::Value::String("tun".into()))
            .and_then(serde_yaml::Value::as_mapping)
            .unwrap();
        assert_eq!(
            tun.get(serde_yaml::Value::String("enable".into()))
                .and_then(serde_yaml::Value::as_bool),
            Some(true)
        );
    }
}
