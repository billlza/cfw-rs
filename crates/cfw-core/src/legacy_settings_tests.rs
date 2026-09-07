use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const REQUIRED_BASE: &str = "retain_window_bounds: true\nlaunch_at_login: false\nsilent_start: false\nsystem_proxy: false\n";

fn paths(name: &str) -> (PathBuf, MacOsAppPaths) {
    let root = std::env::temp_dir().join(format!(
        "cfw-legacy-settings-{name}-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let paths = MacOsAppPaths::from_app_home(root.join("app"));
    (root, paths)
}

fn write_legacy(paths: &MacOsAppPaths, text: &str) {
    fs::create_dir_all(&paths.app_home).expect("create app home");
    fs::set_permissions(&paths.app_home, fs::Permissions::from_mode(0o700))
        .expect("set app home mode");
    fs::write(&paths.legacy_settings_file, text).expect("write legacy settings");
    fs::set_permissions(
        &paths.legacy_settings_file,
        fs::Permissions::from_mode(0o600),
    )
    .expect("set legacy settings mode");
}

#[test]
fn quoted_scalars_and_top_level_sequence_are_migrated() {
    let input = r#"---
theme: 'dark'
font_family: "SF Mono"
retain_window_bounds: false
launch_at_login: true
silent_start: true
check_for_updates: true
system_proxy: true
tun_mode: true
mixed_port: 7900
active_profile: bgbyehygqdaznavk-78bcfb32
restore-dns-servers:
- "1.1.1.1"
- '2001:4860:4860::8888'
secret: should-not-survive
"#;
    let (preferences, network, active_profile) =
        parse_legacy_settings(input).expect("parse legacy settings");
    assert_eq!(preferences.theme, AppearanceTheme::Dark);
    assert_eq!(preferences.font_family, FontFamily::SfMono);
    assert!(preferences.launch_at_login);
    assert_eq!(
        network.restore_dns_servers,
        Some(vec!["1.1.1.1".into(), "2001:4860:4860::8888".into()])
    );
    assert!(network.system_proxy);
    assert!(network.tun_mode);
    assert_eq!(network.mixed_port, Some(7900));
    assert_eq!(active_profile.as_deref(), Some("bgbyehygqdaznavk-78bcfb32"));
}

#[test]
fn nested_spoof_and_alias_duplicates_fail_closed() {
    assert!(matches!(
        parse_legacy_settings("ignored:\n  system_proxy: true\n"),
        Err(SettingsStoreError::InvalidLegacySettings { line: 2, .. })
    ));
    assert!(matches!(
        parse_legacy_settings("launch_at_login: true\nlaunchAtLogin: false\n"),
        Err(SettingsStoreError::AmbiguousLegacySetting { .. })
    ));
}

#[test]
fn malformed_whitelisted_values_are_not_defaulted() {
    for input in [
        "",
        "system_proxy: yes\n",
        "theme: blue\n",
        "restore-dns-servers:\n- not-an-address\n",
        "font_family: [SF Mono]\n",
        "font_family:\n",
        "- orphaned-root-item\n",
    ] {
        assert!(parse_legacy_settings(input).is_err(), "accepted: {input}");
    }
    assert!(parse_legacy_settings(&format!("{REQUIRED_BASE}active_profile: ../escape\n")).is_err());
}

#[test]
fn active_profile_is_optional_but_alias_duplicates_fail_closed() {
    let (_, _, active_profile) =
        parse_legacy_settings(REQUIRED_BASE).expect("legacy settings without a selected profile");
    assert_eq!(active_profile, None);
    assert!(matches!(
        parse_legacy_settings(&format!(
            "{REQUIRED_BASE}active_profile: first\nactiveProfile: second\n"
        )),
        Err(SettingsStoreError::AmbiguousLegacySetting { .. })
    ));
}

#[test]
fn migration_source_is_single_use_and_identity_bound() {
    let (root, paths) = paths("round-trip");
    write_legacy(&paths, &format!("{REQUIRED_BASE}theme: dark\n"));
    let migration = LegacySettingsMigration::read(&paths)
        .expect("read migration")
        .expect("legacy source");
    assert_eq!(migration.preferences.theme, AppearanceTheme::Dark);
    let store = crate::SettingsStore::new(paths.clone());
    store
        .write(&migration.preferences)
        .expect("commit JSON preferences");
    migration
        .remove_source(&paths)
        .expect("remove legacy source");
    store
        .commit_legacy_retirement()
        .expect("commit retirement marker");
    assert!(!paths.legacy_settings_file.exists());
    assert_eq!(
        store
            .snapshot()
            .expect("read JSON preferences")
            .settings
            .theme,
        AppearanceTheme::Dark
    );
    assert!(
        store
            .legacy_retirement_completed()
            .expect("read retirement marker")
    );
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn changed_legacy_source_is_not_deleted_after_parsing() {
    let (root, paths) = paths("changed-source");
    write_legacy(&paths, &format!("{REQUIRED_BASE}theme: dark\n"));
    let migration = LegacySettingsMigration::read(&paths)
        .expect("read migration")
        .expect("legacy source");
    write_legacy(&paths, &format!("{REQUIRED_BASE}theme: light\n"));
    assert!(matches!(
        migration.remove_source(&paths),
        Err(SettingsStoreError::LegacySourceChanged)
    ));
    assert!(paths.legacy_settings_file.exists());
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn symlink_and_hard_link_legacy_sources_are_rejected() {
    let (root, paths) = paths("unsafe-source");
    fs::create_dir_all(&paths.app_home).expect("create app home");
    fs::set_permissions(&paths.app_home, fs::Permissions::from_mode(0o700))
        .expect("set app home mode");
    let outside = root.join("outside.yaml");
    fs::write(&outside, b"theme: dark\n").expect("write outside source");
    symlink(&outside, &paths.legacy_settings_file).expect("create legacy symlink");
    assert!(matches!(
        LegacySettingsMigration::read(&paths),
        Err(SettingsStoreError::UnsafeFile)
    ));
    fs::remove_file(&paths.legacy_settings_file).expect("remove symlink");

    write_legacy(&paths, "theme: dark\n");
    fs::hard_link(&paths.legacy_settings_file, root.join("legacy-hard-link"))
        .expect("create hard link");
    assert!(matches!(
        LegacySettingsMigration::read(&paths),
        Err(SettingsStoreError::UnsafeFile)
    ));
    fs::remove_dir_all(root).expect("remove test root");
}
