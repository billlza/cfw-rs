use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::test_support::{create_private_directory, symlink, write_private};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const REQUIRED_BASE: &str = "retain_window_bounds: true\nlaunch_at_login: false\nsilent_start: false\nsystem_proxy: false\n";

fn paths(name: &str) -> (PathBuf, AppPaths) {
    let root = std::env::temp_dir().join(format!(
        "cfw-legacy-settings-{name}-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let paths = AppPaths::from_app_home(root.join("app"));
    (root, paths)
}

fn write_legacy(paths: &AppPaths, text: &str) {
    write_private(&paths.legacy_settings_file, text);
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
    fs::write(
        &paths.legacy_settings_file,
        format!("{REQUIRED_BASE}theme: light\n"),
    )
    .expect("change the bytes without replacing the inode");
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
    create_private_directory(&paths.app_home);
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

/// The line and message of a legacy settings rejection.
fn rejection(input: &str) -> (usize, String) {
    match parse_legacy_settings(input) {
        Err(SettingsStoreError::InvalidLegacySettings { line, message }) => (line, message),
        other => panic!("expected a rejection of {input:?}, got {other:?}"),
    }
}

#[test]
fn every_whitelisted_key_and_alias_is_read() {
    let input = "theme: light\nfontFamily: Avenir Next\nretainWindowBounds: true\nlaunchAtLogin: true\nsilentStart: true\ncheckForUpdates: false\nsystemProxy: true\ntunMode: true\nmixedPort: 7890\nrestoreDnsServers: 1.1.1.1, 8.8.8.8\nactiveProfile: work_2\n";
    let (preferences, network, active_profile) = parse_legacy_settings(input).expect("aliases");
    assert_eq!(preferences.theme, AppearanceTheme::Light);
    assert_eq!(preferences.font_family, FontFamily::AvenirNext);
    assert!(preferences.retain_window_bounds);
    assert!(preferences.launch_at_login);
    assert!(preferences.silent_start);
    assert!(!preferences.check_for_updates);
    assert_eq!(
        network,
        LegacyNetworkState {
            system_proxy: true,
            tun_mode: true,
            mixed_port: Some(7890),
            restore_dns_servers: Some(vec!["1.1.1.1".into(), "8.8.8.8".into()]),
        }
    );
    assert_eq!(active_profile.as_deref(), Some("work_2"));

    let (preferences, network, _) = parse_legacy_settings(&format!(
        "{REQUIRED_BASE}theme: system\nfont_family: \"\"\nrestore-dns-servers: empty\n"
    ))
    .expect("system defaults");
    assert_eq!(preferences.theme, AppearanceTheme::System);
    assert_eq!(preferences.font_family, FontFamily::System);
    assert_eq!(network.restore_dns_servers, Some(vec!["empty".into()]));
}

#[test]
fn comments_blank_lines_crlf_and_unknown_blocks_are_skipped() {
    let input = "# written by the legacy app\r\n\r\nunknown_block: |\r\n  free text: with a colon\r\n  - and a dash\r\nunknown_list:\r\n- first\r\n- second\r\n"
        .to_owned()
        + &REQUIRED_BASE.replace('\n', "\r\n");
    let (preferences, network, _) = parse_legacy_settings(&input).expect("skipped content");
    assert!(preferences.retain_window_bounds);
    assert!(!network.system_proxy);
}

#[test]
fn every_duplicated_key_names_its_canonical_form() {
    for (first, second, canonical) in [
        ("theme: dark", "theme: light", "theme"),
        ("font_family: SF Mono", "fontFamily: SF Mono", "font_family"),
        (
            "retain_window_bounds: true",
            "retainWindowBounds: true",
            "retain_window_bounds",
        ),
        (
            "launch_at_login: true",
            "launchAtLogin: true",
            "launch_at_login",
        ),
        ("silent_start: true", "silentStart: true", "silent_start"),
        (
            "check_for_updates: true",
            "checkForUpdates: true",
            "check_for_updates",
        ),
        ("system_proxy: true", "systemProxy: true", "system_proxy"),
        ("tun_mode: true", "tunMode: true", "tun_mode"),
        ("mixed_port: 7890", "mixedPort: 7891", "mixed_port"),
        (
            "restore-dns-servers: 1.1.1.1",
            "restoreDnsServers: 8.8.8.8",
            "restore-dns-servers",
        ),
        (
            "active_profile: one",
            "activeProfile: two",
            "active_profile",
        ),
    ] {
        match parse_legacy_settings(&format!("{first}\n{second}\n")) {
            Err(SettingsStoreError::AmbiguousLegacySetting { key }) => assert_eq!(key, canonical),
            other => panic!("{first} / {second}: {other:?}"),
        }
    }
}

#[test]
fn every_missing_required_field_is_named_at_the_last_line() {
    for required in [
        "retain_window_bounds",
        "launch_at_login",
        "silent_start",
        "system_proxy",
    ] {
        let input = REQUIRED_BASE
            .lines()
            .filter(|line| !line.starts_with(required))
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        assert_eq!(
            rejection(&input),
            (
                3,
                format!("required legacy writer field is missing: {required}")
            )
        );
    }
}

#[test]
fn document_structure_outside_the_writer_format_is_refused() {
    for (input, expected) in [
        ("theme:\tdark\n", (1, "tabs are not accepted")),
        (
            "---\ntheme: dark\n---\n",
            (3, "multiple YAML documents are not accepted"),
        ),
        (
            "theme: dark\n...\n",
            (2, "multiple YAML documents are not accepted"),
        ),
        (
            "restore-dns-servers:\n- 1.1.1.1\n    - 8.8.8.8\n",
            (3, "restore DNS sequence is malformed"),
        ),
        (
            "theme: dark\n  extra\n",
            (2, "unexpected nested YAML content"),
        ),
        (
            "theme: dark\n- item\n",
            (2, "unexpected root sequence item"),
        ),
        (
            "not a mapping\n",
            (1, "expected a top-level key and scalar value"),
        ),
        (
            "restore-dns-servers:\ntheme: dark\n",
            (1, "restore DNS sequence is empty"),
        ),
        (
            "restore-dns-servers:\n- empty\n- 1.1.1.1\n",
            (3, "empty cannot be combined with DNS server addresses"),
        ),
    ] {
        assert_eq!(
            rejection(input),
            (expected.0, expected.1.to_owned()),
            "{input:?}"
        );
    }
}

#[test]
fn whitelisted_values_outside_their_domain_are_refused() {
    let too_many = (0..=MAX_DNS_SERVERS)
        .map(|index| format!("10.0.0.{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let long_profile = "p".repeat(MAX_LEGACY_PROFILE_ID_BYTES + 1);
    for (value, message) in [
        ("font_family: Comic Sans", "font value is unsupported".to_owned()),
        (
            "mixed_port: 70000",
            "mixed_port is not a valid u16: number too large to fit in target type".to_owned(),
        ),
        ("mixed_port: 0", "mixed_port must be non-zero".to_owned()),
        (
            "restore-dns-servers: 300.1.1.1",
            "restore DNS value must be an IP address or empty".to_owned(),
        ),
        (
            &format!("restore-dns-servers: \"{too_many}\""),
            "restore DNS sequence is too large".to_owned(),
        ),
        ("restore-dns-servers: \",\"", "restore DNS value is empty".to_owned()),
        (
            &format!("active_profile: {long_profile}"),
            "active_profile must be a bounded basename containing only ASCII letters, digits, '-' or '_'".to_owned(),
        ),
    ] {
        assert_eq!(rejection(&format!("{value}\n")), (1, message), "{value}");
    }
    let longest_profile = "p".repeat(MAX_LEGACY_PROFILE_ID_BYTES);
    let (_, _, active_profile) = parse_legacy_settings(&format!(
        "{REQUIRED_BASE}active_profile: {longest_profile}\n"
    ))
    .expect("the longest profile id");
    assert_eq!(active_profile, Some(longest_profile));
}

#[test]
fn scalars_accept_only_the_writer_quoting() {
    for (value, message) in [
        (
            "theme: dark ",
            "scalar has invalid whitespace or control characters",
        ),
        ("theme: 'dark", "single-quoted scalar is unterminated"),
        ("theme: '", "single-quoted scalar is unterminated"),
        ("theme: 'da'rk'", "single quote must be escaped by doubling"),
        ("theme:", "empty strings must use explicit quotes"),
        ("theme: [dark]", "plain scalar uses unsupported YAML syntax"),
        (
            "theme: dark # comment",
            "plain scalar uses unsupported YAML syntax",
        ),
        ("theme: a: b", "plain scalar uses unsupported YAML syntax"),
        // A doubled quote is one quote, so the value parses and is then unsupported.
        ("theme: 'it''s'", "theme value is unsupported"),
    ] {
        assert_eq!(
            rejection(&format!("{value}\n")),
            (1, message.to_owned()),
            "{value}"
        );
    }
    let (line, message) = rejection("theme: \"dark\n");
    assert_eq!(line, 1);
    assert!(
        message.starts_with("double-quoted scalar is invalid: "),
        "{message}"
    );
}

#[test]
fn a_missing_source_is_no_migration_and_a_non_utf8_source_is_refused() {
    let (root, paths) = paths("absent-source");
    assert!(
        LegacySettingsMigration::read(&paths)
            .expect("no home")
            .is_none()
    );
    create_private_directory(&paths.app_home);
    assert!(
        LegacySettingsMigration::read(&paths)
            .expect("no file")
            .is_none()
    );

    write_private(&paths.legacy_settings_file, b"theme: \xff\n");
    match LegacySettingsMigration::read(&paths) {
        Err(SettingsStoreError::InvalidLegacySettings { line: 1, message }) => {
            assert!(
                message.starts_with("legacy settings are not UTF-8: "),
                "{message}"
            );
        }
        other => panic!("expected a UTF-8 rejection, got {other:?}"),
    }
    fs::remove_dir_all(root).expect("remove test root");
}
