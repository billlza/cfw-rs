//! The UI preferences document: its private atomic round trip, the store lock
//! that times out, the fonts and languages it accepts, the v1 upgrade, unknown
//! schemas and absent files, and documents that are malformed, oversized,
//! linked or read while they are written.

use super::*;

#[test]
fn a_contended_settings_lock_times_out_without_inventing_defaults() {
    use std::time::Duration;

    let (root, store) = test_store("contended-startup");
    store.write(&UiPreferences::default()).unwrap();
    let guard = hold_directory_lock(&store.paths().app_home);
    let (reply, result) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        reply.send(store.read_or_default()).unwrap();
    });
    let observed = result.recv_timeout(Duration::from_secs(5));
    // Release even on failure so this regression also terminates against the
    // old, unbounded flock implementation.
    drop(guard);
    reader.join().unwrap();
    assert!(matches!(observed, Ok(Err(SettingsStoreError::StoreBusy))));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn strict_json_round_trip_is_private_and_atomic() {
    let (root, store) = test_store("round-trip");
    let preferences = UiPreferences {
        theme: AppearanceTheme::Dark,
        font_family: FontFamily::SfMono,
        language: UiLanguage::Japanese,
        retain_window_bounds: false,
        launch_at_login: true,
        silent_start: true,
        check_for_updates: true,
    };
    store.write(&preferences).expect("write preferences");
    let snapshot = store.snapshot().expect("read snapshot");
    assert_eq!(snapshot.settings, preferences);
    assert!(snapshot.persisted);

    let path = &store.paths.preferences_file;
    assert_private_file(path);
    assert_private_directory(&store.paths.app_home);
    let entries = fs::read_dir(&store.paths.app_home)
        .expect("read app home")
        .collect::<Result<Vec<_>, _>>()
        .expect("directory entries");
    assert!(
        !entries
            .iter()
            .any(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
    );
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn windows_font_preferences_round_trip_without_coercing_the_family() {
    let (root, store) = test_store("windows-font-families");
    for family in ["Segoe UI", "Consolas"] {
        let mut document = serde_json::to_value(UiPreferences::default()).unwrap();
        document["font_family"] = family.into();
        let preferences: UiPreferences = serde_json::from_value(document).unwrap();
        store.write(&preferences).expect("save Windows font");
        let snapshot = store.snapshot().expect("reopen saved Windows font");
        assert_eq!(snapshot.settings, preferences);
        assert_eq!(
            serde_json::to_value(snapshot.settings).unwrap()["font_family"],
            family
        );
    }
    for family in ["segoe ui", "Arial", "Consolas, monospace"] {
        let mut document = serde_json::to_value(UiPreferences::default()).unwrap();
        document["font_family"] = family.into();
        assert!(serde_json::from_value::<UiPreferences>(document).is_err());
    }
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn v1_preferences_upgrade_without_mutating_the_original_on_read() {
    let (root, store) = test_store("v1-language-upgrade");
    store.ensure_layout().expect("create layout");
    let original = br#"{"schema_version":1,"preferences":{"theme":"dark","font_family":"SF Mono","retain_window_bounds":false,"launch_at_login":true,"silent_start":true,"check_for_updates":false}}"#;
    write_private(&store.paths.preferences_file, original);
    let mut snapshot = store.snapshot().expect("read v1");
    assert!(snapshot.persisted);
    assert_eq!(snapshot.settings.language, UiLanguage::System);
    assert_eq!(snapshot.settings.theme, AppearanceTheme::Dark);
    assert_eq!(snapshot.settings.font_family, FontFamily::SfMono);
    assert!(snapshot.settings.launch_at_login && snapshot.settings.silent_start);
    assert!(!snapshot.settings.retain_window_bounds);
    assert_eq!(fs::read(&store.paths.preferences_file).unwrap(), original);
    snapshot.settings.language = UiLanguage::TraditionalChinese;
    store.write(&snapshot.settings).expect("save v2");
    assert_eq!(store.snapshot().unwrap().settings, snapshot.settings);
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(&store.paths.preferences_file).unwrap()).unwrap();
    assert_eq!(saved["schema_version"], 2);
    assert_eq!(saved["preferences"]["language"], "zh-Hant");
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn language_preferences_are_closed_and_system_selection_obeys_order_and_script() {
    for (preferred, expected) in [
        (vec!["zh-Hans-TW"], UiLanguage::SimplifiedChinese),
        (vec!["zh-Hant-CN"], UiLanguage::TraditionalChinese),
        (vec!["zh_HK"], UiLanguage::TraditionalChinese),
        (vec!["zh-MO"], UiLanguage::TraditionalChinese),
        (vec!["zh-SG"], UiLanguage::SimplifiedChinese),
        (vec!["fr-FR", "ja-JP", "en-US"], UiLanguage::Japanese),
        (vec!["en-GB", "zh-CN"], UiLanguage::English),
        (vec!["de-DE"], UiLanguage::English),
        (vec![], UiLanguage::English),
    ] {
        let preferred: Vec<_> = preferred.into_iter().map(str::to_owned).collect();
        assert_eq!(UiLanguage::System.resolve(&preferred), expected);
        assert_eq!(
            UiLanguage::Japanese.resolve(&preferred),
            UiLanguage::Japanese
        );
    }
    assert!(serde_json::from_str::<UiLanguage>("\"fr\"").is_err());
    let mut invalid = serde_json::to_value(UiPreferences::default()).unwrap();
    invalid["language"] = serde_json::json!("<script>");
    assert!(serde_json::from_value::<UiPreferences>(invalid).is_err());
}

#[test]
fn symlink_and_hard_link_preferences_are_rejected() {
    let (root, store) = test_store("unsafe-file");
    store.ensure_layout().expect("create layout");
    let outside = root.join("outside");
    fs::write(&outside, b"{}").expect("write outside file");
    symlink(&outside, &store.paths.preferences_file).expect("create symlink");
    assert!(matches!(
        store.snapshot(),
        Err(SettingsStoreError::UnsafeFile)
    ));
    fs::remove_file(&store.paths.preferences_file).expect("remove symlink");

    store
        .write(&UiPreferences::default())
        .expect("write preferences");
    fs::hard_link(&store.paths.preferences_file, root.join("hard-link")).expect("create hard link");
    assert!(matches!(
        store.snapshot(),
        Err(SettingsStoreError::UnsafeFile)
    ));
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn malformed_unknown_and_noncanonical_json_fail_closed() {
    let (root, store) = test_store("strict-json");
    store.ensure_layout().expect("create layout");
    let cases = [
        b"not json".as_slice(),
        br#"{"schema_version":1,"preferences":{"theme":"system","font_family":"","retain_window_bounds":true,"launch_at_login":false,"silent_start":false,"check_for_updates":false},"extra":true}"#,
        br#"{ "schema_version": 1, "preferences": {"theme":"system","font_family":"","retain_window_bounds":true,"launch_at_login":false,"silent_start":false,"check_for_updates":false} }"#,
    ];
    for bytes in cases {
        write_private(&store.paths.preferences_file, bytes);
        assert!(store.snapshot().is_err());
    }
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn oversized_preferences_are_rejected_before_json_parsing() {
    let (root, store) = test_store("oversized");
    store.ensure_layout().expect("create layout");
    write_private(
        &store.paths.preferences_file,
        vec![b' '; MAX_PREFERENCES_BYTES + 1],
    );
    assert!(matches!(
        store.snapshot(),
        Err(SettingsStoreError::TooLarge { .. })
    ));
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn concurrent_readers_never_observe_partial_json() {
    let (root, store) = test_store("concurrent");
    store
        .write(&UiPreferences::default())
        .expect("write initial preferences");
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(2));
    let writer_store = Arc::clone(&store);
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for index in 0..24 {
            let preferences = UiPreferences {
                theme: if index % 2 == 0 {
                    AppearanceTheme::Dark
                } else {
                    AppearanceTheme::Light
                },
                ..UiPreferences::default()
            };
            writer_store
                .write(&preferences)
                .expect("atomic preferences write");
        }
    });
    barrier.wait();
    for _ in 0..64 {
        let snapshot = store.snapshot().expect("complete JSON snapshot");
        assert!(matches!(
            snapshot.settings.theme,
            AppearanceTheme::System | AppearanceTheme::Light | AppearanceTheme::Dark
        ));
    }
    writer.join().expect("writer thread");
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn every_language_code_is_its_stored_name() {
    for (language, code) in [
        (UiLanguage::System, "system"),
        (UiLanguage::English, "en"),
        (UiLanguage::SimplifiedChinese, "zh-Hans"),
        (UiLanguage::TraditionalChinese, "zh-Hant"),
        (UiLanguage::Japanese, "ja"),
    ] {
        assert_eq!(language.code(), code);
        assert_eq!(serde_json::to_value(language).unwrap(), code);
    }
}

#[test]
fn preferences_of_an_unknown_schema_are_refused() {
    let (root, store) = test_store("unknown-schema");
    store.ensure_layout().unwrap();
    let current = format!(
        r#"{{"schema_version":3,"preferences":{}}}"#,
        serde_json::to_string(&UiPreferences::default()).unwrap()
    );
    write_private(&store.paths.preferences_file, current);
    assert!(matches!(
        store.snapshot(),
        Err(SettingsStoreError::UnsupportedSchema(3))
    ));
    let first_shape = br#"{"schema_version":7,"preferences":{"theme":"dark","font_family":"SF Mono","retain_window_bounds":false,"launch_at_login":true,"silent_start":true,"check_for_updates":false}}"#;
    write_private(&store.paths.preferences_file, first_shape);
    assert!(matches!(
        store.snapshot(),
        Err(SettingsStoreError::UnsupportedSchema(7))
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn absent_files_are_defaults_that_were_never_persisted() {
    let (root, store) = test_store("absent");
    let snapshot = store.snapshot().unwrap();
    assert!(!snapshot.persisted);
    assert_eq!(snapshot.settings, UiPreferences::default());
    assert_eq!(store.window_bounds().unwrap(), None);
    assert!(!store.legacy_retirement_completed().unwrap());
    fs::remove_dir_all(root).unwrap();
}
