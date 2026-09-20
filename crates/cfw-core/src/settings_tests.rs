use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use super::*;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_store(name: &str) -> (PathBuf, SettingsStore) {
    let root = env::temp_dir().join(format!(
        "cfw-settings-{name}-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let store = SettingsStore::new(MacOsAppPaths::from_app_home(root.join("app")));
    (root, store)
}

#[test]
fn a_contended_settings_lock_times_out_without_inventing_defaults() {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    let (root, store) = test_store("contended-startup");
    store.write(&UiPreferences::default()).unwrap();
    let guard = fs::File::open(&store.paths().app_home).unwrap();
    assert_eq!(unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_EX) }, 0);
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
fn runtime_settings_compare_and_swap_preserves_ui_preferences_and_rejects_stale_writes() {
    let (root, store) = test_store("runtime-cas");
    store.write(&UiPreferences::default()).unwrap();
    let before = store
        .runtime_settings::<std::collections::BTreeMap<String, u16>>()
        .unwrap();
    assert!(before.revision.is_none());
    let value = std::collections::BTreeMap::from([("port".to_owned(), 8890)]);
    store
        .compare_and_swap_runtime_settings(None, &value)
        .unwrap();
    let observed = store
        .runtime_settings::<std::collections::BTreeMap<String, u16>>()
        .unwrap();
    assert_eq!(observed.settings, value);
    assert!(observed.revision.is_some());
    assert!(matches!(
        store.compare_and_swap_runtime_settings(None, &before.settings),
        Err(SettingsStoreError::RuntimeSettingsChanged)
    ));
    assert_eq!(
        store
            .runtime_settings::<std::collections::BTreeMap<String, u16>>()
            .unwrap()
            .settings,
        value
    );
    assert_eq!(store.read_or_default().unwrap(), UiPreferences::default());
    store
        .compare_and_swap_runtime_settings(observed.revision.as_deref(), &before.settings)
        .unwrap();
    assert!(
        store
            .runtime_settings::<std::collections::BTreeMap<String, u16>>()
            .unwrap()
            .settings
            .is_empty()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_runtime_settings_never_become_defaults() {
    let (root, store) = test_store("runtime-corrupt");
    store
        .compare_and_swap_runtime_settings(
            None,
            &std::collections::BTreeMap::from([("port", 8890)]),
        )
        .unwrap();
    fs::write(
        store.paths().app_home.join("cfw-runtime-settings.json"),
        b"{broken}",
    )
    .unwrap();
    assert!(
        store
            .runtime_settings::<std::collections::BTreeMap<String, u16>>()
            .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_profile_staging_never_reuses_the_legacy_profile_directory() {
    let paths = MacOsAppPaths::from_app_home("/tmp/cfw-profile-path-contract");
    assert_eq!(
        paths
            .legacy_profiles_dir
            .file_name()
            .and_then(|name| name.to_str()),
        Some(LEGACY_PROFILES_DIR_NAME)
    );
    assert_eq!(
        paths
            .profiles_dir
            .file_name()
            .and_then(|name| name.to_str()),
        Some(PROFILES_DIR_NAME)
    );
    assert_ne!(paths.legacy_profiles_dir, paths.profiles_dir);
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
    let metadata = fs::metadata(path).expect("preferences metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        fs::metadata(&store.paths.app_home)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
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
fn v1_preferences_upgrade_without_mutating_the_original_on_read() {
    let (root, store) = test_store("v1-language-upgrade");
    store.ensure_layout().expect("create layout");
    let original = br#"{"schema_version":1,"preferences":{"theme":"dark","font_family":"SF Mono","retain_window_bounds":false,"launch_at_login":true,"silent_start":true,"check_for_updates":false}}"#;
    fs::write(&store.paths.preferences_file, original).expect("write v1");
    fs::set_permissions(
        &store.paths.preferences_file,
        fs::Permissions::from_mode(0o600),
    )
    .expect("private v1");
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
fn window_bounds_round_trip_is_private_canonical_and_independent() {
    let (root, store) = test_store("window-bounds-round-trip");
    let bounds = WindowBounds::new(-1440, 25, 1200, 800).expect("valid bounds");
    store
        .write_window_bounds(bounds)
        .expect("write window bounds");

    assert_eq!(
        store.window_bounds().expect("read window bounds"),
        Some(bounds)
    );
    assert_eq!(
        fs::read(&store.paths.window_state_file).expect("read canonical state"),
        br#"{"schema_version":1,"bounds":{"x":-1440,"y":25,"width":1200,"height":800}}"#,
    );
    let metadata = fs::metadata(&store.paths.window_state_file).expect("window state metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert!(!store.paths.preferences_file.exists());

    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn malformed_noncanonical_and_out_of_range_window_bounds_fail_closed() {
    let (root, store) = test_store("invalid-window-bounds");
    store.ensure_layout().expect("create layout");
    let cases = [
        b"not json".as_slice(),
        br#"{ "schema_version": 1, "bounds": {"x":0,"y":0,"width":850,"height":603} }"#,
        br#"{"schema_version":2,"bounds":{"x":0,"y":0,"width":850,"height":603}}"#,
        br#"{"schema_version":1,"bounds":{"x":0,"y":0,"width":0,"height":603}}"#,
        br#"{"schema_version":1,"bounds":{"x":1000001,"y":0,"width":850,"height":603}}"#,
    ];
    for bytes in cases {
        fs::write(&store.paths.window_state_file, bytes).expect("write malformed state");
        fs::set_permissions(
            &store.paths.window_state_file,
            fs::Permissions::from_mode(0o600),
        )
        .expect("set file mode");
        assert!(store.window_bounds().is_err(), "accepted {bytes:?}");
    }

    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn symlink_and_hard_link_window_state_are_rejected() {
    let (root, store) = test_store("unsafe-window-state");
    store.ensure_layout().expect("create layout");
    let outside = root.join("outside-window-state");
    fs::write(&outside, b"{}").expect("write outside file");
    symlink(&outside, &store.paths.window_state_file).expect("create window state symlink");
    assert!(matches!(
        store.window_bounds(),
        Err(SettingsStoreError::UnsafeFile)
    ));
    fs::remove_file(&store.paths.window_state_file).expect("remove symlink");

    store
        .write_window_bounds(WindowBounds::new(0, 25, 850, 603).expect("valid bounds"))
        .expect("write window state");
    fs::hard_link(
        &store.paths.window_state_file,
        root.join("window-state-hard-link"),
    )
    .expect("create hard link");
    assert!(matches!(
        store.window_bounds(),
        Err(SettingsStoreError::UnsafeFile)
    ));

    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn window_bounds_constructor_rejects_unbounded_platform_values() {
    assert!(WindowBounds::new(0, 0, 0, 603).is_err());
    assert!(WindowBounds::new(0, 0, 850, 0).is_err());
    assert!(WindowBounds::new(0, 0, MAX_WINDOW_DIMENSION + 1, 603).is_err());
    assert!(WindowBounds::new(MAX_WINDOW_COORDINATE_MAGNITUDE + 1, 0, 850, 603).is_err());
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
        fs::write(&store.paths.preferences_file, bytes).expect("write malformed preferences");
        fs::set_permissions(
            &store.paths.preferences_file,
            fs::Permissions::from_mode(0o600),
        )
        .expect("set file mode");
        assert!(store.snapshot().is_err());
    }
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn oversized_preferences_are_rejected_before_json_parsing() {
    let (root, store) = test_store("oversized");
    store.ensure_layout().expect("create layout");
    fs::write(
        &store.paths.preferences_file,
        vec![b' '; MAX_PREFERENCES_BYTES + 1],
    )
    .expect("write oversized preferences");
    fs::set_permissions(
        &store.paths.preferences_file,
        fs::Permissions::from_mode(0o600),
    )
    .expect("set file mode");
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
fn concurrent_window_state_readers_never_observe_partial_json() {
    let (root, store) = test_store("concurrent-window-state");
    store
        .write_window_bounds(WindowBounds::new(0, 25, 850, 603).expect("initial bounds"))
        .expect("write initial window state");
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(2));
    let writer_store = Arc::clone(&store);
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for index in 0..24 {
            writer_store
                .write_window_bounds(
                    WindowBounds::new(index * 10, 25, 850 + index as u32, 603)
                        .expect("valid concurrent bounds"),
                )
                .expect("atomic window state write");
        }
    });
    barrier.wait();
    for _ in 0..64 {
        let bounds = store
            .window_bounds()
            .expect("complete window state")
            .expect("window bounds");
        assert!(bounds.width >= 850);
        assert_eq!(bounds.height, 603);
    }
    writer.join().expect("writer thread");
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn app_paths_separate_new_json_from_legacy_yaml() {
    let paths = MacOsAppPaths::for_user_home("/Users/example");
    assert_eq!(
        paths
            .preferences_file
            .file_name()
            .and_then(|name| name.to_str()),
        Some(PREFERENCES_FILE_NAME)
    );
    assert_eq!(
        paths
            .legacy_settings_file
            .file_name()
            .and_then(|name| name.to_str()),
        Some(LEGACY_SETTINGS_FILE_NAME)
    );
    assert_eq!(
        paths
            .window_state_file
            .file_name()
            .and_then(|name| name.to_str()),
        Some(WINDOW_STATE_FILE_NAME)
    );
}
