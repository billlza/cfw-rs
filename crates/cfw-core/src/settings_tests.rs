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
}
