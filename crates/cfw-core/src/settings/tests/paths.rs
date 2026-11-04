//! Where the settings live: the product's directory on each platform, the
//! current user's default paths, the separate locations of the JSON, the
//! legacy YAML and the profiles, and an invalid ancestor that is never taken
//! for a first launch.

use super::*;

#[test]
fn a_non_directory_ancestor_never_becomes_default_preferences() {
    let (root, store) = test_store("invalid-ancestor");
    fs::write(&root, b"preserved non-directory ancestor").unwrap();
    assert!(
        store.read_or_default().is_err(),
        "an invalid path is not a first launch"
    );
    assert_eq!(
        fs::read(&root).unwrap(),
        b"preserved non-directory ancestor"
    );
    fs::remove_file(root).unwrap();
}

#[test]
fn platform_application_path_preserves_the_product_directory() {
    #[cfg(target_os = "macos")]
    let paths = {
        let paths = AppPaths::for_user_home("/Users/path-contract");
        assert_eq!(
            paths.app_home,
            PathBuf::from("/Users/path-contract/Library/Application Support/Clash for Mac")
        );
        paths
    };
    #[cfg(windows)]
    let paths = {
        let paths = AppPaths::default_for_current_user().unwrap();
        assert!(paths.app_home.is_absolute());
        assert_eq!(paths.app_home.file_name().unwrap(), "Clash for Windows");
        paths
    };
    assert_eq!(
        paths.preferences_file,
        paths.app_home.join(PREFERENCES_FILE_NAME)
    );
    assert_eq!(
        paths.window_state_file,
        paths.app_home.join(WINDOW_STATE_FILE_NAME)
    );
}

#[test]
fn native_profile_staging_never_reuses_the_legacy_profile_directory() {
    let paths = AppPaths::from_app_home("/tmp/cfw-profile-path-contract");
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
fn app_paths_separate_new_json_from_legacy_yaml() {
    let paths = AppPaths::from_app_home(std::env::temp_dir().join("cfw-path-contract"));
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

#[cfg(target_os = "macos")]
#[test]
fn the_default_paths_belong_to_the_current_user() {
    let home = PathBuf::from(env::var_os("HOME").unwrap());
    assert_eq!(
        AppPaths::default_for_current_user().unwrap(),
        AppPaths::for_user_home(&home)
    );
    assert_eq!(
        SettingsStore::default_for_current_user().unwrap().paths(),
        &AppPaths::for_user_home(home)
    );
}
