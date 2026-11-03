//! The documents beside the preferences: the runtime settings and their
//! compare-and-swap, the automation settings kept apart from them, and the
//! legacy retirement marker's exact bytes.

use super::*;

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
fn the_retirement_marker_must_hold_its_exact_bytes() {
    let (root, store) = test_store("marker");
    store.commit_legacy_retirement().unwrap();
    assert!(store.legacy_retirement_completed().unwrap());
    let marker = store.paths.app_home.join(RETIREMENT_MARKER_FILE_NAME);
    let altered = br#"{"schema_version":1,"completed":tru3}"#;
    assert_eq!(altered.len(), RETIREMENT_MARKER_BYTES.len());
    write_private(&marker, altered);
    assert!(matches!(
        store.legacy_retirement_completed(),
        Err(SettingsStoreError::NonCanonicalJson)
    ));
    write_private(&marker, br#"{"schema_version":1,"completed":false}"#);
    assert!(matches!(
        store.legacy_retirement_completed(),
        Err(SettingsStoreError::TooLarge { .. })
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn automation_settings_live_apart_from_runtime_settings() {
    let (root, store) = test_store("automation");
    let empty = store
        .automation_settings::<std::collections::BTreeMap<String, u16>>()
        .unwrap();
    assert!(empty.settings.is_empty());
    assert!(empty.revision.is_none());
    let rules = std::collections::BTreeMap::from([("wifi".to_owned(), 1)]);
    store
        .compare_and_swap_automation_settings(None, &rules)
        .unwrap();
    let stored = store
        .automation_settings::<std::collections::BTreeMap<String, u16>>()
        .unwrap();
    assert_eq!(stored.settings, rules);
    assert!(stored.revision.is_some());
    assert!(matches!(
        store.compare_and_swap_automation_settings(None, &rules),
        Err(SettingsStoreError::RuntimeSettingsChanged)
    ));
    assert!(
        store
            .runtime_settings::<std::collections::BTreeMap<String, u16>>()
            .unwrap()
            .revision
            .is_none()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn runtime_settings_of_another_schema_or_in_other_bytes_are_refused() {
    let (root, store) = test_store("runtime-schema");
    store.ensure_layout().unwrap();
    let file = store.paths.app_home.join("cfw-runtime-settings.json");
    write_private(&file, br#"{"schema_version":2,"settings":{}}"#);
    assert!(matches!(
        store.runtime_settings::<std::collections::BTreeMap<String, u16>>(),
        Err(SettingsStoreError::UnsupportedSchema(2))
    ));
    write_private(&file, br#"{"schema_version":1, "settings":{}}"#);
    assert!(matches!(
        store.runtime_settings::<std::collections::BTreeMap<String, u16>>(),
        Err(SettingsStoreError::NonCanonicalJson)
    ));
    fs::remove_dir_all(root).unwrap();
}
