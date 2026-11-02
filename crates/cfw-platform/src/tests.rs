use objc2_service_management::SMAppServiceStatus;

use super::*;

#[test]
fn every_service_management_status_maps_to_its_own_mode() {
    for (status, mode) in [
        (
            SMAppServiceStatus::NotRegistered,
            ServiceModeStatus::NotRegistered,
        ),
        (SMAppServiceStatus::Enabled, ServiceModeStatus::Enabled),
        (
            SMAppServiceStatus::RequiresApproval,
            ServiceModeStatus::RequiresApproval,
        ),
        (SMAppServiceStatus::NotFound, ServiceModeStatus::NotFound),
        // A status a later macOS adds is not mistaken for a known one.
        (SMAppServiceStatus(4), ServiceModeStatus::Unknown),
        (SMAppServiceStatus(-1), ServiceModeStatus::Unknown),
    ] {
        assert_eq!(map_service_status(status), mode, "{status:?}");
    }
}

#[test]
fn the_preferred_languages_are_language_tags() {
    let languages = preferred_languages().expect("preferred languages");
    assert!(!languages.is_empty());
    for language in &languages {
        assert!(
            !language.is_empty()
                && language
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-'),
            "{language}"
        );
    }
}
