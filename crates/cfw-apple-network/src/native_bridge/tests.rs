use super::*;
use crate::native_bridge::fake_native::fake_bridge;

#[test]
fn a_test_process_has_no_signed_framework_to_load() {
    let bridge = NativeFrameworkBridge::load();
    assert!(!bridge.is_available());
    let reason = bridge.unavailable_reason().expect("unavailable reason");
    assert!(
        reason.starts_with("signed native bridge framework could not be loaded: "),
        "{reason}"
    );
    assert_eq!(
        format!("{bridge:?}"),
        "NativeFrameworkBridge { available: false, .. }"
    );
}

#[test]
fn a_loaded_framework_is_available_without_a_reason() {
    let bridge = fake_bridge();
    assert!(bridge.is_available());
    assert_eq!(bridge.unavailable_reason(), None);
    assert_eq!(
        format!("{bridge:?}"),
        "NativeFrameworkBridge { available: true, .. }"
    );
}
