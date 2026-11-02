use super::*;

#[cfg(target_os = "macos")]
#[test]
fn mac_product_preserves_the_ga_wire_identity() {
    assert_eq!(
        serde_json::to_value(DesktopProductInfo::current()).unwrap(),
        serde_json::json!({
            "name": "Clash for Mac",
            "version": env!("CARGO_PKG_VERSION"),
            "license": "GPL-3.0-or-later",
            "operating_system": "macos",
            "minimum_os_version": "15.0",
            "architecture": "arm64",
        }),
    );
}

#[cfg(windows)]
#[test]
fn windows_product_never_advertises_apple_identity_or_unqualified_os_support() {
    let value = serde_json::to_value(DesktopProductInfo::current()).unwrap();
    assert_eq!(value["name"], "Clash for Windows");
    assert_eq!(value["operating_system"], "windows");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["license"], "GPL-3.0-or-later");
    assert!(value["minimum_os_version"].is_null());
    assert_eq!(value.as_object().unwrap().len(), 6);
    assert_eq!(
        value["architecture"],
        match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            _ => panic!("unqualified Windows desktop architecture"),
        },
    );
}

#[test]
fn release_names_cover_every_architecture_and_system() {
    assert_eq!(release_architecture("aarch64"), "arm64");
    assert_eq!(release_architecture("x86_64"), "x64");
    // An unqualified architecture keeps its own name rather than borrowing one.
    assert_eq!(release_architecture("riscv64"), "riscv64");
    assert_eq!(minimum_os_version("macos"), Some("15.0"));
    assert_eq!(minimum_os_version("windows"), None);
}
