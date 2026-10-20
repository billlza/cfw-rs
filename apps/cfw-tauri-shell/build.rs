//! Select the native build adapter without importing another platform's SDK.
#[cfg(target_os = "macos")]
#[path = "build_support/macos.rs"]
mod macos;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").expect("Cargo target OS is required");
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo target architecture is required");
    match (target_os.as_str(), target_arch.as_str()) {
        ("macos", "aarch64") => {
            #[cfg(target_os = "macos")]
            macos::build();
            #[cfg(not(target_os = "macos"))]
            panic!("the macOS application requires its native Apple build host");
        }
        ("windows", "x86_64") => {
            if std::env::var("PROFILE").as_deref() == Ok("release") {
                panic!("Windows release packaging and signing admission are not implemented");
            }
            for feature in [
                "CARGO_FEATURE_NATIVE_UI",
                "CARGO_FEATURE_PHYSICAL_RELEASE_EVIDENCE",
            ] {
                if std::env::var_os(feature).is_some() {
                    panic!("{feature} requires the macOS native presentation/evidence adapter");
                }
            }
            tauri_build::build();
        }
        _ => panic!("unsupported desktop target: {target_arch}-{target_os}"),
    }
}
