use serde::Serialize;

/// Build identity for the shared desktop, not a runtime or release admission.
#[derive(Debug, Clone, Serialize)]
pub struct DesktopProductInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub license: &'static str,
    pub operating_system: &'static str,
    /// None means no minimum release support claim has been qualified yet.
    pub minimum_os_version: Option<&'static str>,
    pub architecture: &'static str,
}

impl DesktopProductInfo {
    pub fn current() -> Self {
        Self {
            name: crate::PRODUCT_NAME,
            version: env!("CARGO_PKG_VERSION"),
            license: env!("CARGO_PKG_LICENSE"),
            operating_system: std::env::consts::OS,
            minimum_os_version: if cfg!(target_os = "macos") {
                Some("15.0")
            } else {
                None
            },
            architecture: match std::env::consts::ARCH {
                "aarch64" => "arm64",
                "x86_64" => "x64",
                architecture => architecture,
            },
        }
    }
}

#[cfg(test)]
mod tests {
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
}
