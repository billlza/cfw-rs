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
            minimum_os_version: minimum_os_version(std::env::consts::OS),
            architecture: release_architecture(std::env::consts::ARCH),
        }
    }
}

/// The oldest system release this build is qualified on, for the system it
/// was built for.
fn minimum_os_version(operating_system: &str) -> Option<&'static str> {
    (operating_system == "macos").then_some("15.0")
}

/// The architecture name the release artifacts use.
fn release_architecture(architecture: &'static str) -> &'static str {
    match architecture {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        architecture => architecture,
    }
}

#[cfg(test)]
mod tests;
