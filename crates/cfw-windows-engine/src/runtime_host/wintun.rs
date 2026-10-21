//! The official driver image is pinned in the runtime itself. An installation
//! manifest cannot authorize another DLL, version or path.
use super::{HostError, Result, manifest::Manifest};

pub(crate) struct WintunImagePin {
    pub version: &'static str,
    pub sha256: &'static str,
}
impl WintunImagePin {
    pub fn digest(&self) -> Result<[u8; 32]> {
        Manifest::digest(self.sha256)
    }
}

pub(crate) fn image_pin() -> Result<WintunImagePin> {
    const PINS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/dependency_pins.env"
    ));
    decode(PINS)
}

fn decode(pins: &'static str) -> Result<WintunImagePin> {
    let read = |prefix: &str| {
        let mut values = pins.lines().filter_map(|line| line.strip_prefix(prefix));
        let value = values.next().ok_or(HostError::Manifest)?;
        if values.next().is_some() || value.is_empty() {
            return Err(HostError::Manifest);
        }
        Ok(value)
    };
    let version = read("WINTUN_VERSION=")?;
    let sha256 = read("WINTUN_WINDOWS_AMD64_SHA256=")?;
    if !semver::Version::parse(version).is_ok_and(|value| {
        value.to_string() == version && value.pre.is_empty() && value.build.is_empty()
    }) {
        return Err(HostError::Manifest);
    }
    Manifest::digest(sha256)?;
    Ok(WintunImagePin { version, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_image_pin_is_the_official_x64_distribution() {
        let pin = image_pin().unwrap();
        assert_eq!(pin.version, "0.14.1");
        assert_eq!(
            pin.sha256,
            "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
        );
        assert_eq!(pin.digest().unwrap(), Manifest::digest(pin.sha256).unwrap());
    }

    #[test]
    fn missing_ambiguous_and_noncanonical_compiled_pins_are_rejected() {
        for pins in [
            "",
            "WINTUN_VERSION=0.14.1\n",
            "WINTUN_VERSION=0.14.1\nWINTUN_VERSION=0.14.1\n",
            "WINTUN_VERSION=0.14.1\nWINTUN_WINDOWS_AMD64_SHA256=invalid\n",
            "WINTUN_VERSION=01.14.1\nWINTUN_WINDOWS_AMD64_SHA256=e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce\n",
        ] {
            assert!(decode(pins).is_err());
        }
    }
}
