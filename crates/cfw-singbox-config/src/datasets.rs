//! GeoIP and GeoSite datasets: the dataset-name grammar, the rule-set tags and
//! the one remote resource definition that routing and DNS projection share.

use serde_json::{Value, json};

/// The most distinct datasets one profile may reference. Each one is a
/// download before the engine first starts with the profile, so the bound
/// keeps that start finite; every ISO country code fits with room to spare.
pub(crate) const MAX_GEO_DATASETS: usize = 256;

const MAX_GEOSITE_CODE_BYTES: usize = 96;

/// A sing-geosite dataset name as SagerNet/sing-geosite publishes it: a list
/// name of lowercase ASCII letters, digits, `-` and `!` that starts with a
/// letter or digit, optionally followed by one `@attribute`, which may be
/// negated with `!` (`google@!cn`). The grammar admits no path, query or
/// fragment character, so the name is safe inside the download URL and the
/// rule-set tag.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct GeositeCode(String);

impl GeositeCode {
    pub(crate) fn parse(code: &str) -> Option<Self> {
        if code.is_empty() || code.len() > MAX_GEOSITE_CODE_BYTES {
            return None;
        }
        let (list, attribute) = match code.split_once('@') {
            Some((list, attribute)) => (list, Some(attribute)),
            None => (code, None),
        };
        let list_valid = starts_alphanumeric(list)
            && list
                .bytes()
                .all(|byte| is_lower_alphanumeric(byte) || matches!(byte, b'-' | b'!'));
        let attribute_valid = attribute.is_none_or(|attribute| {
            let name = attribute.strip_prefix('!').unwrap_or(attribute);
            starts_alphanumeric(name)
                && name
                    .bytes()
                    .all(|byte| is_lower_alphanumeric(byte) || byte == b'-')
        });
        (list_valid && attribute_valid).then(|| Self(code.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn starts_alphanumeric(text: &str) -> bool {
    text.bytes().next().is_some_and(is_lower_alphanumeric)
}

/// A sing-geoip dataset name: a two-letter country code, kept in lowercase
/// as SagerNet/sing-geoip names its sets. Route rules write the code in
/// uppercase and DNS policies in lowercase; both name the same set. The
/// grammar admits no path, query or fragment character, so the name is safe
/// inside the download URL and the rule-set tag.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CountryCode(String);

impl CountryCode {
    pub(crate) fn parse(code: &str) -> Option<Self> {
        (code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_alphabetic()))
            .then(|| Self(code.to_ascii_lowercase()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// One downloadable dataset. GeoIP sorts before GeoSite and each sorts by
/// name, which is the order projected resources keep.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Dataset {
    GeoIp(CountryCode),
    GeoSite(GeositeCode),
}

impl Dataset {
    pub(crate) fn tag(&self) -> String {
        match self {
            Self::GeoIp(country) => format!("cfw-geoip-{}", country.as_str()),
            Self::GeoSite(code) => format!("cfw-geosite-{}", code.as_str()),
        }
    }

    /// The remote rule set, downloaded through `download_outbound` and
    /// refreshed daily while the engine runs.
    pub(crate) fn resource(&self, download_outbound: &str) -> Value {
        let url = match self {
            Self::GeoIp(country) => format!(
                "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{}.srs",
                country.as_str()
            ),
            Self::GeoSite(code) => format!(
                "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs",
                code.as_str()
            ),
        };
        json!({
            "type": "remote",
            "tag": self.tag(),
            "format": "binary",
            "url": url,
            "download_detour": download_outbound,
            "update_interval": "1d",
        })
    }
}
