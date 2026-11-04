//! TLS options of a remote outbound: the version floor, curves, ECH, uTLS
//! and Reality.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutboundTls {
    pub(crate) enabled: bool,
    pub(crate) server_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) certificate_sha256: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) certificate_public_key_sha256: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) alpn: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) utls: Option<UtlsOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reality: Option<RealityOptions>,
    #[serde(default, skip_serializing_if = "TlsMinimumVersion::is_default")]
    pub(crate) min_version: TlsMinimumVersion,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) curve_preferences: Vec<TlsCurve>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ech: Option<EchOptions>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TlsMinimumVersion {
    #[default]
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

impl TlsMinimumVersion {
    fn is_default(&self) -> bool {
        *self == Self::Tls12
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum TlsCurve {
    P256,
    P384,
    P521,
    X25519,
    X25519MLKEM768,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EchOptions {
    pub(crate) enabled: bool,
    /// Public ECHConfigList in PEM form. No filesystem or bootstrap DNS lookup.
    pub(crate) config: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UtlsOptions {
    pub(crate) enabled: bool,
    pub(crate) fingerprint: UtlsFingerprint,
}

/// uTLS ClientHello presets of the pinned runtime, by their sing-box names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UtlsFingerprint {
    Chrome,
    Firefox,
    Edge,
    Safari,
    #[serde(rename = "360")]
    Browser360,
    Qq,
    Ios,
    Android,
    Random,
    Randomized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RealityOptions {
    pub(crate) enabled: bool,
    pub(crate) public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) short_id: String,
    /// Offers the X25519MLKEM768 key share ahead of X25519, which REALITY
    /// servers since XTLS/REALITY 8cdf7bf require. Off by default because
    /// older servers may mishandle the hybrid share.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) support_x25519mlkem768: bool,
}
