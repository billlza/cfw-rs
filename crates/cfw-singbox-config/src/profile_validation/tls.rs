//! TLS trust, name, protocol and handshake option validation.
use super::{unsupported_shape, validate_server_name};
use crate::{
    ConfigError,
    profile::{OutboundTls, TlsCurve, TlsMinimumVersion},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use std::collections::BTreeSet;
const MAX_ALPN_ENTRIES: usize = 8;

impl OutboundTls {
    pub(crate) fn validate(&self, path: &str) -> Result<(), ConfigError> {
        let certificates = &self.certificate_sha256;
        let keys = &self.certificate_public_key_sha256;
        if !certificates.is_empty() || !keys.is_empty() {
            if !self.enabled
                || self.reality.is_some()
                || (!certificates.is_empty() && !keys.is_empty())
            {
                return Err(unsupported_shape(
                    path,
                    "certificate pinning requires TLS, one pin kind, and no Reality",
                ));
            }
            let pins = if certificates.is_empty() {
                keys
            } else {
                certificates
            };
            if pins.len() > 8
                || pins.iter().collect::<BTreeSet<_>>().len() != pins.len()
                || pins.iter().any(|pin| {
                    !STANDARD
                        .decode(pin)
                        .is_ok_and(|bytes| bytes.len() == 32 && STANDARD.encode(&bytes) == *pin)
                })
            {
                return Err(unsupported_shape(
                    path,
                    "TLS pins must be one to eight distinct SHA256 values in canonical base64",
                ));
            }
        }
        validate_server_name(&self.server_name, &format!("{path}.tls.server_name"))?;
        if self.alpn.len() > MAX_ALPN_ENTRIES
            || self.alpn.iter().any(|alpn| {
                alpn.is_empty()
                    || alpn.len() > 32
                    || alpn.bytes().any(|byte| !byte.is_ascii_graphic())
            })
        {
            return Err(unsupported_shape(
                format!("{path}.tls.alpn"),
                "ALPN list is oversized or contains an invalid token",
            ));
        }
        if !self.enabled
            && (!self.alpn.is_empty()
                || self.utls.is_some()
                || self.reality.is_some()
                || self.ech.is_some()
                || !self.curve_preferences.is_empty()
                || self.min_version == TlsMinimumVersion::Tls13)
        {
            return Err(unsupported_shape(
                format!("{path}.tls.enabled"),
                "TLS options require enabled TLS",
            ));
        }
        if self.curve_preferences.len() > 5
            || self.curve_preferences.iter().collect::<BTreeSet<_>>().len()
                != self.curve_preferences.len()
        {
            return Err(unsupported_shape(
                path,
                "TLS curves must be unique and supported",
            ));
        }
        if !self.curve_preferences.is_empty() && (self.utls.is_some() || self.reality.is_some()) {
            return Err(unsupported_shape(
                path,
                "explicit key-exchange curves require standard TLS; this runtime's uTLS and Reality adapters do not apply them",
            ));
        }
        if self.curve_preferences == [TlsCurve::X25519MLKEM768]
            && self.min_version != TlsMinimumVersion::Tls13
        {
            return Err(unsupported_shape(
                path,
                "requiring X25519MLKEM768 also requires TLS 1.3 to prevent a classical TLS 1.2 downgrade",
            ));
        }
        if let Some(ech) = &self.ech {
            if !ech.enabled
                || self.reality.is_some()
                || self.min_version != TlsMinimumVersion::Tls13
            {
                return Err(unsupported_shape(
                    path,
                    "ECH must be enabled with TLS 1.3 and cannot be combined with Reality",
                ));
            }
            let pem = ech.config.join("\n");
            let payload = pem
                .strip_prefix("-----BEGIN ECH CONFIGS-----\n")
                .and_then(|value| {
                    value
                        .trim_end_matches('\n')
                        .strip_suffix("\n-----END ECH CONFIGS-----")
                })
                .ok_or_else(|| {
                    unsupported_shape(path, "ECH requires an inline ECH CONFIGS PEM block")
                })?;
            if pem.len() > 16_384 || ech.config.len() > 256 {
                return Err(unsupported_shape(path, "ECH config exceeds its size bound"));
            }
            let bytes = STANDARD
                .decode(payload.replace('\n', ""))
                .map_err(|_| unsupported_shape(path, "ECH config contains invalid base64"))?;
            if bytes.len() < 6
                || usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) != bytes.len() - 2
            {
                return Err(unsupported_shape(path, "ECHConfigList length is invalid"));
            }
        }
        if self.utls.as_ref().is_some_and(|utls| !utls.enabled) {
            return Err(unsupported_shape(
                format!("{path}.tls.utls.enabled"),
                "uTLS options must be explicitly enabled when present",
            ));
        }
        if let Some(reality) = &self.reality
            && (!reality.enabled
                || reality.public_key.len() != 43
                || !is_valid_reality_public_key(&reality.public_key)
                || reality.short_id.len() > 16
                || reality.short_id.len() % 2 != 0
                || !reality
                    .short_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(unsupported_shape(
                format!("{path}.tls.reality"),
                "Reality public_key or short_id is invalid",
            ));
        }
        Ok(())
    }
}

fn is_valid_reality_public_key(value: &str) -> bool {
    matches!(URL_SAFE_NO_PAD.decode(value), Ok(key) if key.len() == 32)
}
