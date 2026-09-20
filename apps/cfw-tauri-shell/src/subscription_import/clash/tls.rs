//! Shared Clash TLS fields and protocol-specific compatibility.
use super::{ProxyFields, Value, build_tls_parts, json, parse_utls, tls_json};

/// TLS-related keys shared by the TLS-capable proxy types.
pub(super) struct TlsFields {
    enabled_flag: Option<bool>,
    server_name: Option<String>,
    alpn: Vec<String>,
    client_fingerprint: Option<String>,
    reality: Option<(String, String)>,
    certificate_pin: Option<String>,
}

pub(super) fn collect_tls(fields: &mut ProxyFields) -> Result<TlsFields, String> {
    let certificate_pin = fields
        .take_string("fingerprint")?
        .filter(|value| !value.is_empty())
        .map(|value| super::super::tls::certificate_fingerprint(&value))
        .transpose()?;
    let enabled_flag = fields.take_bool("tls")?;
    let servername = fields
        .take_string("servername")?
        .filter(|value| !value.is_empty());
    let sni = fields.take_string("sni")?.filter(|value| !value.is_empty());
    let server_name = match (servername, sni) {
        (Some(a), Some(b)) if a != b => {
            return Err(format!(
                "{} declares conflicting servername and sni values",
                fields.context()
            ));
        }
        (a, b) => a.or(b),
    };
    let alpn = fields.take_string_list("alpn")?.unwrap_or_default();
    let client_fingerprint = fields.take_string("client-fingerprint")?;
    let reality = match fields.take("reality-opts") {
        None => None,
        Some(value) => {
            let mut reality = ProxyFields::from_nested(value, fields, "reality-opts")?;
            let public_key = reality.require_string("public-key")?;
            let short_id = reality.take_string("short-id")?.unwrap_or_default();
            reality.reject_leftovers()?;
            Some((public_key, short_id))
        }
    };
    Ok(TlsFields {
        certificate_pin,
        enabled_flag,
        server_name,
        alpn,
        client_fingerprint,
        reality,
    })
}

impl TlsFields {
    /// TLS object for proxy types where TLS is optional (vmess, vless).
    pub(super) fn into_optional_json(
        self,
        context: &str,
        server: &str,
        reality_allowed: bool,
    ) -> Result<Option<Value>, String> {
        if self.reality.is_some() {
            if !reality_allowed {
                return Err(format!("{context} does not support Reality"));
            }
            if self.enabled_flag != Some(true) {
                return Err(format!("{context} declares reality-opts without tls: true"));
            }
        }
        if self.enabled_flag != Some(true) {
            if self.certificate_pin.is_some() {
                return Err(format!("{context} certificate pin requires TLS"));
            }
            // Without TLS, servername/alpn/client-fingerprint have no wire
            // effect in Clash either; dropping them preserves semantics.
            return Ok(None);
        }
        self.build(server).map(Some)
    }

    /// TLS object for always-TLS stream protocols that allow uTLS but not Reality.
    pub(super) fn into_required_json(self, context: &str, server: &str) -> Result<Value, String> {
        self.into_required_json_with_capabilities(context, server, true, false)
    }

    pub(super) fn into_quic_required_json(
        self,
        context: &str,
        server: &str,
    ) -> Result<Value, String> {
        self.into_required_json_with_capabilities(context, server, false, false)
    }

    pub(super) fn into_anytls_required_json(
        self,
        context: &str,
        server: &str,
    ) -> Result<Value, String> {
        self.into_required_json_with_capabilities(context, server, true, true)
    }

    pub(super) fn into_required_json_with_capabilities(
        self,
        context: &str,
        server: &str,
        utls_allowed: bool,
        reality_allowed: bool,
    ) -> Result<Value, String> {
        if self.reality.is_some() && !reality_allowed {
            return Err(format!("{context} does not support Reality"));
        }
        if self.client_fingerprint.is_some() && !utls_allowed {
            return Err(format!("{context} does not support uTLS"));
        }
        if self.enabled_flag == Some(false) {
            return Err(format!(
                "{context} declares tls: false for an always-TLS proxy type"
            ));
        }
        self.build(server)
    }

    fn build(self, server: &str) -> Result<Value, String> {
        let utls = match self.client_fingerprint.as_deref() {
            None => None,
            Some(fingerprint) => parse_utls(fingerprint)?,
        };
        let reality = self.reality.map(|(public_key, short_id)| {
            json!({
                "enabled": true,
                "public_key": public_key,
                "short_id": short_id,
            })
        });
        let mut tls = tls_json(build_tls_parts(
            true,
            self.server_name.unwrap_or_else(|| server.to_owned()),
            self.alpn,
            utls,
            reality,
        ));
        if let Some(pin) = self.certificate_pin {
            tls["certificate_sha256"] = json!([pin]);
        }
        Ok(tls)
    }
}
