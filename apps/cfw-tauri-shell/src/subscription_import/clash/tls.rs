//! Shared Clash TLS fields and protocol-specific compatibility.
use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::{
    ProxyFields, UtlsFingerprint, Value, build_tls_parts, json, parse_utls_fingerprint, tls_json,
    utls_json,
};

const GLOBAL_CLIENT_FINGERPRINT: &str = "global-client-fingerprint";

/// Takes Mihomo's top-level `global-client-fingerprint`, the uTLS
/// fingerprint that Mihomo before v1.19.27 gave every TLS VMess, VLESS,
/// Trojan and AnyTLS node without a non-empty `client-fingerprint`. `none`,
/// an empty value and null set no fingerprint; any other value must be a
/// supported one even when no node would use it.
pub(super) fn take_global_client_fingerprint(
    root: &mut ProxyFields,
) -> Result<Option<UtlsFingerprint>, String> {
    let Some(value) = root.take_string(GLOBAL_CLIENT_FINGERPRINT)? else {
        return Ok(None);
    };
    if value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    parse_utls_fingerprint(&value)
        .map_err(|error| format!("{}.{GLOBAL_CLIENT_FINGERPRINT}: {error}", root.context()))
}

/// TLS-related keys shared by the TLS-capable proxy types.
pub(super) struct TlsFields {
    enabled_flag: Option<bool>,
    server_name: Option<String>,
    alpn: Vec<String>,
    client_fingerprint: Option<String>,
    reality: Option<RealityFields>,
    certificate_pin: Option<String>,
    /// Inline `ech-opts` config as sing-box ECH CONFIGS PEM lines.
    ech_config: Option<Vec<String>>,
}

/// Clash `reality-opts`, named after the mihomo keys they come from.
struct RealityFields {
    public_key: String,
    short_id: String,
    support_x25519mlkem768: bool,
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
            let support_x25519mlkem768 = reality
                .take_bool("support-x25519mlkem768")?
                .unwrap_or(false);
            reality.reject_leftovers()?;
            Some(RealityFields {
                public_key,
                short_id,
                support_x25519mlkem768,
            })
        }
    };
    let ech_config = match fields.take("ech-opts") {
        None => None,
        Some(value) => {
            let context = format!("{}.ech-opts", fields.context());
            let mut ech = ProxyFields::from_nested(value, fields, "ech-opts")?;
            let enabled = ech.take_bool("enable")?.unwrap_or(false);
            let config = ech.take_string("config")?.filter(|value| !value.is_empty());
            let query_server_name = ech
                .take_string("query-server-name")?
                .filter(|value| !value.is_empty());
            ech.reject_leftovers()?;
            // Mihomo fetches the config over DNS when it is absent, a lookup
            // that censors can block or forge; only an inline config is used.
            match (enabled, config, query_server_name) {
                (false, None, None) => None,
                (false, ..) => {
                    return Err(format!(
                        "{context} is disabled but carries a config or query-server-name"
                    ));
                }
                (true, _, Some(_)) => {
                    return Err(format!(
                        "{context} query-server-name is unsupported: ECH configs are never fetched over DNS"
                    ));
                }
                (true, None, None) => {
                    return Err(format!(
                        "{context} requires an inline config; ECH configs are never fetched over DNS"
                    ));
                }
                (true, Some(config), None) => Some(ech_config_pem_lines(&config, &context)?),
            }
        }
    };
    Ok(TlsFields {
        certificate_pin,
        enabled_flag,
        server_name,
        alpn,
        client_fingerprint,
        reality,
        ech_config,
    })
}

/// Re-encodes Mihomo's base64 ECHConfigList as the line-split ECH CONFIGS PEM
/// block that sing-box reads; the profile model checks the list itself.
fn ech_config_pem_lines(config: &str, context: &str) -> Result<Vec<String>, String> {
    let list = STANDARD
        .decode(config)
        .map_err(|_| format!("{context}.config is not standard base64"))?;
    let encoded = STANDARD.encode(list);
    let mut lines = vec!["-----BEGIN ECH CONFIGS-----".to_owned()];
    lines.extend(
        encoded
            .as_bytes()
            .chunks(64)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned()),
    );
    lines.push("-----END ECH CONFIGS-----".to_owned());
    Ok(lines)
}

impl TlsFields {
    /// TLS object for proxy types where TLS is optional (http, vmess, vless).
    /// `inherited` is the document's global fingerprint for the types Mihomo
    /// gave it to, and `None` for the others.
    pub(super) fn into_optional_json(
        self,
        context: &str,
        server: &str,
        reality_allowed: bool,
        inherited: Option<UtlsFingerprint>,
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
            if self.ech_config.is_some() {
                return Err(format!("{context} ECH requires TLS"));
            }
            // Without TLS, servername/alpn/client-fingerprint have no wire
            // effect in Clash either; dropping them preserves semantics.
            return Ok(None);
        }
        self.build(server, inherited).map(Some)
    }

    /// TLS object for always-TLS stream protocols that allow uTLS but not Reality.
    pub(super) fn into_required_json(
        self,
        context: &str,
        server: &str,
        inherited: Option<UtlsFingerprint>,
    ) -> Result<Value, String> {
        self.into_required_json_with_capabilities(context, server, true, false, inherited)
    }

    /// QUIC TLS has no uTLS, so these types never inherit a fingerprint.
    pub(super) fn into_quic_required_json(
        self,
        context: &str,
        server: &str,
    ) -> Result<Value, String> {
        self.into_required_json_with_capabilities(context, server, false, false, None)
    }

    pub(super) fn into_anytls_required_json(
        self,
        context: &str,
        server: &str,
        inherited: Option<UtlsFingerprint>,
    ) -> Result<Value, String> {
        self.into_required_json_with_capabilities(context, server, true, true, inherited)
    }

    fn into_required_json_with_capabilities(
        self,
        context: &str,
        server: &str,
        utls_allowed: bool,
        reality_allowed: bool,
        inherited: Option<UtlsFingerprint>,
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
        self.build(server, inherited)
    }

    fn build(self, server: &str, inherited: Option<UtlsFingerprint>) -> Result<Value, String> {
        // Mihomo used the global value only in place of an empty one; its own
        // `none` keeps standard TLS whatever the document sets globally.
        let fingerprint = match self.client_fingerprint.as_deref() {
            None | Some("") => inherited,
            Some(own) if own.eq_ignore_ascii_case("none") => None,
            Some(own) => parse_utls_fingerprint(own)?,
        };
        let reality = self.reality.map(|reality| {
            let mut value = json!({
                "enabled": true,
                "public_key": reality.public_key,
                "short_id": reality.short_id,
            });
            if reality.support_x25519mlkem768 {
                value["support_x25519mlkem768"] = json!(true);
            }
            value
        });
        let mut tls = tls_json(build_tls_parts(
            true,
            self.server_name.unwrap_or_else(|| server.to_owned()),
            self.alpn,
            fingerprint.map(utls_json),
            reality,
        ));
        if let Some(pin) = self.certificate_pin {
            tls["certificate_sha256"] = json!([pin]);
        }
        if let Some(lines) = self.ech_config {
            // ECH exists only in TLS 1.3, which the profile states explicitly.
            tls["min_version"] = json!("1.3");
            tls["ech"] = json!({"enabled": true, "config": lines});
        }
        Ok(tls)
    }
}
