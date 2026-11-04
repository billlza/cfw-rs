//! A source outbound's TLS and transport options, as the profile's.

use serde_json::{Value, json};

use super::source::{SourceTls, SourceTransport, StringList};
use super::{TlsParts, build_tls_parts, parse_utls, tls_json};

pub(super) fn source_tls(tls: SourceTls, server: &str, required: bool) -> Result<Value, String> {
    if required && !tls.enabled {
        return Err("sing-box outbound requires enabled TLS".into());
    }
    // Upstream verifies a public-key pin whether or not `insecure` is set,
    // so beside a pin the flag asks for nothing more: the pin is the node's
    // only trust anchor, the name, validity and server-auth checks remain,
    // and the flag is never stored. Without a pin it fails closed.
    if tls.insecure
        && tls.certificate_sha256.is_empty()
        && tls.certificate_public_key_sha256.is_empty()
    {
        return Err("sing-box outbound requires disabling TLS certificate verification".into());
    }
    if tls.disable_sni {
        return Err("sing-box outbound disables SNI, which is unsupported".into());
    }
    if !matches!(tls.min_version.as_str(), "" | "1.2" | "1.3") {
        return Err("sing-box TLS min_version cannot be represented exactly".into());
    }
    let utls = match tls.utls {
        None => None,
        Some(utls) if !utls.enabled && utls.fingerprint.is_empty() => None,
        Some(utls) if utls.enabled => Some(
            parse_utls(&utls.fingerprint)?
                .ok_or_else(|| "enabled sing-box uTLS requires a fingerprint".to_owned())?,
        ),
        Some(_) => return Err("disabled sing-box uTLS contains active options".into()),
    };
    let reality = match tls.reality {
        None => None,
        Some(reality)
            if !reality.enabled
                && reality.public_key.is_empty()
                && reality.short_id.is_empty()
                && !reality.support_x25519mlkem768 =>
        {
            None
        }
        Some(reality) if reality.enabled => {
            let mut value = json!({
                "enabled": true,
                "public_key": reality.public_key,
                "short_id": reality.short_id,
            });
            if reality.support_x25519mlkem768 {
                value["support_x25519mlkem768"] = json!(true);
            }
            Some(value)
        }
        Some(_) => return Err("disabled sing-box Reality contains active options".into()),
    };
    let mut value = tls_json(TlsParts {
        certificate_sha256: tls.certificate_sha256,
        ..build_tls_parts(
            true,
            if tls.server_name.is_empty() {
                server.to_owned()
            } else {
                tls.server_name
            },
            tls.alpn.into_vec(),
            utls,
            reality,
        )
    });
    if !tls.min_version.is_empty() {
        value["min_version"] = json!(tls.min_version);
    }
    if !tls.certificate_public_key_sha256.is_empty() {
        value["certificate_public_key_sha256"] = json!(tls.certificate_public_key_sha256);
    }
    if !tls.curve_preferences.is_empty() {
        value["curve_preferences"] = json!(tls.curve_preferences);
    }
    if let Some(ech) = tls.ech {
        value["ech"] = json!({"enabled": ech.enabled, "config": ech.config.into_vec()});
    }
    Ok(value)
}

impl SourceTls {
    pub(super) fn has_disabled_semantics(&self) -> bool {
        !self.server_name.is_empty()
            || !self.certificate_sha256.is_empty()
            || !self.certificate_public_key_sha256.is_empty()
            || self.insecure
            || self.disable_sni
            || !matches!(self.alpn, StringList::Empty)
            || !self.min_version.is_empty()
            || self.utls.is_some()
            || self.reality.is_some()
            || !self.curve_preferences.is_empty()
            || self.ech.is_some()
    }
}

pub(super) fn insert_transport(
    outbound: &mut Value,
    transport: Option<SourceTransport>,
) -> Result<(), String> {
    let Some(transport) = transport else {
        return Ok(());
    };
    outbound["transport"] = match transport {
        SourceTransport::Http {
            path,
            host,
            method,
            mut headers,
        } => {
            let explicit_host = host.into_vec();
            let upper_host = headers.remove("Host").map(StringList::into_vec);
            let lower_host = headers.remove("host").map(StringList::into_vec);
            let header_host = match (upper_host, lower_host) {
                (Some(a), Some(b)) if a != b => {
                    return Err("sing-box HTTP transport declares conflicting Host headers".into());
                }
                (a, b) => a.or(b).unwrap_or_default(),
            };
            if !headers.is_empty() {
                return Err("sing-box HTTP headers other than Host are unsupported".into());
            }
            let host = match (explicit_host.is_empty(), header_host.is_empty()) {
                (false, false) if explicit_host != header_host => {
                    return Err(
                        "sing-box HTTP transport declares conflicting host authorities".into(),
                    );
                }
                (false, _) => explicit_host,
                (true, _) => header_host,
            };
            let mut value = json!({
                "type": "http",
                "path": path,
                "host": host,
            });
            if !method.is_empty() {
                value["method"] = Value::String(super::normalize_v2ray_http_method(
                    &method,
                    "sing-box HTTP method",
                )?);
            }
            value
        }
        SourceTransport::Websocket { path, mut headers } => {
            let host = headers.remove("Host").or_else(|| headers.remove("host"));
            if !headers.is_empty() {
                return Err("sing-box WebSocket headers other than Host are unsupported".into());
            }
            let mut value = json!({ "type": "ws", "path": path });
            if let Some(host) = host {
                value["headers"] = json!({ "Host": host });
            }
            value
        }
        SourceTransport::Grpc { service_name } => json!({
            "type": "grpc",
            "service_name": service_name,
        }),
        SourceTransport::Quic => json!({ "type": "quic" }),
        SourceTransport::HttpUpgrade {
            path,
            host,
            headers,
        } => {
            if !headers.is_empty() {
                return Err("sing-box HTTPUpgrade custom headers are unsupported".into());
            }
            let mut value = json!({ "type": "http_upgrade", "path": path });
            if !host.is_empty() {
                value["host"] = Value::String(host);
            }
            value
        }
    };
    Ok(())
}
