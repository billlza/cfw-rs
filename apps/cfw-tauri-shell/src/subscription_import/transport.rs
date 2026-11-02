//! The TLS and transport blocks of an imported outbound.

use cfw_singbox_config::UtlsFingerprint;
use serde_json::{Value, json};

use super::{non_empty, normalize_v2ray_http_method, sanitized_token, split_csv};

#[derive(Debug, Default)]
pub(super) struct TlsParts {
    pub(super) enabled: bool,
    pub(super) server_name: String,
    pub(super) alpn: Vec<String>,
    pub(super) utls: Option<Value>,
    pub(super) reality: Option<Value>,
    /// Canonical base64 SHA-256 values of the server's DER leaf certificate.
    pub(super) certificate_sha256: Vec<String>,
}

pub(super) fn parse_utls(value: &str) -> Result<Option<Value>, String> {
    Ok(parse_utls_fingerprint(value)?.map(utls_json))
}

/// Maps a case-insensitive uTLS name onto the runtime's preset set; an empty
/// name requests no uTLS.
pub(super) fn parse_utls_fingerprint(value: &str) -> Result<Option<UtlsFingerprint>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    serde_json::from_value(Value::String(value.to_ascii_lowercase()))
        .map(Some)
        .map_err(|_| {
            format!(
                "uTLS fingerprint is unsupported: {}",
                sanitized_token(value)
            )
        })
}

pub(super) fn utls_json(fingerprint: UtlsFingerprint) -> Value {
    json!({
        "enabled": true,
        "fingerprint": fingerprint,
    })
}

pub(super) fn build_tls_parts(
    enabled: bool,
    server_name: String,
    alpn: Vec<String>,
    utls: Option<Value>,
    reality: Option<Value>,
) -> TlsParts {
    TlsParts {
        enabled,
        server_name,
        alpn,
        utls,
        reality,
        certificate_sha256: Vec::new(),
    }
}

pub(super) fn tls_json(tls: TlsParts) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("enabled".into(), Value::Bool(tls.enabled));
    object.insert("server_name".into(), Value::String(tls.server_name));
    if !tls.certificate_sha256.is_empty() {
        object.insert(
            "certificate_sha256".into(),
            Value::Array(
                tls.certificate_sha256
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if !tls.alpn.is_empty() {
        object.insert(
            "alpn".into(),
            Value::Array(tls.alpn.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(utls) = tls.utls {
        object.insert("utls".into(), utls);
    }
    if let Some(reality) = tls.reality {
        object.insert("reality".into(), reality);
    }
    Value::Object(object)
}

pub(super) fn transport_from_parts(
    kind: &str,
    path: Option<String>,
    host: Option<String>,
    service_name: Option<String>,
    method: Option<String>,
) -> Result<Option<Value>, String> {
    let normalized_kind = kind.to_ascii_lowercase();
    match normalized_kind.as_str() {
        "" | "tcp" | "none" => {
            if [
                path.as_deref(),
                host.as_deref(),
                service_name.as_deref(),
                method.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| !value.is_empty())
            {
                return Err("TCP subscription transport declares unsupported options".into());
            }
            Ok(None)
        }
        "http" | "h2" => {
            if service_name.as_ref().is_some_and(|value| !value.is_empty()) {
                return Err("HTTP subscription transport declares a gRPC service name".into());
            }
            let mut transport = json!({
                "type": "http",
                "path": path.unwrap_or_else(|| "/".into()),
                "host": host.map(|value| split_csv(&value)).unwrap_or_default(),
            });
            if let Some(method) = method.filter(|value| !value.is_empty()) {
                transport["method"] =
                    Value::String(normalize_v2ray_http_method(&method, "HTTP method")?);
            }
            Ok(Some(transport))
        }
        "ws" => {
            if [service_name.as_deref(), method.as_deref()]
                .into_iter()
                .flatten()
                .any(|value| !value.is_empty())
            {
                return Err(
                    "WebSocket subscription transport declares unsupported service or method options"
                        .into(),
                );
            }
            let path = path.unwrap_or_else(|| "/".into());
            let mut object = serde_json::Map::new();
            object.insert("type".into(), Value::String("ws".into()));
            object.insert("path".into(), Value::String(path));
            if let Some(host) = host
                && !host.is_empty()
            {
                object.insert("headers".into(), json!({ "Host": host }));
            }
            Ok(Some(Value::Object(object)))
        }
        "grpc" => {
            if [path.as_deref(), host.as_deref(), method.as_deref()]
                .into_iter()
                .flatten()
                .any(|value| !value.is_empty())
            {
                return Err(
                    "gRPC subscription transport declares HTTP path or host options".into(),
                );
            }
            Ok(Some(json!({
                "type": "grpc",
                "service_name": non_empty(service_name.unwrap_or_default())
                    .ok_or_else(|| "gRPC subscriptions require a non-empty serviceName".to_owned())?,
            })))
        }
        "quic" => {
            if [
                path.as_deref(),
                host.as_deref(),
                service_name.as_deref(),
                method.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| !value.is_empty())
            {
                return Err("QUIC subscription transport declares unsupported options".into());
            }
            Ok(Some(json!({ "type": "quic" })))
        }
        "httpupgrade" | "http-upgrade" => {
            if [service_name.as_deref(), method.as_deref()]
                .into_iter()
                .flatten()
                .any(|value| !value.is_empty())
            {
                return Err(
                    "HTTPUpgrade subscription transport declares unsupported service or method options"
                        .into(),
                );
            }
            let mut transport = json!({
                "type": "http_upgrade",
                "path": path.unwrap_or_else(|| "/".into()),
            });
            if let Some(host) = host.filter(|value| !value.is_empty()) {
                transport["host"] = Value::String(host);
            }
            Ok(Some(transport))
        }
        other => Err(format!(
            "subscription transport is unsupported: {}",
            sanitized_token(other)
        )),
    }
}
