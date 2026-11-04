//! Fields shared by projected outbounds: the base object, the remote server,
//! TLS, transports and packet encoding.

use std::net::IpAddr;

use serde_json::{Map, Value, json};

use crate::{
    ConfigError,
    profile::{OutboundTls, V2RayPacketEncoding, V2RayTransport},
    profile_projection::DomainResolverTags,
};

pub(crate) fn base_outbound(kind: &str, tag: &str) -> Map<String, Value> {
    Map::from_iter([
        ("type".to_owned(), Value::String(kind.to_owned())),
        ("tag".to_owned(), Value::String(tag.to_owned())),
    ])
}

pub(crate) fn remote_outbound(
    kind: &str,
    tag: &str,
    server: &str,
    port: u16,
    bootstrap_resolver: DomainResolverTags<'_>,
) -> Map<String, Value> {
    let mut object = base_outbound(kind, tag);
    object.insert("server".into(), Value::String(server.to_owned()));
    object.insert("server_port".into(), json!(port));
    if server.parse::<IpAddr>().is_err() {
        object.insert("domain_resolver".into(), bootstrap_resolver.value());
    }
    object
}

pub(crate) fn insert_tls_transport(
    object: &mut Map<String, Value>,
    tls: Option<&OutboundTls>,
    transport: Option<&V2RayTransport>,
) -> Result<(), ConfigError> {
    if let Some(tls) = tls {
        object.insert("tls".into(), project_tls(tls)?);
    }
    if let Some(transport) = transport {
        object.insert("transport".into(), project_transport(transport));
    }
    Ok(())
}

pub(crate) fn insert_packet_encoding(
    object: &mut Map<String, Value>,
    packet_encoding: Option<&V2RayPacketEncoding>,
) {
    if let Some(packet_encoding) = packet_encoding {
        let value = match packet_encoding {
            V2RayPacketEncoding::Raw => "",
            V2RayPacketEncoding::PacketAddr => "packetaddr",
            V2RayPacketEncoding::Xudp => "xudp",
        };
        object.insert("packet_encoding".into(), Value::String(value.into()));
    }
}

pub(crate) fn project_tls(tls: &OutboundTls) -> Result<Value, ConfigError> {
    let mut object = Map::new();
    object.insert("enabled".into(), Value::Bool(tls.enabled));
    object.insert("server_name".into(), Value::String(tls.server_name.clone()));
    if !tls.certificate_sha256.is_empty() {
        object.insert("certificate_sha256".into(), json!(tls.certificate_sha256));
    }
    if !tls.certificate_public_key_sha256.is_empty() {
        object.insert(
            "certificate_public_key_sha256".into(),
            json!(tls.certificate_public_key_sha256),
        );
    }
    if tls.enabled {
        object.insert("min_version".into(), serde_json::to_value(tls.min_version)?);
    }
    if !tls.alpn.is_empty() {
        object.insert("alpn".into(), serde_json::to_value(&tls.alpn)?);
    }
    if !tls.curve_preferences.is_empty() {
        object.insert(
            "curve_preferences".into(),
            serde_json::to_value(&tls.curve_preferences)?,
        );
    }
    if let Some(ech) = &tls.ech {
        object.insert("ech".into(), serde_json::to_value(ech)?);
    }
    if let Some(utls) = &tls.utls {
        object.insert(
            "utls".into(),
            json!({ "enabled": utls.enabled, "fingerprint": utls.fingerprint }),
        );
    }
    if let Some(reality) = &tls.reality {
        let mut projected = json!({
            "enabled": reality.enabled,
            "public_key": reality.public_key,
            "short_id": reality.short_id,
        });
        if reality.support_x25519mlkem768 {
            projected["support_x25519mlkem768"] = Value::Bool(true);
        }
        object.insert("reality".into(), projected);
    }
    Ok(Value::Object(object))
}

fn project_transport(transport: &V2RayTransport) -> Value {
    match transport {
        V2RayTransport::Http { method, path, host } => {
            let mut object = Map::from_iter([
                ("type".into(), Value::String("http".into())),
                ("path".into(), Value::String(path.clone())),
                ("host".into(), json!(host)),
            ]);
            if let Some(method) = method {
                object.insert("method".into(), Value::String(method.as_str().into()));
            }
            Value::Object(object)
        }
        V2RayTransport::Websocket { path, headers } => {
            let mut object = Map::from_iter([
                ("type".into(), Value::String("ws".into())),
                ("path".into(), Value::String(path.clone())),
            ]);
            if let Some(headers) = headers {
                object.insert("headers".into(), json!({ "Host": headers.host }));
            }
            Value::Object(object)
        }
        V2RayTransport::Grpc { service_name } => json!({
            "type": "grpc",
            "service_name": service_name,
        }),
        V2RayTransport::Quic => json!({ "type": "quic" }),
        V2RayTransport::HttpUpgrade { path, host } => {
            let mut object = Map::from_iter([
                ("type".into(), Value::String("httpupgrade".into())),
                ("path".into(), Value::String(path.clone())),
            ]);
            if let Some(host) = host {
                object.insert("host".into(), Value::String(host.clone()));
            }
            Value::Object(object)
        }
    }
}
