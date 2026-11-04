//! V2Ray transports and their compatibility with TLS and VLESS Vision.

use super::{
    MAX_PATH_BYTES, MAX_SERVER_BYTES, unsupported_shape, validate_quic_tls, validate_server_name,
};
use crate::ConfigError;
use crate::profile::{OutboundTls, V2RayPacketEncoding, V2RayTransport, VlessFlow};

pub(super) fn validate_optional_transport(
    transport: Option<&V2RayTransport>,
    path: &str,
) -> Result<(), ConfigError> {
    let Some(transport) = transport else {
        return Ok(());
    };
    match transport {
        V2RayTransport::Http {
            method: _,
            path: value,
            host,
        } => {
            validate_v2ray_transport_path(value, &format!("{path}.transport.path"))?;
            if host.len() > 16 {
                return Err(unsupported_shape(
                    format!("{path}.transport.host"),
                    "HTTP transport accepts at most 16 host authorities",
                ));
            }
            for (index, authority) in host.iter().enumerate() {
                validate_websocket_host_authority(
                    authority,
                    &format!("{path}.transport.host[{index}]"),
                )?;
            }
        }
        V2RayTransport::Websocket {
            path: value,
            headers,
        } => {
            validate_v2ray_transport_path(value, &format!("{path}.transport.path"))?;
            if let Some(headers) = headers {
                validate_websocket_host_authority(
                    &headers.host,
                    &format!("{path}.transport.headers.Host"),
                )?;
            }
        }
        V2RayTransport::Grpc { service_name } => {
            if service_name.is_empty()
                || service_name.len() > 256
                || service_name.chars().any(char::is_control)
            {
                return Err(unsupported_shape(
                    format!("{path}.transport.service_name"),
                    "gRPC service_name is invalid",
                ));
            }
        }
        V2RayTransport::Quic => {}
        V2RayTransport::HttpUpgrade { path: value, host } => {
            validate_v2ray_transport_path(value, &format!("{path}.transport.path"))?;
            if let Some(authority) = host {
                validate_websocket_host_authority(authority, &format!("{path}.transport.host"))?;
            }
        }
    }
    Ok(())
}

pub(super) fn validate_v2ray_transport_path(value: &str, path: &str) -> Result<(), ConfigError> {
    if !value.starts_with('/')
        || value.len() > MAX_PATH_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(unsupported_shape(
            path,
            "V2Ray transport path must be a bounded absolute path",
        ));
    }
    Ok(())
}

pub(super) fn validate_transport_tls_compatibility(
    transport: Option<&V2RayTransport>,
    tls: Option<&OutboundTls>,
    path: &str,
) -> Result<(), ConfigError> {
    if !matches!(transport, Some(V2RayTransport::Quic)) {
        return Ok(());
    }
    let tls = tls.filter(|tls| tls.enabled).ok_or_else(|| {
        unsupported_shape(
            format!("{path}.tls.enabled"),
            "V2Ray QUIC transport requires enabled TLS",
        )
    })?;
    validate_quic_tls(tls, path)
}

pub(super) fn validate_vless_vision_compatibility(
    flow: Option<&VlessFlow>,
    packet_encoding: Option<&V2RayPacketEncoding>,
    tls: Option<&OutboundTls>,
    transport: Option<&V2RayTransport>,
    path: &str,
) -> Result<(), ConfigError> {
    if flow.is_none() {
        return Ok(());
    }
    if !tls.is_some_and(|tls| tls.enabled) {
        return Err(unsupported_shape(
            format!("{path}.tls.enabled"),
            "VLESS Vision requires enabled TLS",
        ));
    }
    if transport.is_some() {
        return Err(unsupported_shape(
            format!("{path}.transport"),
            "VLESS Vision cannot be combined with a V2Ray transport stream",
        ));
    }
    if matches!(
        packet_encoding,
        Some(V2RayPacketEncoding::Raw | V2RayPacketEncoding::PacketAddr)
    ) {
        return Err(unsupported_shape(
            format!("{path}.packet_encoding"),
            "VLESS Vision packet encoding must be omitted or XUDP",
        ));
    }
    Ok(())
}

pub(super) fn validate_websocket_host_authority(
    authority: &str,
    path: &str,
) -> Result<(), ConfigError> {
    let invalid = || {
        unsupported_shape(
            path,
            "WebSocket Host must be a bounded DNS name or IP address with an optional nonzero port",
        )
    };
    if authority.is_empty()
        || authority.len() > MAX_SERVER_BYTES + 8
        || authority.trim() != authority
        || authority.chars().any(char::is_control)
        || authority.contains(['/', '\\', '@'])
    {
        return Err(invalid());
    }

    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return Err(invalid());
        };
        let port = match suffix.strip_prefix(':') {
            Some(value) => Some(value),
            None if suffix.is_empty() => None,
            None => return Err(invalid()),
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid());
        }
        (host, port)
    } else if authority.matches(':').count() == 1 {
        let (host, port) = authority.rsplit_once(':').ok_or_else(invalid)?;
        (host, Some(port))
    } else {
        (authority, None)
    };

    if let Some(port) = port
        && !matches!(port.parse::<u16>(), Ok(port) if port != 0)
    {
        return Err(invalid());
    }
    validate_server_name(host, path)
}
