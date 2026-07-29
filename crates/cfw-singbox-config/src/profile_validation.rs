use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::profile::{
    MAX_OUTBOUNDS, OutboundTls, ProfileDocument, ProfileOutbound, V2RayTransport,
};
use crate::{ConfigError, CredentialKind, CredentialRef};

const MAX_TAG_BYTES: usize = 128;
const MAX_SERVER_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 2_048;
const MAX_ALPN_ENTRIES: usize = 8;

impl ProfileDocument {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.outbounds.is_empty() || self.outbounds.len() > MAX_OUTBOUNDS {
            return Err(unsupported_shape(
                "$.outbounds",
                "outbound count is outside the accepted 1..=128 range",
            ));
        }

        let mut tags = BTreeSet::new();
        let mut credential_kinds = BTreeMap::new();
        for (index, outbound) in self.outbounds.iter().enumerate() {
            let path = format!("$.outbounds[{index}]");
            outbound.validate(&path)?;
            if !tags.insert(outbound.tag()) {
                return Err(unsupported_shape(
                    format!("{path}.tag"),
                    "outbound tags must be unique",
                ));
            }
            for reference in outbound.credential_refs() {
                match credential_kinds.insert(reference.id(), reference.kind()) {
                    Some(kind) if kind != reference.kind() => {
                        return Err(ConfigError::ConflictingCredentialReference {
                            id: reference.id().to_owned(),
                        });
                    }
                    _ => {}
                }
            }
        }

        if let Some(final_tag) = self
            .route
            .as_ref()
            .and_then(|route| route.final_tag.as_ref())
            && !tags.contains(final_tag.as_str())
        {
            return Err(unsupported_shape(
                "$.route.final",
                "final must reference a declared outbound tag",
            ));
        }
        Ok(())
    }
}

impl ProfileOutbound {
    fn validate(&self, path: &str) -> Result<(), ConfigError> {
        validate_tag(self.tag(), &format!("{path}.tag"))?;
        match self {
            Self::Direct { .. } | Self::Block { .. } => Ok(()),
            Self::Shadowsocks {
                server,
                server_port,
                credential_ref,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_reference_kind(credential_ref, CredentialKind::ShadowsocksPassword, path)
            }
            Self::Vmess {
                server,
                server_port,
                credential_ref,
                tls,
                transport,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_reference_kind(credential_ref, CredentialKind::VmessUuid, path)?;
                validate_optional_tls(tls.as_ref(), path)?;
                validate_optional_transport(transport.as_ref(), path)
            }
            Self::Vless {
                server,
                server_port,
                credential_ref,
                flow,
                tls,
                transport,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_reference_kind(credential_ref, CredentialKind::VlessUuid, path)?;
                validate_optional_tls(tls.as_ref(), path)?;
                if flow.is_some() && !tls.as_ref().is_some_and(|tls| tls.enabled) {
                    return Err(unsupported_shape(
                        format!("{path}.tls.enabled"),
                        "VLESS Vision requires enabled TLS",
                    ));
                }
                if tls.as_ref().is_some_and(|tls| tls.reality.is_some())
                    && !tls.as_ref().is_some_and(|tls| tls.enabled)
                {
                    return Err(unsupported_shape(
                        format!("{path}.tls.enabled"),
                        "Reality requires enabled TLS",
                    ));
                }
                validate_optional_transport(transport.as_ref(), path)
            }
            Self::Trojan {
                server,
                server_port,
                credential_ref,
                tls,
                transport,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_reference_kind(credential_ref, CredentialKind::TrojanPassword, path)?;
                validate_required_tls(tls, path)?;
                validate_optional_transport(transport.as_ref(), path)
            }
            Self::Hysteria2 {
                server,
                server_port,
                credential_ref,
                tls,
                up_mbps,
                down_mbps,
                obfs,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_reference_kind(credential_ref, CredentialKind::Hysteria2Password, path)?;
                validate_required_tls(tls, path)?;
                for (field, value) in [("up_mbps", up_mbps), ("down_mbps", down_mbps)] {
                    if value.is_some_and(|value| value == 0 || value > 1_000_000) {
                        return Err(unsupported_shape(
                            format!("{path}.{field}"),
                            "bandwidth must be between 1 and 1000000 Mbps",
                        ));
                    }
                }
                if let Some(obfs) = obfs {
                    validate_reference_kind(
                        &obfs.credential_ref,
                        CredentialKind::Hysteria2ObfsPassword,
                        path,
                    )?;
                }
                Ok(())
            }
        }
    }
}

fn validate_tag(tag: &str, path: &str) -> Result<(), ConfigError> {
    if tag.trim() != tag
        || tag.is_empty()
        || tag.len() > MAX_TAG_BYTES
        || tag.chars().any(char::is_control)
    {
        return Err(unsupported_shape(
            path,
            "tag is empty, too long, padded, or contains unsafe characters",
        ));
    }
    Ok(())
}

fn validate_reference_kind(
    reference: &CredentialRef,
    expected: CredentialKind,
    path: &str,
) -> Result<(), ConfigError> {
    if reference.kind() != expected {
        return Err(ConfigError::CredentialKindMismatch {
            path: format!("{path}.credential_ref"),
            expected,
            actual: reference.kind(),
        });
    }
    Ok(())
}

fn validate_remote_endpoint(server: &str, port: u16, path: &str) -> Result<(), ConfigError> {
    if port == 0 {
        return Err(unsupported_shape(
            format!("{path}.server_port"),
            "server_port must be nonzero",
        ));
    }
    validate_server_name(server, &format!("{path}.server"))
}

fn validate_server_name(server: &str, path: &str) -> Result<(), ConfigError> {
    if server.is_empty()
        || server.len() > MAX_SERVER_BYTES
        || server.trim() != server
        || server.chars().any(char::is_control)
        || server.contains(['/', '\\', '@', ':']) && server.parse::<IpAddr>().is_err()
    {
        return Err(unsupported_shape(
            path,
            "server is not a bounded IP address or DNS name",
        ));
    }
    if let Ok(address) = server.parse::<IpAddr>() {
        if remote_endpoint_ip_is_unusable(address) {
            return Err(unsupported_shape(
                path,
                "server IP is loopback, link-local, multicast, documentation, or tunnel-reserved",
            ));
        }
        return Ok(());
    }
    if server.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(unsupported_shape(
            path,
            "server is not a bounded IP address or DNS name",
        ));
    }
    Ok(())
}

fn remote_endpoint_ip_is_unusable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_documentation()
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            address.is_unspecified()
                || address.is_loopback()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0)
        }
    }
}

fn validate_optional_tls(tls: Option<&OutboundTls>, path: &str) -> Result<(), ConfigError> {
    match tls {
        Some(tls) => tls.validate(path),
        None => Ok(()),
    }
}

fn validate_required_tls(tls: &OutboundTls, path: &str) -> Result<(), ConfigError> {
    tls.validate(path)?;
    if !tls.enabled {
        return Err(unsupported_shape(
            format!("{path}.tls.enabled"),
            "this protocol requires enabled TLS",
        ));
    }
    Ok(())
}

impl OutboundTls {
    fn validate(&self, path: &str) -> Result<(), ConfigError> {
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
        if !self.enabled && (!self.alpn.is_empty() || self.utls.is_some() || self.reality.is_some())
        {
            return Err(unsupported_shape(
                format!("{path}.tls.enabled"),
                "ALPN, uTLS, and Reality require enabled TLS",
            ));
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

fn validate_optional_transport(
    transport: Option<&V2RayTransport>,
    path: &str,
) -> Result<(), ConfigError> {
    let Some(transport) = transport else {
        return Ok(());
    };
    match transport {
        V2RayTransport::Websocket {
            path: value,
            headers,
        } => {
            if !value.starts_with('/')
                || value.len() > MAX_PATH_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(unsupported_shape(
                    format!("{path}.transport.path"),
                    "WebSocket path must be a bounded absolute path",
                ));
            }
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
    }
    Ok(())
}

fn validate_websocket_host_authority(authority: &str, path: &str) -> Result<(), ConfigError> {
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

fn unsupported_shape(path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::UnsupportedPolicyShape {
        path: path.into(),
        reason: reason.into(),
    }
}
