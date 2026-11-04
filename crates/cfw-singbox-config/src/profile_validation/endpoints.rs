//! Remote endpoints, server names and Tailscale identities.

use std::net::IpAddr;

use super::{MAX_PATH_BYTES, MAX_SERVER_BYTES, unsupported_shape};
use crate::ConfigError;

pub(super) fn validate_remote_endpoint(
    server: &str,
    port: u16,
    path: &str,
) -> Result<(), ConfigError> {
    if port == 0 {
        return Err(unsupported_shape(
            format!("{path}.server_port"),
            "server_port must be nonzero",
        ));
    }
    validate_server_name(server, &format!("{path}.server"))
}

pub(crate) fn validate_server_name(server: &str, path: &str) -> Result<(), ConfigError> {
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

/// A Tailscale machine name is one DNS label; the coordination server derives
/// the node's MagicDNS name from it.
pub(super) fn validate_tailscale_hostname(hostname: &str, path: &str) -> Result<(), ConfigError> {
    if hostname.is_empty()
        || hostname.len() > 63
        || hostname.starts_with('-')
        || hostname.ends_with('-')
        || !hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(unsupported_shape(
            path,
            "Tailscale hostname must be one DNS label of up to 63 letters, digits and hyphens",
        ));
    }
    Ok(())
}

/// The coordination server receives the node key, so only an https origin
/// without credentials, query or fragment is admitted.
pub(super) fn validate_tailscale_control_server(
    value: &str,
    path: &str,
) -> Result<(), ConfigError> {
    let invalid = || {
        unsupported_shape(
            path,
            "Tailscale control_server must be an https URL with a host and no credentials, query or fragment",
        )
    };
    if value.len() > MAX_PATH_BYTES || value.trim() != value {
        return Err(invalid());
    }
    let parsed = url::Url::parse(value).map_err(|_| invalid())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn remote_endpoint_ip_is_unusable(address: IpAddr) -> bool {
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
