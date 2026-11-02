//! Application-owned DNS-over-HTTPS servers and the checks their pools pass.

use super::*;

/// One application-owned DNS-over-HTTPS server. Without `detour` the
/// ordinary dialer goes DIRECT.
pub(super) fn doh_server(
    tag: &str,
    server: &crate::engine_settings::AuthenticatedDnsServer,
    detour: Option<&str>,
) -> Value {
    let mut value = json!({
        "type": "https",
        "tag": tag,
        "server": server.address.to_string(),
        "server_port": 443,
        "path": "/dns-query",
        "connect_timeout": "5s",
        "tls": {
            "enabled": true,
            "server_name": server.server_name.as_str(),
            "min_version": MINIMUM_REMOTE_TLS_VERSION
        }
    });
    if let Some(detour) = detour {
        value["detour"] = json!(detour);
    }
    value
}

/// The checks every DNS-over-HTTPS pool the application owns must pass.
pub(crate) fn validate_authenticated_dns_pool(
    servers: &[crate::engine_settings::AuthenticatedDnsServer],
    enable_ipv6: bool,
) -> Result<(), ConfigError> {
    let unique_addresses = servers
        .iter()
        .map(|server| server.address)
        .collect::<BTreeSet<_>>();
    if unique_addresses.len() != servers.len() {
        return Err(ConfigError::InvalidAuthenticatedDnsServers(
            "the two authenticated DNS endpoints must be distinct".to_owned(),
        ));
    }
    for server in servers {
        if !enable_ipv6 && server.address.is_ipv6() {
            return Err(ConfigError::InvalidAuthenticatedDnsServers(format!(
                "authenticated IPv6 endpoint {} is unavailable while IPv6 is disabled",
                server.address
            )));
        }
        if dns_address_is_unusable(server.address) || !is_valid_tls_dns_name(&server.server_name) {
            return Err(ConfigError::InvalidAuthenticatedDnsServers(format!(
                "authenticated endpoint {} has an unusable address or TLS server name",
                server.address
            )));
        }
    }
    Ok(())
}

fn is_valid_tls_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.trim() == name
        && name.parse::<IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn dns_address_is_unusable(address: IpAddr) -> bool {
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
        }
    }
}
