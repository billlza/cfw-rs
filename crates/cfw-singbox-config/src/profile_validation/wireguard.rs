//! WireGuard peer routes, keys and interface addresses.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::unsupported_shape;
use crate::ConfigError;

/// The peer routes the default IPv4 and/or IPv6 prefix, each once.
pub(super) fn validate_wireguard_allowed_ips(
    peer_allowed_ips: &[String],
    path: &str,
) -> Result<(), ConfigError> {
    if peer_allowed_ips.is_empty()
        || peer_allowed_ips.len() > 2
        || peer_allowed_ips
            .iter()
            .any(|prefix| !matches!(prefix.as_str(), "0.0.0.0/0" | "::/0"))
        || peer_allowed_ips.iter().collect::<BTreeSet<_>>().len() != peer_allowed_ips.len()
    {
        return Err(unsupported_shape(
            path,
            "WireGuard peer requires unique IPv4 and/or IPv6 default routes",
        ));
    }
    Ok(())
}

pub(super) fn validate_wireguard_link(
    peer_public_key: &str,
    mtu: u16,
    persistent_keepalive_seconds: u16,
    path: &str,
) -> Result<(), ConfigError> {
    if !crate::credentials::valid_wireguard_key(peer_public_key)
        || !(1280..=9000).contains(&mtu)
        || persistent_keepalive_seconds > 3600
    {
        return Err(unsupported_shape(
            path,
            "WireGuard requires a 32-byte peer key, MTU 1280..=9000 and keepalive 0..=3600 seconds",
        ));
    }
    Ok(())
}

/// One numeric, canonical interface address per IP family.
pub(super) fn validate_wireguard_local_addresses(
    local_addresses: &[String],
    path: &str,
) -> Result<(), ConfigError> {
    if local_addresses.is_empty() || local_addresses.len() > 2 {
        return Err(unsupported_shape(
            path,
            "WireGuard requires one IPv4 and/or one IPv6 address",
        ));
    }
    let mut families = BTreeSet::new();
    for address in local_addresses {
        let (host, prefix) = address
            .split_once('/')
            .ok_or_else(|| unsupported_shape(path, "WireGuard address requires an IP prefix"))?;
        let host = host
            .parse::<IpAddr>()
            .map_err(|_| unsupported_shape(path, "WireGuard address must be numeric"))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| unsupported_shape(path, "WireGuard prefix is invalid"))?;
        if host.is_unspecified()
            || host.is_multicast()
            || host.is_loopback()
            || prefix > if host.is_ipv4() { 32 } else { 128 }
            || !families.insert(host.is_ipv4())
            || format!("{host}/{prefix}") != *address
        {
            return Err(unsupported_shape(
                path,
                "WireGuard address is invalid, duplicated by family or noncanonical",
            ));
        }
    }
    Ok(())
}
