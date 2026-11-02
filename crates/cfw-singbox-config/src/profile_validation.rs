use std::collections::{BTreeMap, BTreeSet};

mod endpoints;
mod groups;
mod hysteria2;
mod tls;
mod transport;
mod wireguard;

pub(crate) use endpoints::{remote_endpoint_ip_is_unusable, validate_server_name};
use endpoints::{
    validate_remote_endpoint, validate_tailscale_control_server, validate_tailscale_hostname,
};
use groups::{has_unique_members, validate_group_timing, validate_health_check_url};
use hysteria2::{
    validate_hysteria2_bandwidth, validate_hysteria2_hop_interval,
    validate_hysteria2_obfs_packet_sizes, validate_hysteria2_server_ports,
};
use tls::{validate_optional_tls, validate_quic_tls, validate_required_tls};
use transport::{
    validate_optional_transport, validate_transport_tls_compatibility,
    validate_vless_vision_compatibility,
};
use wireguard::{
    validate_wireguard_allowed_ips, validate_wireguard_link, validate_wireguard_local_addresses,
};

use crate::profile::{MAX_OUTBOUNDS, ProfileDocument, ProfileOutbound};
use crate::{ConfigError, CredentialKind, CredentialRef};

const MAX_TAG_BYTES: usize = 128;
const MAX_SERVER_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 2_048;

impl ProfileDocument {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.outbounds.is_empty() || self.outbounds.len() > MAX_OUTBOUNDS {
            return Err(unsupported_shape(
                "$.outbounds",
                format!("outbound count is outside the accepted 1..={MAX_OUTBOUNDS} range"),
            ));
        }
        let nodes = self
            .outbounds
            .iter()
            .filter(|outbound| outbound.is_remote())
            .count();
        let groups = self
            .outbounds
            .iter()
            .filter(|outbound| outbound.group_members().is_some())
            .count();
        let memberships: usize = self
            .outbounds
            .iter()
            .filter_map(ProfileOutbound::group_members)
            .map(<[String]>::len)
            .sum();
        if nodes > crate::MAX_PROXY_NODES
            || groups > crate::MAX_PROXY_GROUPS
            || memberships > crate::MAX_GROUP_MEMBERSHIPS
        {
            return Err(unsupported_shape(
                "$.outbounds",
                "profile exceeds the node, group, or membership capacity",
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
        self.validate_routing(&tags)?;
        if let Some(dns) = &self.dns {
            dns.validate(self)?;
        }
        let mut datasets = self.route_datasets();
        if self.dns.is_some() {
            datasets.extend(crate::dns_policy::dns_datasets(self)?);
        }
        if datasets.len() > crate::datasets::MAX_GEO_DATASETS {
            return Err(unsupported_shape(
                "$",
                format!(
                    "profile references more than {} GeoIP and GeoSite datasets",
                    crate::datasets::MAX_GEO_DATASETS
                ),
            ));
        }
        crate::dns_policy::validate_hosts(&self.hosts)?;
        Ok(())
    }
}

impl ProfileOutbound {
    pub(crate) fn validate(&self, path: &str) -> Result<(), ConfigError> {
        validate_tag(self.tag(), &format!("{path}.tag"))?;
        match self {
            Self::Direct { .. } | Self::Block { .. } => Ok(()),
            Self::WireGuard {
                server,
                server_port,
                local_addresses,
                private_key_credential_ref,
                peer_public_key,
                peer_allowed_ips,
                pre_shared_key_credential_ref,
                mtu,
                persistent_keepalive_seconds,
                ..
            } => {
                validate_wireguard_allowed_ips(peer_allowed_ips, path)?;
                validate_remote_endpoint(server, *server_port, path)?;
                validate_reference_kind_at(
                    private_key_credential_ref,
                    CredentialKind::WireGuardPrivateKey,
                    path,
                    "private_key_credential_ref",
                )?;
                if let Some(reference) = pre_shared_key_credential_ref {
                    validate_reference_kind_at(
                        reference,
                        CredentialKind::WireGuardPreSharedKey,
                        path,
                        "pre_shared_key_credential_ref",
                    )?;
                }
                validate_wireguard_link(
                    peer_public_key,
                    *mtu,
                    *persistent_keepalive_seconds,
                    path,
                )?;
                validate_wireguard_local_addresses(local_addresses, path)
            }
            Self::Tailscale {
                auth_key_credential_ref,
                exit_node,
                control_server,
                hostname,
                ..
            } => {
                validate_reference_kind_at(
                    auth_key_credential_ref,
                    CredentialKind::TailscaleAuthKey,
                    path,
                    "auth_key_credential_ref",
                )?;
                validate_server_name(exit_node, &format!("{path}.exit_node"))?;
                if let Some(hostname) = hostname {
                    validate_tailscale_hostname(hostname, &format!("{path}.hostname"))?;
                }
                if let Some(server) = control_server {
                    validate_tailscale_control_server(server, &format!("{path}.control_server"))?;
                }
                Ok(())
            }
            Self::Selector {
                outbounds, default, ..
            } => {
                if !has_unique_members(outbounds)
                    || default.as_ref().is_some_and(|tag| !outbounds.contains(tag))
                {
                    return Err(unsupported_shape(
                        path,
                        "selector requires unique members and a default from its members",
                    ));
                }
                Ok(())
            }
            Self::UrlTest {
                outbounds,
                url,
                interval_seconds,
                idle_timeout_seconds,
                ..
            }
            | Self::Fallback {
                outbounds,
                url,
                interval_seconds,
                idle_timeout_seconds,
                ..
            }
            | Self::LoadBalance {
                outbounds,
                url,
                interval_seconds,
                idle_timeout_seconds,
                ..
            } => {
                let tolerance_ms = match self {
                    Self::UrlTest { tolerance_ms, .. } => *tolerance_ms,
                    _ => 0,
                };
                if !has_unique_members(outbounds) {
                    return Err(unsupported_shape(
                        path,
                        "automatic group requires unique members",
                    ));
                }
                validate_health_check_url(url, path)?;
                validate_group_timing(*interval_seconds, tolerance_ms, *idle_timeout_seconds, path)
            }
            Self::Socks5 {
                server,
                server_port,
                authentication,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                if let Some(authentication) = authentication {
                    validate_reference_kind_at(
                        &authentication.username_credential_ref,
                        CredentialKind::Socks5Username,
                        path,
                        "authentication.username_credential_ref",
                    )?;
                    validate_reference_kind_at(
                        &authentication.password_credential_ref,
                        CredentialKind::Socks5Password,
                        path,
                        "authentication.password_credential_ref",
                    )?;
                }
                Ok(())
            }
            Self::Http {
                server,
                server_port,
                authentication,
                tls,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_optional_tls(tls.as_ref(), path)?;
                if let Some(authentication) = authentication {
                    validate_reference_kind_at(
                        &authentication.username_credential_ref,
                        CredentialKind::HttpProxyUsername,
                        path,
                        "authentication.username_credential_ref",
                    )?;
                    if let Some(password) = &authentication.password_credential_ref {
                        validate_reference_kind_at(
                            password,
                            CredentialKind::HttpProxyPassword,
                            path,
                            "authentication.password_credential_ref",
                        )?;
                    }
                }
                Ok(())
            }
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
                validate_transport_tls_compatibility(transport.as_ref(), tls.as_ref(), path)?;
                validate_optional_tls(tls.as_ref(), path)?;
                validate_optional_transport(transport.as_ref(), path)
            }
            Self::Vless {
                server,
                server_port,
                credential_ref,
                flow,
                packet_encoding,
                tls,
                transport,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_reference_kind(credential_ref, CredentialKind::VlessUuid, path)?;
                validate_transport_tls_compatibility(transport.as_ref(), tls.as_ref(), path)?;
                validate_optional_tls(tls.as_ref(), path)?;
                validate_vless_vision_compatibility(
                    flow.as_ref(),
                    packet_encoding.as_ref(),
                    tls.as_ref(),
                    transport.as_ref(),
                    path,
                )?;
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
                validate_transport_tls_compatibility(transport.as_ref(), Some(tls), path)?;
                validate_required_tls(tls, path)?;
                validate_optional_transport(transport.as_ref(), path)
            }
            Self::Hysteria2 {
                server,
                server_port,
                server_ports,
                hop_interval_seconds,
                hop_interval_max_seconds,
                credential_ref,
                tls,
                up_mbps,
                down_mbps,
                obfs,
                bbr_profile,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_hysteria2_server_ports(server_ports.as_deref(), path)?;
                validate_hysteria2_hop_interval(
                    server_ports.is_some(),
                    *hop_interval_seconds,
                    *hop_interval_max_seconds,
                    path,
                )?;
                validate_reference_kind(credential_ref, CredentialKind::Hysteria2Password, path)?;
                validate_quic_tls(tls, path)?;
                validate_required_tls(tls, path)?;
                validate_hysteria2_bandwidth(*up_mbps, *down_mbps, bbr_profile.is_some(), path)?;
                if let Some(obfs) = obfs {
                    validate_reference_kind(
                        &obfs.credential_ref,
                        CredentialKind::Hysteria2ObfsPassword,
                        path,
                    )?;
                    validate_hysteria2_obfs_packet_sizes(obfs, path)?;
                }
                Ok(())
            }
            Self::AnyTls {
                server,
                server_port,
                credential_ref,
                tls,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_reference_kind(credential_ref, CredentialKind::AnyTlsPassword, path)?;
                validate_required_tls(tls, path)
            }
            Self::Tuic {
                server,
                server_port,
                uuid_credential_ref,
                password_credential_ref,
                tls,
                ..
            } => {
                validate_remote_endpoint(server, *server_port, path)?;
                validate_reference_kind_at(
                    uuid_credential_ref,
                    CredentialKind::TuicUuid,
                    path,
                    "uuid_credential_ref",
                )?;
                validate_reference_kind_at(
                    password_credential_ref,
                    CredentialKind::TuicPassword,
                    path,
                    "password_credential_ref",
                )?;
                validate_quic_tls(tls, path)?;
                validate_required_tls(tls, path)
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
    validate_reference_kind_at(reference, expected, path, "credential_ref")
}

fn validate_reference_kind_at(
    reference: &CredentialRef,
    expected: CredentialKind,
    path: &str,
    field: &str,
) -> Result<(), ConfigError> {
    if reference.kind() != expected {
        return Err(ConfigError::CredentialKindMismatch {
            path: format!("{path}.{field}"),
            expected,
            actual: reference.kind(),
        });
    }
    Ok(())
}

fn unsupported_shape(path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::UnsupportedPolicyShape {
        path: path.into(),
        reason: reason.into(),
    }
}
