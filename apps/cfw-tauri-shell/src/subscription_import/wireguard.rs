//! Single-peer WireGuard client import. wg-quick shell hooks and routing
//! directives are never executed; unsupported semantics fail before commit.

use std::collections::BTreeMap;
use std::net::IpAddr;

use cfw_singbox_config::{CredentialKind, CredentialSecret};
use serde_json::{Value, json};

use super::{ImportedSubscription, OutboundCollector, credential_ref_json};

pub(super) struct WireGuardNode {
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub local_addresses: Vec<String>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub mtu: u16,
    pub keepalive: u16,
}

struct WireGuardSections {
    interface: BTreeMap<String, String>,
    peer: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
enum Section {
    Interface,
    Peer,
}

pub(super) fn convert(
    collector: &mut OutboundCollector,
    node: WireGuardNode,
) -> Result<Value, String> {
    validate_key(&node.private_key, CredentialKind::WireGuardPrivateKey)?;
    if let Some(key) = &node.pre_shared_key {
        validate_key(key, CredentialKind::WireGuardPreSharedKey)?;
    }
    let private_ref = collector.push_secret(CredentialKind::WireGuardPrivateKey, node.private_key);
    let mut outbound = json!({
        "type":"wireguard","tag":collector.unique_tag(node.name)?,"server":node.server,"server_port":node.server_port,
        "local_addresses":node.local_addresses,"private_key_credential_ref":credential_ref_json(&private_ref),
        "peer_public_key":node.public_key,"mtu":node.mtu,"persistent_keepalive_seconds":node.keepalive,
    });
    if let Some(key) = node.pre_shared_key {
        let reference = collector.push_secret(CredentialKind::WireGuardPreSharedKey, key);
        outbound["pre_shared_key_credential_ref"] = credential_ref_json(&reference);
    }
    Ok(outbound)
}

fn validate_key(value: &str, kind: CredentialKind) -> Result<(), String> {
    CredentialSecret::new(value)
        .and_then(|secret| secret.validate_for_kind(kind))
        .map_err(|_| "WireGuard key must be a nonzero 32-byte canonical base64 value".into())
}

pub(super) fn import_document(
    body: &str,
    mut collector: OutboundCollector,
) -> Result<ImportedSubscription, String> {
    let WireGuardSections {
        mut interface,
        mut peer,
    } = parse_sections(body)?;
    let endpoint = required(&mut peer, "Endpoint")?;
    let (server, port) = endpoint
        .rsplit_once(':')
        .ok_or("WireGuard Endpoint requires host:port")?;
    let server = server
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(server)
        .to_owned();
    let local_addresses = required(&mut interface, "Address")?
        .split(',')
        .map(|value| value.trim().to_owned())
        .collect();
    let allowed = required(&mut peer, "AllowedIPs")?;
    let allowed = allowed.split(',').map(str::trim).collect::<Vec<_>>();
    if allowed.is_empty()
        || allowed.len() > 2
        || allowed
            .iter()
            .any(|value| !matches!(*value, "0.0.0.0/0" | "::/0"))
        || allowed
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != allowed.len()
    {
        return Err("WireGuard configuration uses split AllowedIPs; import explicit routing rules instead of changing its scope".into());
    }
    let node = WireGuardNode {
        name: "WireGuard".into(),
        server,
        server_port: port
            .parse()
            .map_err(|_| "WireGuard endpoint port is invalid")?,
        local_addresses,
        private_key: required(&mut interface, "PrivateKey")?,
        public_key: required(&mut peer, "PublicKey")?,
        pre_shared_key: peer.remove("PresharedKey"),
        mtu: optional_number(&mut interface, "MTU", 1420)?,
        keepalive: optional_number(&mut peer, "PersistentKeepalive", 0)?,
    };
    let mut outbound = convert(&mut collector, node)?;
    outbound["peer_allowed_ips"] = json!(allowed);
    let tag = outbound["tag"]
        .as_str()
        .ok_or("WireGuard conversion has no tag")?
        .to_owned();
    collector.outbounds.push(outbound);
    collector.route = Some(json!({"final":tag}));
    if let Some(dns) = interface.remove("DNS") {
        let servers = dns
            .split(',')
            .map(|value| {
                let address = value
                    .trim()
                    .parse::<IpAddr>()
                    .map_err(|_| "WireGuard DNS search domains are unsupported")?;
                Ok(json!({"type":"udp","server":address,"server_port":53}))
            })
            .collect::<Result<Vec<_>, String>>()?;
        collector.dns = Some(json!({"servers":servers}));
    }
    if !interface.is_empty() || !peer.is_empty() {
        return Err("WireGuard configuration contains unapplied fields".into());
    }
    collector.into_subscription()
}

fn parse_sections(body: &str) -> Result<WireGuardSections, String> {
    let mut interface = BTreeMap::new();
    let mut peer = BTreeMap::new();
    let mut section = None;
    let mut seen_interface = false;
    let mut seen_peer = false;
    for (index, line) in body.lines().enumerate() {
        if index >= 256 {
            return Err("WireGuard configuration exceeds 256 lines".into());
        }
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match line {
            "[Interface]" if !seen_interface && !seen_peer => {
                section = Some(Section::Interface);
                seen_interface = true;
                continue;
            }
            "[Peer]" if seen_interface && !seen_peer => {
                section = Some(Section::Peer);
                seen_peer = true;
                continue;
            }
            _ if line.starts_with('[') => {
                return Err("WireGuard requires one Interface followed by one Peer".into());
            }
            _ => {}
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("WireGuard line {} is not a setting", index + 1))?;
        let (key, value) = (key.trim(), value.trim());
        let is_peer = matches!(
            section.ok_or("WireGuard settings must follow a section")?,
            Section::Peer
        );
        let accepted = if is_peer {
            [
                "PublicKey",
                "PresharedKey",
                "Endpoint",
                "AllowedIPs",
                "PersistentKeepalive",
            ]
            .contains(&key)
        } else {
            ["PrivateKey", "Address", "DNS", "MTU"].contains(&key)
        };
        if !accepted || value.is_empty() {
            return Err(format!(
                "WireGuard line {} contains an unsupported or empty setting; no commands were executed",
                index + 1
            ));
        }
        let destination = if is_peer { &mut peer } else { &mut interface };
        if destination
            .insert(key.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(format!("WireGuard line {} repeats a setting", index + 1));
        }
    }
    if !seen_peer {
        return Err("WireGuard Peer section is missing".into());
    }
    Ok(WireGuardSections { interface, peer })
}

fn required(fields: &mut BTreeMap<String, String>, key: &str) -> Result<String, String> {
    fields
        .remove(key)
        .ok_or_else(|| format!("WireGuard {key} is missing"))
}

fn optional_number(
    fields: &mut BTreeMap<String, String>,
    key: &str,
    default: u16,
) -> Result<u16, String> {
    fields
        .remove(key)
        .map(|value| value.parse())
        .transpose()
        .map_err(|_| format!("WireGuard {key} must be an integer"))
        .map(|value| value.unwrap_or(default))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> String {
        "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.64.0.2/32\nDNS = 10.64.0.1\nMTU = 1380\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n".into()
    }

    #[test]
    fn full_tunnel_file_preserves_keys_dns_mtu_and_address_family_scope() {
        let imported =
            super::super::import_subscription_document(&source()).expect("WireGuard file");
        let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
        assert_eq!(imported.credentials.len(), 1);
        assert_eq!(profile["outbounds"][0]["mtu"], 1380);
        assert_eq!(profile["outbounds"][0]["persistent_keepalive_seconds"], 25);
        assert_eq!(
            profile["outbounds"][0]["peer_allowed_ips"],
            json!(["0.0.0.0/0"])
        );
        assert_eq!(profile["dns"]["servers"][0]["server"], "10.64.0.1");
        assert!(!imported.profile.as_json().contains("AQEBAQE"));
    }

    #[test]
    fn unsupported_hooks_split_routes_and_ambiguous_files_are_rejected() {
        for bad in [
            source().replace("MTU = 1380", "PostUp = echo PRIVATE"),
            source().replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8"),
            source().replace("DNS = 10.64.0.1", "DNS = private.example"),
            source().replace("[Peer]", "[Peer]\n[Peer]"),
            source().replace("MTU = 1380", "MTU = 1380\nMTU = 1400"),
            source().replace("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "PRIVATE"),
        ] {
            let error = super::super::import_subscription_document(&bad).expect_err("invalid file");
            assert!(!error.contains("PRIVATE"));
        }
    }
}
