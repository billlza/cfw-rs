//! Restricted adapter for upstream sing-box node-list JSON.
//!
//! This is deliberately not a full sing-box configuration loader. Only one
//! root `outbounds` array, with an optional `endpoints` array of Tailscale
//! nodes, is accepted; every source field is typed, inline secrets are
//! extracted into the vault batch, and the result is revalidated as the
//! application's closed secret-free profile.

mod outbound;
mod source;
mod tls_transport;

use outbound::{convert_outbound, reject_present};
use source::{SourceDocument, SourceEndpoint};

use cfw_singbox_config::CredentialKind;
use serde_json::{Value, json};

use super::socks5::Network as Socks5Network;
use super::{
    ImportedSubscription, OutboundCollector, TlsParts, build_tls_parts, canonical_uuid_credential,
    credential_ref_json, normalize_hysteria2_server_ports,
    normalize_shadowsocks_method_and_password, normalize_tuic_congestion_control,
    normalize_tuic_udp_relay_mode, normalize_v2ray_http_method, normalize_v2ray_packet_encoding,
    normalize_vless_flow, normalize_vmess_alter_id, normalize_vmess_security,
    parse_hysteria2_bbr_profile, parse_hysteria2_hop_interval_seconds, parse_utls, tls_json,
};

/// True when `body` has the node-list shape this adapter converts, which lets
/// the dispatcher tell a node list the typed schema also reads (credential-free
/// HTTP lists) from a typed profile this adapter would reject.
pub(super) fn matches_node_list_schema(body: &str) -> bool {
    serde_json::from_str::<SourceDocument>(body).is_ok()
}

pub(super) fn import_sing_box_document(
    body: &str,
    mut collector: OutboundCollector,
) -> Result<ImportedSubscription, String> {
    let source: SourceDocument = serde_json::from_str(body).map_err(|_| {
        "sing-box source JSON does not match the supported node-list schema".to_owned()
    })?;
    if source.outbounds.is_empty() && source.endpoints.is_empty() {
        return Err("sing-box source JSON contains no outbounds".into());
    }
    if source.outbounds.len() + source.endpoints.len() > cfw_singbox_config::MAX_OUTBOUNDS {
        return Err(format!(
            "sing-box source JSON has more than {} outbounds",
            cfw_singbox_config::MAX_OUTBOUNDS
        ));
    }
    for outbound in source.outbounds {
        let outbound = convert_outbound(&mut collector, outbound)?;
        collector.outbounds.push(outbound);
    }
    for endpoint in source.endpoints {
        let endpoint = convert_endpoint(&mut collector, endpoint)?;
        collector.outbounds.push(endpoint);
    }
    collector.into_subscription()
}

fn convert_endpoint(
    collector: &mut OutboundCollector,
    source: SourceEndpoint,
) -> Result<Value, String> {
    match source {
        SourceEndpoint::Tailscale {
            tag,
            auth_key,
            exit_node,
            control_url,
            hostname,
            accept_routes,
            exit_node_allow_lan_access,
            ephemeral,
            state_directory,
            advertise_routes,
            advertise_exit_node,
            advertise_tags,
            listen_port,
            relay_server_port,
            relay_server_static_endpoints,
            system_interface,
            system_interface_name,
            system_interface_mtu,
            udp_timeout,
            ssh_server,
            taildrop_directory,
        } => {
            reject_present(state_directory, "Tailscale state directory")?;
            reject_present(advertise_routes, "Tailscale route advertisement")?;
            reject_present(advertise_tags, "Tailscale tag advertisement")?;
            reject_present(listen_port, "Tailscale listen port")?;
            reject_present(relay_server_port, "Tailscale relay server")?;
            reject_present(relay_server_static_endpoints, "Tailscale relay server")?;
            reject_present(system_interface_name, "Tailscale system interface")?;
            reject_present(system_interface_mtu, "Tailscale system interface")?;
            reject_present(udp_timeout, "Tailscale UDP timeout")?;
            reject_present(ssh_server, "Tailscale SSH server")?;
            reject_present(taildrop_directory, "Taildrop")?;
            if advertise_exit_node {
                return Err("sing-box Tailscale exit-node advertisement is unsupported: this Mac only uses an exit node".into());
            }
            if system_interface {
                return Err("sing-box Tailscale system interfaces are unsupported".into());
            }
            if ephemeral {
                return Err("sing-box Tailscale ephemeral nodes are unsupported".into());
            }
            if auth_key.is_empty() {
                return Err(
                    "sing-box Tailscale import requires auth_key; interactive login is unsupported"
                        .into(),
                );
            }
            if exit_node.is_empty() {
                return Err("sing-box Tailscale import requires exit_node".into());
            }
            let reference = collector.push_secret(CredentialKind::TailscaleAuthKey, auth_key);
            let mut endpoint = json!({
                "type": "tailscale",
                "tag": collector.unique_tag(tag)?,
                "auth_key_credential_ref": credential_ref_json(&reference),
                "exit_node": exit_node,
            });
            if !control_url.is_empty() {
                endpoint["control_server"] = Value::String(control_url);
            }
            if !hostname.is_empty() {
                endpoint["hostname"] = Value::String(hostname);
            }
            if accept_routes {
                endpoint["accept_routes"] = Value::Bool(true);
            }
            if exit_node_allow_lan_access {
                endpoint["exit_node_allow_lan_access"] = Value::Bool(true);
            }
            Ok(endpoint)
        }
    }
}
