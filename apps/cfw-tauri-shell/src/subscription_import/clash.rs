//! Clash/Mihomo YAML subscription conversion.
//!
//! Airport subscription endpoints negotiate on the `User-Agent` header and
//! answer Clash Meta clients with a YAML document whose `proxies` list carries
//! the modern protocol set (VLESS/Reality, Hysteria2, and the classic types).
//! Nodes, selector groups and supported routing rules are translated into the
//! typed profile schema. Listeners and operating-system DNS remain app-owned.
//! Unsupported routing behavior is rejected before any profile is stored.
//!
//! Conversion contract:
//!
//! - Every key of a proxy entry is either mapped onto the typed schema,
//!   listed in [`IGNORED_TUNING_KEYS`] (local socket tuning with no effect on
//!   destination, trust, or framing), or fails the import with the key name.
//! - Requests this app refuses to honour fail closed instead of being
//!   silently dropped: `skip-cert-verify: true` without a certificate
//!   `fingerprint` (beside one it asks for nothing more, below), Shadowsocks plugins,
//!   `udp-over-tcp`, `smux`, and every proxy type outside the
//!   closed schema. Hysteria2 port hopping accepts only canonical,
//!   non-overlapping port sets and a `hop-interval` of 5..=3600 seconds,
//!   either fixed or a range such as `15-30` that the pinned sing-box 1.14
//!   runtime randomizes up to `hop_interval_max`. Mihomo raises an interval
//!   under five seconds to five; here it fails the import instead. Gecko
//!   obfuscation sizes and `bbr-profile` map onto the same runtime fields.
//! - `ech-opts` with `enable: true` imports only an inline base64 `config`,
//!   which also pins TLS 1.3. An empty `config`, which Mihomo would look up
//!   over DNS, and `query-server-name` fail the import.
//! - `fingerprint` is Mihomo's SHA-256 of the server's DER leaf certificate,
//!   unrelated to `client-fingerprint`. It becomes one `certificate_sha256`
//!   pin, never a public-key pin. The pin replaces CA-chain trust for that
//!   node; the leaf must still be within its validity period, match the
//!   server name and permit server authentication. An empty value counts as
//!   absent; any other value that is not 64 hex digits (colons allowed) fails
//!   the import, as does a pin without TLS or beside `reality-opts`. Mihomo
//!   verifies a pinned node against the pin alone, so `skip-cert-verify:
//!   true` beside a pin is accepted and never emitted, as `insecure=1` beside
//!   a Hysteria2 link's `pinSHA256` is.
//! - `servername`/`sni`, `alpn`, and `client-fingerprint` are only mapped
//!   while TLS is enabled; without TLS they have no wire effect in Clash
//!   either, so dropping them preserves semantics. `client-fingerprint: none`
//!   keeps standard TLS, as in Mihomo.
//! - The top-level `global-client-fingerprint` is applied as Mihomo did
//!   until v1.19.27 removed it: a TLS VMess, VLESS, Trojan or AnyTLS node
//!   whose `client-fingerprint` is absent or empty gets it as its own uTLS
//!   fingerprint, and proxy providers store it for their refreshes. HTTP,
//!   Hysteria2 and TUIC nodes never took it. `none` or an empty value sets
//!   nothing and any other unsupported value fails the import. A V2Ray QUIC
//!   node that takes it fails like one naming a fingerprint itself.
//! - `reality-opts` needs a uTLS fingerprint from `client-fingerprint` or
//!   `global-client-fingerprint`: sing-box runs Reality only over uTLS, so a
//!   Reality node without one fails the import instead of the engine start.
//!   The app never picks one on its behalf.
//! - Node secrets keep their exact source bytes (the YAML loader never
//!   applies number resolution to them) and leave this module only as
//!   credential-vault entries, never inside the stored profile.

mod dns;
mod fields;
mod policy;
mod proxies;
pub(super) mod resources;
mod transport_options;

use fields::ProxyFields;
use proxies::{
    convert_anytls, convert_http_proxy, convert_hysteria2, convert_shadowsocks, convert_socks5,
    convert_trojan, convert_tuic, convert_vless, convert_vmess, convert_wireguard,
};

use cfw_singbox_config::{MAX_OUTBOUNDS, UtlsFingerprint};
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::socks5::Network as Socks5Network;
use super::wireguard;
use super::yaml::{YamlMapping, YamlScalar, YamlValue, load_single_document};
use super::{
    ImportedSubscription, OutboundCollector, TlsParts, build_tls_parts, canonical_uuid_credential,
    credential_ref_json, normalize_hysteria2_server_ports,
    normalize_shadowsocks_method_and_password, normalize_tuic_congestion_control,
    normalize_tuic_udp_relay_mode, normalize_v2ray_http_method, normalize_v2ray_packet_encoding,
    normalize_vless_flow, normalize_vmess_security, parse_hysteria2_bbr_profile,
    parse_hysteria2_hop_interval_range, parse_utls_fingerprint, parse_vmess_alter_id,
    sanitized_token, tls_json, transport_from_parts, utls_json,
};

/// Proxy-entry keys that only tune local socket behaviour. They change
/// neither the destination, nor credentials, nor TLS trust, nor framing, so
/// the projection's own defaults apply and the keys are accepted and ignored.
const IGNORED_TUNING_KEYS: &[&str] = &[
    "udp",
    "tfo",
    "mptcp",
    "ip-version",
    "interface-name",
    "routing-mark",
];

/// Converts one Clash/Mihomo YAML document into a validated subscription.
pub(super) fn import_clash_document(
    body: &str,
    mut collector: OutboundCollector,
) -> Result<ImportedSubscription, String> {
    let root = load_single_document(body)?;
    let YamlValue::Mapping(root) = root else {
        return Err("Clash subscription document must be a YAML mapping".to_owned());
    };
    let mut root = ProxyFields::new(root, "Clash profile".into());
    let global_fingerprint = take_global_client_fingerprint(&mut root)?;
    let proxies = root.take("proxies");
    if proxies.is_none()
        && !root
            .entries
            .iter()
            .any(|(key, _)| matches!(key.as_str(), "proxy-providers" | "rule-providers"))
    {
        return Err("Clash subscription has no proxies list or provider resources".into());
    }
    let proxies = proxies.unwrap_or_else(|| YamlValue::Sequence(Vec::new()));
    let YamlValue::Sequence(proxies) = proxies else {
        return Err("Clash proxies must be a YAML sequence".to_owned());
    };
    if proxies.len() > MAX_OUTBOUNDS {
        return Err(format!(
            "Clash subscription document has {} proxies; at most {MAX_OUTBOUNDS} are supported",
            proxies.len()
        ));
    }

    let mut names = BTreeMap::new();
    for (index, proxy) in proxies.into_iter().enumerate() {
        let context = format!("proxies[{index}]");
        let YamlValue::Mapping(proxy) = proxy else {
            return Err(format!("{context} must be a YAML mapping"));
        };
        let (source_name, outbound) = convert_proxy(
            &mut collector,
            ProxyFields::new(proxy, context),
            global_fingerprint,
        )?;
        let tag = outbound["tag"]
            .as_str()
            .ok_or("converted proxy has no tag")?
            .to_owned();
        if matches!(source_name.as_str(), "DIRECT" | "REJECT")
            || names.insert(source_name, tag).is_some()
        {
            return Err("Clash proxy names must be unique and cannot use DIRECT or REJECT".into());
        }
        collector.outbounds.push(outbound);
    }
    let mut providers =
        resources::import_providers(&mut root, &mut collector, &mut names, global_fingerprint)?;
    policy::import_policy(&mut root, &mut collector, names, &mut providers)?;
    if !providers.proxies.is_empty() || !providers.rules.is_empty() {
        collector.providers = Some(providers);
    }
    dns::import_dns(&mut root, &mut collector)?;
    collector.into_subscription()
}

/// Converts one proxy entry. `global_fingerprint` reaches only the TLS stream
/// types Mihomo gave its `global-client-fingerprint` to.
fn convert_proxy(
    collector: &mut OutboundCollector,
    mut fields: ProxyFields,
    global_fingerprint: Option<UtlsFingerprint>,
) -> Result<(String, Value), String> {
    let kind = fields.require_string("type")?;
    let name = fields.require_string("name")?;
    let source_name = name.clone();
    enforce_common_guards(&mut fields)?;
    let detour = fields.take_string("dialer-proxy")?;
    let outbound = match kind.as_str() {
        "http" => convert_http_proxy(collector, &mut fields, name)?,
        "socks5" => convert_socks5(collector, &mut fields, name)?,
        "ss" => convert_shadowsocks(collector, &mut fields, name)?,
        "vmess" => convert_vmess(collector, &mut fields, name, global_fingerprint)?,
        "vless" => convert_vless(collector, &mut fields, name, global_fingerprint)?,
        "trojan" => convert_trojan(collector, &mut fields, name, global_fingerprint)?,
        "hysteria2" => convert_hysteria2(collector, &mut fields, name)?,
        "anytls" => convert_anytls(collector, &mut fields, name, global_fingerprint)?,
        "tuic" => convert_tuic(collector, &mut fields, name)?,
        "wireguard" => convert_wireguard(collector, &mut fields, name)?,
        other => {
            return Err(format!(
                "{} has a proxy type outside the supported set (socks5, ss, vmess, vless, trojan, hysteria2, anytls, tuic): {}",
                fields.context(),
                sanitized_token(other)
            ));
        }
    };
    fields.reject_leftovers()?;
    if let Some(detour) = detour {
        collector.detours.insert(source_name.clone(), detour);
    }
    Ok((source_name, outbound))
}

/// Fails closed on requests the closed schema cannot honour, independent of
/// the proxy type. `skip-cert-verify: true` beside a non-empty `fingerprint`
/// asks for nothing more than the pin: Mihomo then verifies the node against
/// the pin alone, and `collect_tls` turns it into the only trust anchor (or
/// fails the import when it is malformed, without TLS, beside `reality-opts`,
/// or on a type without TLS, whose leftover keys are refused).
fn enforce_common_guards(fields: &mut ProxyFields) -> Result<(), String> {
    if fields.take_bool("skip-cert-verify")?.unwrap_or(false) && !fields.has_text("fingerprint") {
        return Err(format!(
            "{} requires disabling TLS certificate verification, which this app refuses",
            fields.context()
        ));
    }
    if fields.take("smux").is_some() {
        return Err(format!(
            "{} uses stream multiplexing (smux), which is not supported",
            fields.context()
        ));
    }
    Ok(())
}

use tls::{collect_tls, take_global_client_fingerprint};
mod tls;
