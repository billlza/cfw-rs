//! Mainland China direct: the routing and DNS the application adds, in Rule
//! mode, for a user in mainland China. It applies to any profile whose
//! selected route is remote, with or without country rules of its own (an
//! outbound-only file has none).
//!
//! Route rules follow the profile's own rules and precede its final outbound,
//! so the profile's own rules always take precedence: GeoSite `cn` goes
//! DIRECT, GeoSite `geolocation-!cn` is matched by name and goes to the
//! profile's route, and the remaining names are resolved and go DIRECT when
//! the address is in GeoIP `CN`. These rules add no lookup before the
//! `geolocation-!cn` match, but a profile that resolves names itself still
//! does: each of its IP or GeoIP rules without `no_resolve` resolves first, and
//! with a nameserver policy or fallback filter every route rule does. The
//! GeoSite rules need the destination's name, which System Proxy connections
//! carry; Tunnel connections without fake-IP carry only the address, so there
//! the GeoIP rule decides. For the application's own DNS, used by profiles
//! without their own `dns`, mainland names in Rule mode are answered by
//! domestic DNS-over-HTTPS dialled DIRECT; every other name uses a foreign pool
//! through the selected route, because a domestic resolver reached through a
//! foreign proxy still answers blocked names with censored addresses.

use std::net::{IpAddr, Ipv4Addr};

use serde_json::{Value, json};

use crate::engine_settings::AuthenticatedDnsServer;
use crate::routing::{ProfileRule, RuleKind};

const MAINLAND_SITES: &str = "cn";
const FOREIGN_SITES: &str = "geolocation-!cn";
const MAINLAND_ADDRESSES: &str = "CN";
const MAINLAND_DNS_PREFIX: &str = "cfw-mainland-dns";

fn resolver(address: [u8; 4], server_name: &str) -> AuthenticatedDnsServer {
    AuthenticatedDnsServer {
        address: IpAddr::V4(Ipv4Addr::from(address)),
        server_name: server_name.to_owned(),
    }
}

/// AliDNS, then DNSPod: independent operators whose DoH endpoints are reached
/// directly from mainland networks. Both names and chains were verified on
/// 2026-10-15.
pub(crate) fn domestic_resolvers() -> [AuthenticatedDnsServer; 2] {
    [
        resolver([223, 5, 5, 5], "dns.alidns.com"),
        resolver([1, 12, 12, 12], "doh.pub"),
    ]
}

/// Cloudflare, then Google, reached through the selected route.
pub(crate) fn foreign_resolvers() -> [AuthenticatedDnsServer; 2] {
    [
        resolver([1, 1, 1, 1], "cloudflare-dns.com"),
        resolver([8, 8, 8, 8], "dns.google"),
    ]
}

/// The route rules appended after the profile's own rules.
pub(crate) fn route_rules(direct_outbound: &str, proxied_outbound: &str) -> [ProfileRule; 3] {
    let rule = |kind, value: &str, outbound: &str| ProfileRule {
        kind,
        value: value.to_owned(),
        outbound: outbound.to_owned(),
        no_resolve: false,
    };
    [
        rule(RuleKind::GeoSite, MAINLAND_SITES, direct_outbound),
        rule(RuleKind::GeoSite, FOREIGN_SITES, proxied_outbound),
        rule(RuleKind::GeoIp, MAINLAND_ADDRESSES, direct_outbound),
    ]
}

/// The domestic DoH servers, tagged `cfw-mainland-dns-<n>`. They carry no
/// detour: the ordinary dialer goes DIRECT.
pub(crate) fn dns_servers(project: impl Fn(&str, &AuthenticatedDnsServer) -> Value) -> Vec<Value> {
    domestic_resolvers()
        .iter()
        .enumerate()
        .map(|(index, server)| project(&format!("{MAINLAND_DNS_PREFIX}-{index}"), server))
        .collect()
}

/// The DNS rules that send mainland names, in Rule mode only, to the domestic
/// pool. The pool is terminal: a failed domestic lookup never falls through
/// to the foreign pool, and Global and Direct mode queries never match.
pub(crate) fn dns_rules() -> Vec<Value> {
    let condition = json!({
        "clash_mode": "Rule",
        "rule_set": [crate::datasets::Dataset::GeoSite(
            crate::datasets::GeositeCode::parse(MAINLAND_SITES).expect("published GeoSite name")
        )
        .tag()],
    });
    let tags = crate::dns_policy::resolver_tags(MAINLAND_DNS_PREFIX, domestic_resolvers().len());
    let mut rules = Vec::new();
    crate::dns_policy::append_pool_rules(&mut rules, &tags, &condition);
    rules
}
