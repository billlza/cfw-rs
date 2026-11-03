//! DNS import owns syntax conversion; the profile crate validates policy.

use std::net::IpAddr;

use reqwest::Url;
use serde_json::{Value, json};

use super::{OutboundCollector, ProxyFields};

pub(super) fn import_dns(
    root: &mut ProxyFields,
    collector: &mut OutboundCollector,
) -> Result<(), String> {
    let hosts_value = root.take("hosts");
    let Some(value) = root.take("dns") else {
        import_hosts(root, collector, hosts_value)?;
        return Ok(());
    };
    let mut fields = ProxyFields::from_nested(value, root, "dns")?;
    if fields.take_bool("enable")? == Some(false) {
        return Err("Clash dns.enable=false requests the system resolver, which this DNS import does not support".into());
    }
    if fields.take_bool("use-hosts")? != Some(false) {
        import_hosts(root, collector, hosts_value)?;
    }
    let use_system_hosts = fields.take_bool("use-system-hosts")?.unwrap_or(true);
    let respect_rules = fields.take_bool("respect-rules")?.unwrap_or(false);
    let servers = fields
        .take_string_list("nameserver")?
        .ok_or("Clash dns.nameserver is missing")?
        .iter()
        .map(|source| resolver_with_route(source, respect_rules))
        .collect::<Result<Vec<_>, _>>()?;
    let mut policy = json!({"servers":servers,"use_system_hosts":use_system_hosts});
    if let Some(ipv6) = fields.take_bool("ipv6")? {
        policy["ipv6"] = json!(ipv6);
    }
    if let Some(servers) = fields.take_string_list("default-nameserver")? {
        let servers = servers.iter().map(|source| {
            if let Ok(address) = source.parse::<IpAddr>() { return Ok(json!(address)); }
            let server = resolver(source)?;
            if server["server"].as_str().is_none_or(|address| address.parse::<IpAddr>().is_err()) {
                return Err("Clash default-nameserver transports require numeric endpoints to avoid a bootstrap cycle".into());
            }
            Ok::<Value, String>(server)
        }).collect::<Result<Vec<_>, _>>()?;
        policy["bootstrap_servers"] = json!(servers);
    }
    for (source, target) in [
        ("proxy-server-nameserver", "proxy_servers"),
        ("direct-nameserver", "direct_servers"),
        ("fallback", "fallback_servers"),
    ] {
        if let Some(servers) = fields.take_string_list(source)? {
            policy[target] = json!(
                servers
                    .iter()
                    .map(|entry| resolver_with_route(
                        entry,
                        respect_rules && source != "proxy-server-nameserver"
                    ))
                    .collect::<Result<Vec<_>, _>>()?
            );
        }
    }
    for (source, target) in [
        ("nameserver-policy", "nameserver_policy"),
        ("proxy-server-nameserver-policy", "proxy_server_policy"),
    ] {
        if let Some(value) = fields.take(source) {
            let mut policies = ProxyFields::from_nested(value, &fields, "nameserver-policy")?;
            let mut entries = Vec::new();
            for domain in policies
                .entries
                .iter()
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>()
            {
                let servers = policies
                    .take_string_or_list(&domain)?
                    .ok_or("Clash nameserver-policy entry is empty")?;
                entries.push(json!({"domain":if domain.starts_with("rule-set:") { domain.clone() } else { domain.to_ascii_lowercase() },"servers":servers.iter().map(|entry| resolver_with_route(entry, respect_rules && source != "proxy-server-nameserver-policy")).collect::<Result<Vec<_>, _>>()?}));
            }
            policy[target] = json!(entries);
        }
    }
    if let Some(value) = fields.take("fallback-filter") {
        let mut filter = ProxyFields::from_nested(value, &fields, "fallback-filter")?;
        let geoip = filter.take_bool("geoip")?.unwrap_or(true);
        let code = filter
            .take_string("geoip-code")?
            .unwrap_or_else(|| "CN".into())
            .to_ascii_lowercase();
        let domain = filter.take_string_list("domain")?.unwrap_or_default();
        let cidr = filter.take_string_list("ipcidr")?.unwrap_or_default();
        let geosite = filter
            .take_string_list("geosite")?
            .unwrap_or_default()
            .into_iter()
            .map(|code| code.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if !filter.entries.is_empty() {
            return Err("Clash DNS fallback-filter contains an unsupported field".into());
        }
        policy["fallback_filter"] = json!({"domain":domain,"ip_cidr":cidr,"geosite":geosite});
        if geoip {
            policy["fallback_filter"]["geoip_code"] = json!(code);
        }
    } else if policy.get("fallback_servers").is_some() {
        policy["fallback_filter"] = json!({"geoip_code":"cn"});
    }
    if let Some(follow) = fields.take_bool("direct-nameserver-follow-policy")? {
        policy["direct_follow_policy"] = json!(follow);
    }
    let enhanced = fields
        .take_string("enhanced-mode")?
        .unwrap_or_else(|| "redir-host".into());
    let filter = fields
        .take_string_list("fake-ip-filter")?
        .unwrap_or_default();
    let range = fields.take_string("fake-ip-range")?;
    if fields
        .take_string("fake-ip-filter-mode")?
        .is_some_and(|mode| mode != "blacklist")
    {
        return Err("Clash fake-IP import currently supports blacklist filters".into());
    }
    match enhanced.as_str() {
        "fake-ip" => {
            // Clash's default pool overlaps the app-owned point-to-point TUN
            // subnet. Profile storage retains policy, never foreign addresses.
            if range.is_some_and(|range| {
                !matches!(
                    range.as_str(),
                    "198.18.0.1/16" | "198.18.0.0/16" | "198.19.0.0/16"
                )
            }) {
                return Err("Clash custom fake-IP ranges need explicit conversion; supported benchmark pools use the CFM-owned pool".into());
            }
            policy["fake_ip"] = json!({"exclude":filter});
        }
        "redir-host" => {}
        _ => return Err("Clash dns.enhanced-mode is unsupported".into()),
    }
    // Listeners are local application settings, not portable profile policy.
    fields.take_string("listen")?;
    // Unlike proxy socket tuning, no unknown DNS policy can be ignored.
    if !fields.entries.is_empty() {
        return Err(format!(
            "Clash DNS policy is unsupported: {}; no partial profile was saved",
            fields
                .entries
                .iter()
                .map(|(key, _)| super::sanitized_token(key))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    collector.dns = Some(policy);
    Ok(())
}

fn import_hosts(
    root: &ProxyFields,
    collector: &mut OutboundCollector,
    value: Option<super::YamlValue>,
) -> Result<(), String> {
    if let Some(value) = value {
        let mut hosts = ProxyFields::from_nested(value, root, "hosts")?;
        for name in hosts
            .entries
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>()
        {
            let addresses = hosts
                .take_string_or_list(&name)?
                .ok_or("Clash hosts entry is empty")?;
            if collector
                .hosts
                .insert(name.to_ascii_lowercase(), addresses)
                .is_some()
            {
                return Err("Clash hosts names must be unique regardless of case".into());
            }
        }
    }
    Ok(())
}

fn resolver_with_route(source: &str, respect_rules: bool) -> Result<Value, String> {
    let mut value = resolver(source)?;
    if respect_rules && !source.ends_with("#DIRECT") {
        value["route"] = json!("rules");
    }
    Ok(value)
}

fn resolver(source: &str) -> Result<Value, String> {
    if let Ok(address) = source.parse::<IpAddr>() {
        return Ok(json!({"type":"udp","server":address,"server_port":53,"route":"direct"}));
    }
    let url = Url::parse(source).map_err(|_| "Clash nameserver URL is invalid")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some_and(|fragment| fragment != "DIRECT")
        || url.query().is_some()
    {
        return Err("Clash nameserver URL credentials and modifiers are unsupported".into());
    }
    let address = url
        .host_str()
        .ok_or("Clash nameserver has no host")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let (kind, default_port) = match url.scheme() {
        "udp" => ("udp", 53),
        "tcp" => ("tcp", 53),
        "tls" => ("tls", 853),
        "quic" => ("quic", 853),
        "https" => ("https", 443),
        "h3" => ("h3", 443),
        _ => return Err("Clash nameserver transport is unsupported".into()),
    };
    let mut server = json!({"type":kind,"server":address,"server_port":url.port().unwrap_or(default_port),"route":"direct"});
    if !matches!(kind, "udp" | "tcp") {
        server["tls"] = json!({"enabled":true,"server_name":address});
    }
    if matches!(kind, "https" | "h3") {
        server["path"] = json!(if url.path().is_empty() || url.path() == "/" {
            "/dns-query"
        } else {
            url.path()
        });
    } else if !matches!(url.path(), "" | "/") {
        return Err("Clash nameserver transport does not accept a URL path".into());
    }
    Ok(server)
}

#[cfg(test)]
mod tests;
