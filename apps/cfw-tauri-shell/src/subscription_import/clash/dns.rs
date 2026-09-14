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
mod tests {
    use super::resolver;
    use crate::subscription_import::import_subscription_document;
    use serde_json::{Value, json};

    const SOURCE: &str = r#"
proxies:
  - {name: example, type: socks5, server: node.example.com, port: 1080}
hosts:
  node.example.com: 9.9.9.9
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: ['+.lan', '*.local', localhost, '+.example.com']
  default-nameserver: [8.8.8.8, 1.1.1.1]
  nameserver: [https://8.8.8.8/dns-query, https://1.1.1.1/dns-query]
"#;

    #[test]
    fn cfw_dns_hosts_and_fake_ip_policy_survive_import() {
        let imported = import_subscription_document(SOURCE).expect("Clash import");
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("profile JSON");
        assert_eq!(profile["hosts"], json!({"node.example.com":["9.9.9.9"]}));
        assert_eq!(profile["dns"]["ipv6"], false);
        assert_eq!(
            profile["dns"]["bootstrap_servers"],
            json!(["8.8.8.8", "1.1.1.1"])
        );
        assert_eq!(
            profile["dns"]["servers"][0]["tls"]["server_name"],
            "8.8.8.8"
        );
        assert_eq!(
            profile["dns"]["fake_ip"]["exclude"],
            json!(["+.lan", "*.local", "localhost", "+.example.com"])
        );
        assert!(imported.credentials.is_empty());
    }

    #[test]
    fn clash_routed_and_direct_dns_compose_without_changing_bootstrap() {
        let text = format!(
            "{SOURCE}\n  respect-rules: true\n  proxy-server-nameserver: [223.5.5.5]\n  direct-nameserver: [119.29.29.29]\n  direct-nameserver-follow-policy: true\n  nameserver-policy: {{'+.example.org': 1.1.1.1}}\n"
        );
        let imported = import_subscription_document(&text).unwrap();
        let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
        assert_eq!(profile["dns"]["servers"][0]["route"], "rules");
        assert_eq!(profile["dns"]["direct_servers"][0]["route"], "rules");
        assert_eq!(profile["dns"]["proxy_servers"][0]["route"], "direct");
        assert_eq!(
            profile["dns"]["nameserver_policy"][0]["servers"][0]["route"],
            "rules"
        );
        assert_eq!(profile["dns"]["direct_follow_policy"], true);
        assert!(
            import_subscription_document(
                &text.replace("  proxy-server-nameserver: [223.5.5.5]\n", "")
            )
            .is_err()
        );
        assert_eq!(
            super::resolver_with_route("https://1.1.1.1/dns-query#DIRECT", true).unwrap()["route"],
            "direct"
        );
    }

    #[test]
    fn disabled_profile_hosts_do_not_reject_ignored_entries() {
        let source = SOURCE.replace(
            "node.example.com: 9.9.9.9",
            "node.example.com: {ignored: true}",
        );
        let imported = import_subscription_document(&format!(
            "{source}\n  use-hosts: false\n  use-system-hosts: true\n"
        ))
        .unwrap();
        let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
        assert!(profile.get("hosts").is_none());
        assert_eq!(profile["dns"]["use_system_hosts"], true);
    }

    #[test]
    fn dns_policy_is_never_silently_dropped() {
        for extra in [
            "  nameserver-policy: {'geosite:../cn': 1.1.1.1}",
            "  prefer-h3: true",
        ] {
            assert!(import_subscription_document(&format!("{SOURCE}\n{extra}\n")).is_err());
        }
        for (old, new) in [
            ("enable: true", "enable: false"),
            ("198.18.0.1/16", "10.0.0.0/8"),
            (
                "https://8.8.8.8/dns-query",
                "https://user:secret@8.8.8.8/dns-query",
            ),
        ] {
            assert!(import_subscription_document(&SOURCE.replace(old, new)).is_err());
        }
    }
    #[test]
    fn domain_dns_and_separate_roles_are_imported_with_explicit_bootstrap() {
        let source = SOURCE.replace("default-nameserver: [8.8.8.8, 1.1.1.1]", "default-nameserver: [8.8.8.8]")
            .replace("nameserver: [https://8.8.8.8/dns-query, https://1.1.1.1/dns-query]", "nameserver: [https://dns.example.com/dns-query, tls://one.example.com, quic://two.example.com, h3://three.example.com/dns-query]");
        let source = format!(
            "{source}\n  nameserver-policy: {{'+.internal.example': '10.0.0.53', 'exact.example': [1.1.1.1, 8.8.8.8, 9.9.9.9]}}\n  proxy-server-nameserver: [223.5.5.5]\n  direct-nameserver: [119.29.29.29]\n"
        );
        let imported = import_subscription_document(&source).expect("DNS roles");
        let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
        assert_eq!(profile["dns"]["servers"][0]["server"], "dns.example.com");
        assert_eq!(
            profile["dns"]["servers"][0]["tls"]["server_name"],
            "dns.example.com"
        );
        assert_eq!(
            profile["dns"]["nameserver_policy"][1]["servers"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(profile["dns"]["proxy_servers"][0]["server"], "223.5.5.5");
        assert_eq!(
            profile["dns"]["direct_servers"][0]["server"],
            "119.29.29.29"
        );
        assert!(
            import_subscription_document(&source.replace("  default-nameserver: [8.8.8.8]\n", ""))
                .is_err()
        );
        assert!(
            import_subscription_document(&source.replace(
                "default-nameserver: [8.8.8.8]",
                "default-nameserver: [dns.example.com]"
            ))
            .is_err()
        );
    }

    #[test]
    fn clash_fallback_filter_semantics_are_retained_or_explicitly_rejected() {
        let source = format!(
            "{SOURCE}\n  fallback: [8.8.4.4]\n  fallback-filter:\n    geoip: false\n    domain: ['+.fallback.example']\n    ipcidr: ['240.0.0.0/4']\n"
        );
        let imported = import_subscription_document(&source).expect("explicit supported filter");
        let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
        assert_eq!(
            profile["dns"]["fallback_filter"]["ip_cidr"],
            json!(["240.0.0.0/4"])
        );
        let geoip =
            import_subscription_document(&source.replace("geoip: false", "geoip: true")).unwrap();
        let geoip: Value = serde_json::from_str(geoip.profile.as_json()).unwrap();
        assert_eq!(geoip["dns"]["fallback_filter"]["geoip_code"], "cn");
        let implicit =
            import_subscription_document(&format!("{SOURCE}\n  fallback: [8.8.4.4]\n")).unwrap();
        let implicit: Value = serde_json::from_str(implicit.profile.as_json()).unwrap();
        assert_eq!(implicit["dns"]["fallback_filter"]["geoip_code"], "cn");
        let geosite =
            import_subscription_document(&format!("{source}    geosite: [cn]\n")).unwrap();
        let geosite: Value = serde_json::from_str(geosite.profile.as_json()).unwrap();
        assert_eq!(geosite["dns"]["fallback_filter"]["geosite"], json!(["cn"]));
        for suffix in ["#skip-cert-verify", "#proxy", "?insecure=true"] {
            assert!(resolver(&format!("https://dns.example.com/dns-query{suffix}")).is_err());
        }
    }
}
