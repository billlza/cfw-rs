//! DNS import owns syntax conversion; the profile crate validates policy.

use std::net::IpAddr;

use reqwest::Url;
use serde_json::{Value, json};

use super::{OutboundCollector, ProxyFields};

pub(super) fn import_dns(
    root: &mut ProxyFields,
    collector: &mut OutboundCollector,
) -> Result<(), String> {
    if let Some(value) = root.take("hosts") {
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
    let Some(value) = root.take("dns") else {
        return Ok(());
    };
    let mut fields = ProxyFields::from_nested(value, root, "dns")?;
    if fields.take_bool("enable")? == Some(false) {
        return Err("Clash dns.enable=false requests the system resolver, which this DNS import does not support".into());
    }
    if fields.take_bool("use-hosts")? == Some(false) && !collector.hosts.is_empty() {
        return Err("Clash dns.use-hosts=false conflicts with imported hosts overrides".into());
    }
    if fields.take_bool("use-system-hosts")? == Some(true) {
        return Err("Clash dns.use-system-hosts requires system hosts import support".into());
    }
    let servers = fields
        .take_string_list("nameserver")?
        .ok_or("Clash dns.nameserver is missing")?
        .iter()
        .map(|source| resolver(source))
        .collect::<Result<Vec<_>, _>>()?;
    let mut policy = json!({"servers":servers});
    if let Some(ipv6) = fields.take_bool("ipv6")? {
        policy["ipv6"] = json!(ipv6);
    }
    if let Some(servers) = fields.take_string_list("default-nameserver")? {
        let servers = servers
            .iter()
            .map(|server| {
                server
                    .parse::<IpAddr>()
                    .map_err(|_| "Clash default-nameserver requires numeric IP addresses")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if servers.len() != 2 {
            return Err(
                "Clash default-nameserver requires two distinct bootstrap resolvers".into(),
            );
        }
        policy["bootstrap_servers"] = json!(servers);
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

fn resolver(source: &str) -> Result<Value, String> {
    if let Ok(address) = source.parse::<IpAddr>() {
        return Ok(json!({"type":"udp","server":address,"server_port":53}));
    }
    let url = Url::parse(source).map_err(|_| "Clash nameserver URL is invalid")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err("Clash nameserver URL credentials and modifiers are unsupported".into());
    }
    let address = url.host_str().ok_or("Clash nameserver has no host")?.trim_start_matches('[').trim_end_matches(']')
        .parse::<IpAddr>().map_err(|_| "Clash encrypted nameserver requires a numeric address to avoid bootstrap recursion")?;
    let (kind, default_port) = match url.scheme() {
        "udp" => ("udp", 53),
        "tcp" => ("tcp", 53),
        "tls" => ("tls", 853),
        "quic" => ("quic", 853),
        "https" => ("https", 443),
        "h3" => ("h3", 443),
        _ => return Err("Clash nameserver transport is unsupported".into()),
    };
    let mut server =
        json!({"type":kind,"server":address,"server_port":url.port().unwrap_or(default_port)});
    if !matches!(kind, "udp" | "tcp") {
        server["tls"] = json!({"enabled":true,"server_name":address.to_string()});
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
    fn dns_policy_is_never_silently_dropped() {
        for extra in [
            "  nameserver-policy: {example.com: 1.1.1.1}",
            "  fallback-filter: {geoip: true}",
            "  fallback: [8.8.4.4]",
            "  prefer-h3: true",
        ] {
            assert!(
                import_subscription_document(&format!("{SOURCE}\n{extra}\n"))
                    .expect_err("unsupported DNS")
                    .contains("DNS policy is unsupported")
            );
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
}
