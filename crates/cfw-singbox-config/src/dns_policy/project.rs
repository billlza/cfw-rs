//! Compile validated DNS roles without changing the selected traffic route.
use serde_json::{Value, json};

use super::ProfileDnsServer;
use crate::{ConfigError, profile::ProfileDocument};

pub(crate) struct DnsPolicyProjection {
    pub(crate) servers: Vec<Value>,
    pub(crate) rules: Vec<Value>,
    pub(crate) final_server: String,
    pub(crate) default_resolver: Value,
    pub(crate) policies: Vec<Value>,
    pub(crate) rule_sets: Vec<Value>,
}

pub(crate) fn resolver_tags(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{prefix}-{index}"))
        .collect()
}

pub(crate) fn resolver_value(tags: &[String]) -> Value {
    let mut resolver = json!({"server":tags[0]});
    if tags.len() == 2 {
        resolver["fallback_server"] = json!(tags[1]);
    } else if tags.len() > 2 {
        resolver["fallback_servers"] = json!(&tags[1..]);
    }
    resolver
}

fn append_pool(
    output: &mut Vec<Value>,
    servers: &[ProfileDnsServer],
    prefix: &str,
    outbound: Option<&str>,
    bootstrap: &Value,
    ipv6: bool,
    default_direct: bool,
) -> Result<Vec<String>, ConfigError> {
    let tags = resolver_tags(prefix, servers.len());
    for (server, tag) in servers.iter().zip(&tags) {
        if server.address().is_some_and(|address| address.is_ipv6()) && !ipv6 {
            return Err(super::invalid("IPv6 resolver requires IPv6 to be enabled"));
        }
        output.push(server.project(
            tag,
            outbound.filter(|_| {
                !default_direct || server.route() == Some(super::DnsResolverRoute::Selected)
            }),
            bootstrap,
        )?);
    }
    Ok(tags)
}

// A terminal rule for each matched pool prevents failed policy queries from
// continuing into an unrelated DNS policy or a direct bootstrap resolver.
fn append_pool_rules(rules: &mut Vec<Value>, tags: &[String], condition: &Value) {
    for (index, tag) in tags.iter().enumerate() {
        let mut rule = condition.clone();
        if index + 1 != tags.len() {
            rule["retry_on_error"] = json!(true);
        }
        rule["action"] = json!("route");
        rule["server"] = json!(tag);
        rules.push(rule);
    }
}

pub(crate) fn project_profile_dns(
    document: &ProfileDocument,
    selected_outbound: &str,
    bootstrap: &Value,
    ipv6: bool,
) -> Result<DnsPolicyProjection, ConfigError> {
    let dns = document.dns.as_ref().expect("DNS policy exists");
    let mut servers = Vec::new();
    let ordinary = append_pool(
        &mut servers,
        &dns.servers,
        "cfw-profile-dns",
        Some(selected_outbound),
        bootstrap,
        ipv6,
        false,
    )?;
    let mut policies = Vec::new();
    for (pool, policy, prefix, tag, is_proxy) in [
        (
            &dns.proxy_servers,
            dns.proxy_server_policy.as_slice(),
            "cfw-proxy-server-dns",
            "cfw-proxy-endpoint",
            true,
        ),
        (
            &dns.direct_servers,
            if dns.direct_follow_policy {
                dns.nameserver_policy.as_slice()
            } else {
                &[]
            },
            "cfw-direct-dns",
            "cfw-direct",
            false,
        ),
    ] {
        if let Some(pool) = pool {
            let tags = append_pool(
                &mut servers,
                pool,
                prefix,
                (!is_proxy).then_some(selected_outbound),
                bootstrap,
                ipv6,
                true,
            )?;
            let mut role_rules = Vec::new();
            for (index, entry) in super::matcher::ordered_policies(policy) {
                let policy_prefix = if is_proxy {
                    format!("cfw-proxy-policy-{index}")
                } else {
                    format!("cfw-policy-dns-{index}")
                };
                let target_tags = if is_proxy {
                    append_pool(
                        &mut servers,
                        &entry.servers,
                        &policy_prefix,
                        None,
                        bootstrap,
                        ipv6,
                        true,
                    )?
                } else {
                    resolver_tags(&policy_prefix, entry.servers.len())
                };
                append_pool_rules(
                    &mut role_rules,
                    &target_tags,
                    &super::matcher::DnsMatcher::parse(&entry.domain)?.condition(document)?,
                );
            }
            if !policy.is_empty() {
                append_pool_rules(&mut role_rules, &tags, &json!({"domain_regex":".*"}));
                policies.push(json!({"tag":tag,"rules":role_rules,"final":tags.last().expect("validated resolver pool")}));
            }
        }
    }
    let mut rules = Vec::new();
    for (index, policy) in super::matcher::ordered_policies(&dns.nameserver_policy) {
        let tags = append_pool(
            &mut servers,
            &policy.servers,
            &format!("cfw-policy-dns-{index}"),
            Some(selected_outbound),
            bootstrap,
            ipv6,
            false,
        )?;
        append_pool_rules(
            &mut rules,
            &tags,
            &super::matcher::DnsMatcher::parse(&policy.domain)?.condition(document)?,
        );
    }
    let mut default_tags = ordinary.clone();
    let fallback = dns
        .fallback_servers
        .as_ref()
        .map(|pool| {
            append_pool(
                &mut servers,
                pool,
                "cfw-fallback-dns",
                Some(selected_outbound),
                bootstrap,
                ipv6,
                false,
            )
        })
        .transpose()?;
    if let Some(fallback) = &fallback {
        if let Some(filter) = &dns.fallback_filter {
            if !filter.geosite.is_empty() {
                append_pool_rules(
                    &mut rules,
                    fallback,
                    &json!({"rule_set":filter.geosite.iter().map(|code| format!("cfw-geosite-{code}")).collect::<Vec<_>>()}),
                );
            }
            for domain in &filter.domain {
                append_pool_rules(
                    &mut rules,
                    fallback,
                    &super::matcher::DnsMatcher::parse(domain)?.condition(document)?,
                );
            }
        }
        default_tags.extend(fallback.iter().cloned());
    }
    // IP response filters apply to A/AAAA and HTTPS address hints. Other DNS record types still
    // traverse the complete ordered pool; they must not jump to its last server.
    if dns
        .fallback_filter
        .as_ref()
        .is_some_and(|filter| !filter.ip_cidr.is_empty() || filter.geoip_code.is_some())
    {
        append_pool_rules(
            &mut rules,
            &default_tags,
            &json!({"query_type":["A","AAAA","HTTPS"],"invert":true}),
        );
    }
    for (index, tag) in ordinary.iter().enumerate() {
        let mut rule = if let Some(filter) = dns
            .fallback_filter
            .as_ref()
            .filter(|filter| !filter.ip_cidr.is_empty() || filter.geoip_code.is_some())
        {
            {
                let mut conditions = vec![json!({"ip_accept_any":true})];
                if !filter.ip_cidr.is_empty() {
                    conditions.push(json!({"ip_cidr":filter.ip_cidr,"invert":true}));
                }
                if let Some(country) = &filter.geoip_code {
                    conditions.push(json!({"rule_set":[format!("cfw-geoip-{country}")]}));
                }
                json!({"type":"logical","mode":"and","rules":conditions,"response_ip_accept_all":true})
            }
        } else {
            json!({"domain_regex":".*"})
        };
        // The final server is emitted as dns.final, preserving existing profile
        // projections and avoiding a redundant terminal lookup.
        if fallback.is_none() && index + 1 == ordinary.len() {
            break;
        }
        rule["action"] = json!("route");
        rule["server"] = json!(tag);
        rule["retry_on_error"] = json!(true);
        rules.push(rule);
    }
    if let Some(fallback) = &fallback {
        for tag in &fallback[..fallback.len() - 1] {
            rules.push(
                json!({"domain_regex":".*","retry_on_error":true,"action":"route","server":tag}),
            );
        }
    }
    Ok(DnsPolicyProjection {
        servers,
        rules,
        final_server: default_tags.last().expect("validated DNS pool").clone(),
        default_resolver: json!({"policy":"default"}),
        policies,
        rule_sets: super::matcher::dataset_rule_sets(document, selected_outbound)?,
    })
}

pub(crate) fn add_connection_dns_rules(
    document: &ProfileDocument,
    rules: &mut Vec<Value>,
    direct_outbound: &str,
    final_outbound: &str,
) {
    let Some(dns) = &document.dns else {
        return;
    };
    if dns.nameserver_policy.is_empty() && dns.fallback_filter.is_none() {
        return;
    }
    let mut projected = Vec::new();
    for rule in rules.drain(..) {
        if rule["action"] == "route"
            && (rule["outbound"] != direct_outbound || dns.direct_servers.is_none())
        {
            let mut condition = rule.clone();
            let object = condition.as_object_mut().expect("projected route rule");
            object.remove("action");
            object.remove("outbound");
            projected.push(json!({"type":"logical","mode":"and","rules":[condition,{"domain_regex":"."}],"action":"resolve"}));
        }
        projected.push(rule);
    }
    if final_outbound != direct_outbound || dns.direct_servers.is_none() {
        projected.push(json!({"domain_regex":".","action":"resolve"}));
    }
    // No explicit server: these incoming HTTP/SOCKS hostname lookups traverse
    // DNS rules just like a TUN DNS query. Explicit direct routes terminate
    // before these resolves and retain their separate direct-nameserver role.
    *rules = projected;
}
