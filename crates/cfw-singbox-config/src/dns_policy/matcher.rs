//! DNS domain selectors share dataset identities with route projection. Provider
//! references expand only domain conditions; address rules cannot select a DNS
//! server before the answer exists.
use crate::{ConfigError, DomainPattern, profile::ProfileDocument, routing::RuleKind};
use serde_json::{Value, json};

pub(super) enum DnsMatcher {
    Domain(DomainPattern),
    Geosite(Vec<String>),
    Providers(Vec<String>),
}

impl DnsMatcher {
    pub(super) fn parse(value: &str) -> Result<Self, ConfigError> {
        let (kind, values) = if let Some(values) = value.strip_prefix("geosite:") {
            (true, values)
        } else if let Some(values) = value.strip_prefix("rule-set:") {
            (false, values)
        } else {
            if value.parse::<std::net::IpAddr>().is_ok() {
                return Err(super::invalid("DNS policy domain cannot be an IP address"));
            }
            return Ok(Self::Domain(DomainPattern::parse(value)?));
        };
        let values = values.split(',').map(str::to_owned).collect::<Vec<_>>();
        if values.is_empty()
            || values.len() > 32
            || values.iter().any(|value| {
                value.is_empty()
                    || value.len() > 128
                    || value.trim() != value
                    || value.chars().any(char::is_control)
            })
        {
            return Err(super::invalid(
                "DNS dataset selectors require one to 32 bounded names",
            ));
        }
        if kind {
            for value in &values {
                validate_geosite(value)?;
            }
            Ok(Self::Geosite(values))
        } else {
            Ok(Self::Providers(values))
        }
    }

    pub(super) fn condition(&self, document: &ProfileDocument) -> Result<Value, ConfigError> {
        match self {
            Self::Domain(pattern) => Ok(pattern.condition()),
            Self::Geosite(codes) => Ok(
                json!({"rule_set":codes.iter().map(|code| format!("cfw-geosite-{code}")).collect::<Vec<_>>()}),
            ),
            Self::Providers(names) => {
                let mut tags = Vec::new();
                for name in names {
                    let (index, provider) = document
                        .providers
                        .as_ref()
                        .and_then(|catalog| {
                            catalog
                                .rules
                                .iter()
                                .enumerate()
                                .find(|(_, provider)| &provider.name == name)
                        })
                        .ok_or_else(|| {
                            super::invalid("DNS rule-set references an undeclared rule provider")
                        })?;
                    if provider.rules.is_empty()
                        || provider.rules.iter().any(|rule| {
                            !matches!(
                                rule.kind,
                                RuleKind::Domain
                                    | RuleKind::DomainSuffix
                                    | RuleKind::DomainKeyword
                                    | RuleKind::DomainRegex
                            )
                        })
                    {
                        return Err(super::invalid(
                            "DNS rule-set providers must contain only domain conditions",
                        ));
                    }
                    tags.push(format!("cfw-dns-provider-{index}"));
                }
                Ok(json!({"rule_set":tags}))
            }
        }
    }
}

pub(super) fn validate_geosite(code: &str) -> Result<(), ConfigError> {
    if code.is_empty()
        || code.len() > 96
        || !code.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'@' | b'_' | b'!')
        })
    {
        return Err(super::invalid(
            "geosite names require lowercase dataset identifiers",
        ));
    }
    Ok(())
}

pub(super) fn ordered_policies(
    policies: &[super::DomainDnsPolicy],
) -> Vec<(usize, &super::DomainDnsPolicy)> {
    // Dataset matchers retain source order. A contiguous domain-tree segment
    // uses exact/suffix specificity, as in Clash's domain trie.
    let mut ordered = policies.iter().enumerate().collect::<Vec<_>>();
    let mut start = 0;
    while start < ordered.len() {
        if !matches!(
            DnsMatcher::parse(&ordered[start].1.domain),
            Ok(DnsMatcher::Domain(_))
        ) {
            start += 1;
            continue;
        }
        let end = (start..ordered.len())
            .find(|index| {
                !matches!(
                    DnsMatcher::parse(&ordered[*index].1.domain),
                    Ok(DnsMatcher::Domain(_))
                )
            })
            .unwrap_or(ordered.len());
        ordered[start..end].sort_by_key(|(_, policy)| {
            std::cmp::Reverse(DomainPattern::specificity(&policy.domain))
        });
        start = end;
    }
    ordered
}

pub(super) fn dataset_rule_sets(
    document: &ProfileDocument,
    download_outbound: &str,
) -> Result<Vec<Value>, ConfigError> {
    let dns = document.dns.as_ref().expect("DNS policy");
    let mut geosite = std::collections::BTreeSet::new();
    let mut providers = std::collections::BTreeSet::new();
    let patterns = dns
        .nameserver_policy
        .iter()
        .chain(&dns.proxy_server_policy)
        .map(|policy| policy.domain.as_str())
        .chain(
            dns.fallback_filter
                .iter()
                .flat_map(|filter| filter.domain.iter().map(String::as_str)),
        )
        .chain(
            dns.fake_ip
                .iter()
                .flat_map(|policy| policy.exclude.iter().map(String::as_str)),
        );
    for pattern in patterns {
        match DnsMatcher::parse(pattern)? {
            DnsMatcher::Geosite(codes) => geosite.extend(codes),
            DnsMatcher::Providers(names) => providers.extend(names),
            DnsMatcher::Domain(_) => {}
        }
    }
    if let Some(filter) = &dns.fallback_filter {
        geosite.extend(filter.geosite.iter().cloned());
    }
    let mut resources = Vec::new();
    for name in providers {
        let (index, provider) = document
            .providers
            .as_ref()
            .and_then(|catalog| {
                catalog
                    .rules
                    .iter()
                    .enumerate()
                    .find(|(_, provider)| provider.name == name)
            })
            .expect("validated DNS provider");
        let conditions = provider
            .rules
            .iter()
            .map(|rule| {
                let key = match rule.kind {
                    RuleKind::Domain => "domain",
                    RuleKind::DomainSuffix => "domain_suffix",
                    RuleKind::DomainKeyword => "domain_keyword",
                    RuleKind::DomainRegex => "domain_regex",
                    _ => unreachable!("validated DNS condition"),
                };
                json!({key:rule.value})
            })
            .collect::<Vec<_>>();
        resources.push(
            json!({"type":"inline","tag":format!("cfw-dns-provider-{index}"),"rules":conditions}),
        );
    }
    for code in geosite {
        resources.push(json!({"type":"remote","tag":format!("cfw-geosite-{code}"),"format":"binary","url":format!("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{code}.srs"),"download_detour":download_outbound,"update_interval":"1d"}));
    }
    if let Some(code) = dns
        .fallback_filter
        .as_ref()
        .and_then(|filter| filter.geoip_code.as_ref())
    {
        resources.push(json!({"type":"remote","tag":format!("cfw-geoip-{code}"),"format":"binary","url":format!("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{code}.srs"),"download_detour":download_outbound,"update_interval":"1d"}));
    }
    Ok(resources)
}
