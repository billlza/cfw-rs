//! DNS domain selectors share dataset identities with route projection. Provider
//! references expand only domain conditions; address rules cannot select a DNS
//! server before the answer exists.
use std::collections::BTreeSet;

use crate::datasets::{CountryCode, Dataset, GeositeCode};
use crate::{ConfigError, DomainPattern, profile::ProfileDocument, routing::RuleKind};
use serde_json::{Value, json};

pub(super) enum DnsMatcher {
    Domain(DomainPattern),
    Geosite(Vec<GeositeCode>),
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
            Ok(Self::Geosite(
                values
                    .iter()
                    .map(|value| validate_geosite(value))
                    .collect::<Result<_, _>>()?,
            ))
        } else {
            Ok(Self::Providers(values))
        }
    }

    pub(super) fn condition(&self, document: &ProfileDocument) -> Result<Value, ConfigError> {
        match self {
            Self::Domain(pattern) => Ok(pattern.condition()),
            Self::Geosite(codes) => Ok(json!({"rule_set":codes
                .iter()
                .map(|code| Dataset::GeoSite(code.clone()).tag())
                .collect::<Vec<_>>()})),
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

pub(super) fn validate_geosite(code: &str) -> Result<GeositeCode, ConfigError> {
    GeositeCode::parse(code)
        .ok_or_else(|| super::invalid("geosite names must be published sing-geosite dataset names"))
}

/// A DNS policy writes its GeoIP code in lowercase.
pub(super) fn validate_geoip_code(code: &str) -> Result<CountryCode, ConfigError> {
    CountryCode::parse(code)
        .filter(|_| code.bytes().all(|byte| byte.is_ascii_lowercase()))
        .ok_or_else(|| {
            super::invalid("DNS GeoIP code requires a lowercase two-letter country code")
        })
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

/// The rule providers and GeoSite datasets that a validated profile's DNS
/// selectors name, plus the fallback filter's GeoIP dataset.
fn dns_dataset_names(
    document: &ProfileDocument,
) -> Result<(BTreeSet<String>, BTreeSet<Dataset>), ConfigError> {
    let dns = document.dns.as_ref().expect("DNS policy");
    let mut datasets = BTreeSet::new();
    let mut providers = BTreeSet::new();
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
            DnsMatcher::Geosite(codes) => datasets.extend(codes.into_iter().map(Dataset::GeoSite)),
            DnsMatcher::Providers(names) => providers.extend(names),
            DnsMatcher::Domain(_) => {}
        }
    }
    if let Some(filter) = &dns.fallback_filter {
        for code in &filter.geosite {
            datasets.insert(Dataset::GeoSite(validate_geosite(code)?));
        }
        if let Some(code) = &filter.geoip_code {
            datasets.insert(Dataset::GeoIp(validate_geoip_code(code)?));
        }
    }
    Ok((providers, datasets))
}

/// The downloadable datasets a validated profile's DNS policy references.
pub(crate) fn dns_datasets(document: &ProfileDocument) -> Result<BTreeSet<Dataset>, ConfigError> {
    Ok(dns_dataset_names(document)?.1)
}

pub(super) fn dataset_rule_sets(
    document: &ProfileDocument,
    download_outbound: &str,
) -> Result<Vec<Value>, ConfigError> {
    let (providers, datasets) = dns_dataset_names(document)?;
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
    // GeoSite datasets keep their sorted order and the fallback GeoIP comes
    // last, as before the datasets were shared with routing.
    let (geoip, geosite): (Vec<_>, Vec<_>) = datasets
        .into_iter()
        .partition(|dataset| matches!(dataset, Dataset::GeoIp(_)));
    resources.extend(
        geosite
            .iter()
            .chain(&geoip)
            .map(|dataset| dataset.resource(download_outbound)),
    );
    Ok(resources)
}
