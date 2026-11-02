//! Fetched provider payloads, imported as outbounds and rules.

use std::collections::BTreeMap;

use cfw_singbox_config::{
    MAX_PROVIDER_RULES, ProviderFilter, ProviderMember, ProviderRule, ProviderRuleBehavior,
    ProviderRuleFormat, RuleKind, UtlsFingerprint,
};

use super::declaration::provider_mapping;
use super::{
    OutboundCollector, ProviderKind, YamlScalar, YamlValue, convert_proxy, load_single_document,
};

pub(super) fn decode_payload(
    kind: ProviderKind,
    format: ProviderRuleFormat,
    body: &str,
) -> Result<YamlValue, String> {
    if kind == ProviderKind::Rule && format == ProviderRuleFormat::Text {
        return Ok(YamlValue::Sequence(
            body.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(|line| YamlValue::Scalar(YamlScalar::string(line.into())))
                .collect(),
        ));
    }
    let YamlValue::Mapping(root) = load_single_document(body)? else {
        return Err("provider response must be a mapping".into());
    };
    let key = if kind == ProviderKind::Proxy {
        "proxies"
    } else {
        "payload"
    };
    root.get(key)
        .cloned()
        .ok_or_else(|| format!("provider response is missing {key}"))
}

pub(super) fn provider_tag(provider: &str, name: &str) -> String {
    format!(
        "provider-{}",
        cfw_singbox_config::sha256_hex(format!("cfm-provider\0{provider}\0{name}").as_bytes())
    )
}

pub(super) fn import_proxy_payload(
    provider: &str,
    payload: YamlValue,
    filter: &ProviderFilter,
    default_fingerprint: Option<UtlsFingerprint>,
    collector: &mut OutboundCollector,
    names: &mut BTreeMap<String, String>,
) -> Result<Vec<ProviderMember>, String> {
    let YamlValue::Sequence(nodes) = payload else {
        return Err("proxy provider payload must be a sequence".into());
    };
    let filter = filter.compile().map_err(|error| error.to_string())?;
    let mut members = Vec::new();
    let mut local_names = BTreeMap::new();
    for value in nodes {
        let mut fields = provider_mapping(value, "provider node".into())?;
        let name = fields.require_string("name")?;
        if !filter.accepts(&name) {
            continue;
        }
        let tag = provider_tag(provider, &name);
        if local_names.insert(name.clone(), tag.clone()).is_some() {
            return Err("provider node names must be unique".into());
        }
        fields.entries.insert(
            0,
            (
                "name".into(),
                YamlValue::Scalar(YamlScalar::string(tag.clone())),
            ),
        );
        if collector.outbounds.len() >= cfw_singbox_config::MAX_OUTBOUNDS {
            return Err("provider nodes exceed the supported outbound capacity".into());
        }
        let (_, outbound) = convert_proxy(collector, fields, default_fingerprint)?;
        let actual = outbound["tag"]
            .as_str()
            .ok_or("converted provider node has no tag")?
            .to_owned();
        if actual != tag
            && let Some(detour) = collector.detours.remove(&tag)
        {
            collector.detours.insert(actual.clone(), detour);
        }
        local_names.insert(name.clone(), actual.clone());
        names.insert(actual.clone(), actual.clone());
        collector.outbounds.push(outbound);
        members.push(ProviderMember { tag: actual, name });
    }
    // Dialer-proxy references inside a provider retain that provider's scope.
    for member in &members {
        if let Some(target) = collector.detours.get_mut(&member.tag)
            && let Some(resolved) = local_names.get(target)
        {
            *target = resolved.clone();
        }
    }
    Ok(members)
}

pub(super) fn import_rule_payload(
    payload: YamlValue,
    behavior: ProviderRuleBehavior,
) -> Result<Vec<ProviderRule>, String> {
    let YamlValue::Sequence(values) = payload else {
        return Err("rule provider payload must be a sequence".into());
    };
    if values.len() > MAX_PROVIDER_RULES {
        return Err("rule provider is too large".into());
    }
    values
        .into_iter()
        .map(|value| {
            let YamlValue::Scalar(value) = value else {
                return Err("provider rule must be a string".into());
            };
            let text = value.text().trim();
            let (kind, value) = match behavior {
                ProviderRuleBehavior::IpCidr => (RuleKind::IpCidr, text.to_owned()),
                ProviderRuleBehavior::Domain => {
                    match cfw_singbox_config::DomainPattern::parse(text)
                        .map_err(|error| error.to_string())?
                    {
                        cfw_singbox_config::DomainPattern::Exact(value) => {
                            (RuleKind::Domain, value)
                        }
                        cfw_singbox_config::DomainPattern::Suffix(value) => {
                            (RuleKind::DomainSuffix, value)
                        }
                        cfw_singbox_config::DomainPattern::Regex(value) => {
                            (RuleKind::DomainRegex, value)
                        }
                    }
                }
                ProviderRuleBehavior::Classical => {
                    let (kind, value) = text
                        .split_once(',')
                        .ok_or("classical provider rule requires a type and value")?;
                    if value.contains(',') {
                        return Err(
                            "classical provider rules cannot include an outbound target".into()
                        );
                    }
                    let kind = match kind.trim() {
                        "DOMAIN" => RuleKind::Domain,
                        "DOMAIN-SUFFIX" => RuleKind::DomainSuffix,
                        "DOMAIN-KEYWORD" => RuleKind::DomainKeyword,
                        "DOMAIN-REGEX" => RuleKind::DomainRegex,
                        "IP-CIDR" | "IP-CIDR6" => RuleKind::IpCidr,
                        "SRC-IP-CIDR" => RuleKind::SourceIpCidr,
                        "DST-PORT" => RuleKind::Port,
                        "SRC-PORT" => RuleKind::SourcePort,
                        "NETWORK" => RuleKind::Network,
                        "PROCESS-NAME" => RuleKind::ProcessName,
                        "PROCESS-PATH" => RuleKind::ProcessPath,
                        "GEOIP" => RuleKind::GeoIp,
                        "GEOSITE" => RuleKind::GeoSite,
                        _ => return Err("unsupported classical provider rule".into()),
                    };
                    // Mihomo matches GEOSITE codes case-insensitively; the
                    // published dataset names are lowercase.
                    let value = value.trim();
                    let value = if kind == RuleKind::GeoSite {
                        value.to_ascii_lowercase()
                    } else {
                        value.to_owned()
                    };
                    (kind, value)
                }
            };
            Ok(ProviderRule { kind, value })
        })
        .collect()
}
