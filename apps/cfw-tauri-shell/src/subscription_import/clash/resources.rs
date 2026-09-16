use cfw_singbox_config::{
    MAX_PROVIDER_RULES, MAX_PROVIDERS, ProviderCatalog, ProviderFilter, ProviderHealthCheck,
    ProviderMember, ProviderRule, ProviderRuleBehavior, ProviderRuleFormat, ProviderSource,
    ProxyProvider, RuleKind, RuleProvider,
};
use std::collections::BTreeMap;

use super::{
    OutboundCollector, ProxyFields, YamlScalar, YamlValue, convert_proxy, load_single_document,
};
use crate::subscription_import::MAX_SUBSCRIPTION_DOCUMENT_BYTES;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProviderKind {
    Proxy,
    Rule,
}

#[derive(Clone)]
pub(crate) struct ProviderRequest {
    pub kind: ProviderKind,
    pub name: String,
    pub url: String,
    pub maximum_bytes: usize,
    pub format: ProviderRuleFormat,
}

impl std::fmt::Debug for ProviderRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderRequest")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

fn provider_mapping(value: YamlValue, context: String) -> Result<ProxyFields, String> {
    let YamlValue::Mapping(mapping) = value else {
        return Err(format!("{context} must be a mapping"));
    };
    Ok(ProxyFields::new(mapping, context))
}

fn source(fields: &mut ProxyFields) -> Result<(ProviderSource, usize), String> {
    let kind = fields.require_string("type")?;
    let url = fields.take_string("url")?;
    let interval = fields
        .take_string("interval")?
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| "provider interval must be an integer")?;
    let maximum = fields
        .take_string("size-limit")?
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| "provider size-limit must be an integer")?
        .filter(|value| *value > 0)
        .unwrap_or(MAX_SUBSCRIPTION_DOCUMENT_BYTES)
        .min(MAX_SUBSCRIPTION_DOCUMENT_BYTES);
    // The application owns its cache location; a subscription cannot choose a
    // filesystem write target. The cache hint does not change routing content.
    fields.take_string("path")?;
    if fields
        .take_string("proxy")?
        .is_some_and(|proxy| proxy != "DIRECT")
    {
        return Err(
            "provider download via a named proxy requires the profile resource transport".into(),
        );
    }
    let source = match (kind.as_str(), url) {
        ("http", Some(url)) => {
            let url = reqwest::Url::parse(&url).map_err(|_| "provider URL is invalid")?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(
                    "provider downloads require HTTPS without userinfo or a fragment".into(),
                );
            }
            let interval_seconds = interval.unwrap_or(3600);
            if !(60..=604800).contains(&interval_seconds) {
                return Err("provider interval must be 60..=604800 seconds".into());
            }
            ProviderSource {
                url: Some(url.to_string()),
                interval_seconds,
            }
        }
        ("inline", None) if interval.is_none_or(|value| value == 0) => ProviderSource {
            url: None,
            interval_seconds: 0,
        },
        _ => {
            return Err(
                "provider requires type http with a URL, or type inline with a payload".into(),
            );
        }
    };
    Ok((source, maximum))
}

fn filter(fields: &mut ProxyFields) -> Result<ProviderFilter, String> {
    let filter = ProviderFilter {
        include: fields.take_string("filter")?,
        exclude: fields.take_string("exclude-filter")?,
    };
    filter.accepts("").map_err(|error| error.to_string())?;
    Ok(filter)
}

fn health(fields: &mut ProxyFields) -> Result<Option<ProviderHealthCheck>, String> {
    let Some(value) = fields.take("health-check") else {
        return Ok(None);
    };
    let mut fields = provider_mapping(value, "provider health-check".into())?;
    let enabled = fields.take_bool("enable")?.unwrap_or(false);
    let url = fields.take_string("url")?;
    let interval = fields
        .take_string("interval")?
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| "health interval must be an integer")?
        .unwrap_or(300);
    let lazy = fields.take_bool("lazy")?.unwrap_or(true);
    let timeout_ms = fields
        .take_string("timeout")?
        .map(|value| value.parse::<u16>())
        .transpose()
        .map_err(|_| "health timeout must be an integer")?
        .unwrap_or(5000);
    let expected_status = fields.take_string("expected-status")?;
    fields.reject_leftovers()?;
    if !enabled {
        return Ok(None);
    }
    Ok(Some(ProviderHealthCheck {
        url: url.ok_or("enabled provider health check requires a URL")?,
        interval_seconds: interval,
        lazy,
        timeout_ms,
        expected_status,
    }))
}

fn format(fields: &mut ProxyFields) -> Result<ProviderRuleFormat, String> {
    match fields.take_string("format")?.as_deref().unwrap_or("yaml") {
        "yaml" => Ok(ProviderRuleFormat::Yaml),
        "text" => Ok(ProviderRuleFormat::Text),
        _ => Err("rule provider format must be yaml or text".into()),
    }
}

pub(crate) fn requests(body: &str) -> Result<Vec<ProviderRequest>, String> {
    if !super::super::looks_like_clash_yaml(body) && !body.trim_start().starts_with('{') {
        return Ok(Vec::new());
    }
    let YamlValue::Mapping(root) = load_single_document(body)? else {
        return Ok(Vec::new());
    };
    let mut requests = Vec::new();
    let mut count = 0usize;
    for (key, kind) in [
        ("proxy-providers", ProviderKind::Proxy),
        ("rule-providers", ProviderKind::Rule),
    ] {
        let Some(value) = root.get(key) else { continue };
        let YamlValue::Mapping(providers) = value else {
            return Err(format!("{key} must be a mapping"));
        };
        for (name, value) in providers.clone().into_entries() {
            count += 1;
            if count > MAX_PROVIDERS {
                return Err("provider count exceeds 32".into());
            }
            let mut fields = provider_mapping(value, format!("{key} entry"))?;
            let (source, maximum_bytes) = source(&mut fields)?;
            let format = if kind == ProviderKind::Rule {
                format(&mut fields)?
            } else {
                ProviderRuleFormat::Yaml
            };
            if let Some(url) = source.url {
                requests.push(ProviderRequest {
                    kind,
                    name,
                    url,
                    maximum_bytes,
                    format,
                });
            }
        }
    }
    Ok(requests)
}

pub(crate) fn materialize(
    body: &str,
    resources: &[(ProviderRequest, String)],
) -> Result<String, String> {
    if resources.is_empty() {
        return Ok(body.into());
    }
    let mut root = load_single_document(body)?;
    let YamlValue::Mapping(mapping) = &mut root else {
        return Err("provider root must be a mapping".into());
    };
    for (request, body) in resources {
        let payload = decode_payload(request.kind, request.format, body)?;
        let key = if request.kind == ProviderKind::Proxy {
            "proxy-providers"
        } else {
            "rule-providers"
        };
        let Some(YamlValue::Mapping(providers)) = mapping.get_mut(key) else {
            return Err("provider collection changed while downloading".into());
        };
        let Some(YamlValue::Mapping(provider)) = providers.get_mut(&request.name) else {
            return Err("provider changed while downloading".into());
        };
        provider.set("payload", payload);
    }
    root.render_document()
}

fn decode_payload(
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

pub(super) fn import_providers(
    root: &mut ProxyFields,
    collector: &mut OutboundCollector,
    names: &mut BTreeMap<String, String>,
) -> Result<ProviderCatalog, String> {
    let mut catalog = ProviderCatalog::default();
    if let Some(value) = root.take("proxy-providers") {
        let YamlValue::Mapping(providers) = value else {
            return Err("proxy-providers must be a mapping".into());
        };
        for (name, value) in providers.into_entries() {
            let mut fields = provider_mapping(value, "proxy provider".into())?;
            let (source, _) = source(&mut fields)?;
            let filter = filter(&mut fields)?;
            let health_check = health(&mut fields)?;
            let payload = fields
                .take("payload")
                .ok_or("provider payload has not been downloaded")?;
            fields.reject_leftovers()?;
            let members = import_proxy_payload(&name, payload, &filter, collector, names)?;
            catalog.proxies.push(ProxyProvider {
                name,
                source,
                members,
                filter,
                health_check,
            });
        }
    }
    if let Some(value) = root.take("rule-providers") {
        let YamlValue::Mapping(providers) = value else {
            return Err("rule-providers must be a mapping".into());
        };
        for (name, value) in providers.into_entries() {
            let mut fields = provider_mapping(value, "rule provider".into())?;
            let (source, _) = source(&mut fields)?;
            let format = format(&mut fields)?;
            let behavior = match fields.require_string("behavior")?.as_str() {
                "domain" => ProviderRuleBehavior::Domain,
                "ipcidr" => ProviderRuleBehavior::IpCidr,
                "classical" => ProviderRuleBehavior::Classical,
                _ => {
                    return Err("rule provider behavior must be domain, ipcidr or classical".into());
                }
            };
            let payload = fields
                .take("payload")
                .ok_or("rule payload has not been downloaded")?;
            fields.reject_leftovers()?;
            let rules = import_rule_payload(payload, behavior)?;
            catalog.rules.push(RuleProvider {
                name,
                source,
                format,
                behavior,
                rules,
            });
        }
    }
    Ok(catalog)
}

fn provider_tag(provider: &str, name: &str) -> String {
    format!(
        "provider-{}",
        cfw_singbox_config::sha256_hex(format!("cfm-provider\0{provider}\0{name}").as_bytes())
    )
}

fn import_proxy_payload(
    provider: &str,
    payload: YamlValue,
    filter: &ProviderFilter,
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
        let (_, outbound) = convert_proxy(collector, fields)?;
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

fn import_rule_payload(
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
                        _ => return Err("unsupported classical provider rule".into()),
                    };
                    (kind, value.trim().into())
                }
            };
            Ok(ProviderRule { kind, value })
        })
        .collect()
}

pub(crate) fn replacement(
    previous: &cfw_singbox_config::ValidatedSingBoxProfile,
    resources: &[(ProviderRequest, String)],
    rotate_credentials: bool,
) -> Result<crate::subscription_import::ImportedSubscription, String> {
    use std::collections::BTreeSet;
    let mut catalog = previous
        .providers()
        .cloned()
        .ok_or("profile has no provider catalog")?;
    let mut root: serde_json::Value = serde_json::from_str(previous.as_json())
        .map_err(|_| "stored provider profile is invalid")?;
    let mut credentials = Vec::new();
    for (request, body) in resources {
        let payload = decode_payload(request.kind, request.format, body)?;
        match request.kind {
            ProviderKind::Proxy => {
                let provider = catalog
                    .proxies
                    .iter_mut()
                    .find(|provider| provider.name == request.name)
                    .ok_or("proxy provider disappeared")?;
                if provider.source.url.as_deref() != Some(request.url.as_str()) {
                    return Err("proxy provider URL changed while downloading".into());
                }
                let owned = provider
                    .members
                    .iter()
                    .map(|member| member.tag.clone())
                    .collect::<BTreeSet<_>>();
                let nodes = root["outbounds"]
                    .as_array_mut()
                    .ok_or("stored outbounds are invalid")?;
                let position = nodes
                    .iter()
                    .position(|node| node["tag"].as_str().is_some_and(|tag| owned.contains(tag)))
                    .ok_or("provider members disappeared")?;
                nodes.retain(|node| !node["tag"].as_str().is_some_and(|tag| owned.contains(tag)));
                let mut collector = if rotate_credentials {
                    OutboundCollector::default()
                } else {
                    OutboundCollector::with_reusable_references(
                        previous.credential_references_for_outbounds(&owned),
                    )
                };
                collector.used_tags = nodes
                    .iter()
                    .filter_map(|node| node["tag"].as_str().map(str::to_owned))
                    .collect();
                let mut names = collector
                    .used_tags
                    .iter()
                    .map(|tag| (tag.clone(), tag.clone()))
                    .collect();
                provider.members = import_proxy_payload(
                    &provider.name,
                    payload,
                    &provider.filter,
                    &mut collector,
                    &mut names,
                )?;
                nodes.splice(position..position, collector.outbounds);
                if let Some(detours) = root
                    .get_mut("detours")
                    .and_then(serde_json::Value::as_object_mut)
                {
                    detours.retain(|tag, _| !owned.contains(tag));
                }
                if !collector.detours.is_empty() {
                    if root.get("detours").is_none() {
                        root["detours"] = serde_json::json!({});
                    }
                    let detours = root["detours"]
                        .as_object_mut()
                        .ok_or("stored detours are invalid")?;
                    for (source, target) in collector.detours {
                        detours.insert(source, serde_json::json!(target));
                    }
                }
                credentials.extend(collector.credentials);
            }
            ProviderKind::Rule => {
                let provider = catalog
                    .rules
                    .iter_mut()
                    .find(|provider| provider.name == request.name)
                    .ok_or("rule provider disappeared")?;
                if provider.source.url.as_deref() != Some(request.url.as_str())
                    || provider.format != request.format
                {
                    return Err("rule provider source changed while downloading".into());
                }
                provider.rules = import_rule_payload(payload, provider.behavior)?;
            }
        }
    }
    for group in &catalog.groups {
        let members = catalog
            .group_members(group)
            .map_err(|error| error.to_string())?;
        let node = root["outbounds"]
            .as_array_mut()
            .ok_or("stored outbounds are invalid")?
            .iter_mut()
            .find(|node| node["tag"].as_str() == Some(group.group.as_str()))
            .ok_or("provider group disappeared")?;
        if node
            .get("default")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|selected| !members.iter().any(|member| member == selected))
        {
            node.as_object_mut()
                .ok_or("provider group is not an object")?
                .remove("default");
        }
        node["outbounds"] = serde_json::json!(members);
    }
    let sources = catalog.sources();
    root["providers"] = serde_json::json!(catalog);
    let profile = cfw_singbox_config::ValidatedSingBoxProfile::parse(&root.to_string())
        .and_then(|profile| profile.with_provider_sources(sources))
        .map_err(|error| error.to_string())?;
    Ok(crate::subscription_import::ImportedSubscription {
        profile,
        credentials,
    })
}

pub(crate) fn stored_requests(
    profile: &cfw_singbox_config::ValidatedSingBoxProfile,
    kind: ProviderKind,
    name: Option<&str>,
) -> Result<Vec<ProviderRequest>, String> {
    let catalog = profile
        .providers()
        .ok_or("selected profile has no providers")?;
    let requests = match kind {
        ProviderKind::Proxy => catalog
            .proxies
            .iter()
            .filter(|provider| name.is_none_or(|name| name == provider.name))
            .map(|provider| (&provider.name, &provider.source, ProviderRuleFormat::Yaml))
            .collect::<Vec<_>>(),
        ProviderKind::Rule => catalog
            .rules
            .iter()
            .filter(|provider| name.is_none_or(|name| name == provider.name))
            .map(|provider| (&provider.name, &provider.source, provider.format))
            .collect(),
    };
    if name.is_some() && requests.is_empty() {
        return Err("provider is not in the selected profile".into());
    }
    let mut result = Vec::new();
    let single = name.is_some();
    for (name, source, format) in requests {
        if let Some(url) = &source.url {
            result.push(ProviderRequest {
                kind,
                name: name.clone(),
                url: url.clone(),
                maximum_bytes: MAX_SUBSCRIPTION_DOCUMENT_BYTES,
                format,
            });
        } else if single {
            return Err(
                "provider has no remote source URL; edit its materialized content in Profiles"
                    .into(),
            );
        }
    }
    Ok(result)
}
