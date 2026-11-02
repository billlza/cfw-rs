use cfw_singbox_config::{
    MAX_PROVIDERS, ProviderCatalog, ProviderRuleBehavior, ProviderRuleFormat, ProxyProvider,
    RuleProvider, UtlsFingerprint,
};
use std::collections::BTreeMap;

use super::{
    OutboundCollector, ProxyFields, YamlScalar, YamlValue, convert_proxy, load_single_document,
};
use crate::subscription_import::MAX_SUBSCRIPTION_DOCUMENT_BYTES;

mod declaration;
mod payload;

use declaration::{filter, format, health, provider_mapping, source};
use payload::{decode_payload, import_proxy_payload, import_rule_payload};
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

/// Imports materialized providers. Proxy providers keep the document's
/// `global_fingerprint` so that refreshing their members applies it again.
pub(super) fn import_providers(
    root: &mut ProxyFields,
    collector: &mut OutboundCollector,
    names: &mut BTreeMap<String, String>,
    global_fingerprint: Option<UtlsFingerprint>,
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
            let members = import_proxy_payload(
                &name,
                payload,
                &filter,
                global_fingerprint,
                collector,
                names,
            )?;
            catalog.proxies.push(ProxyProvider {
                name,
                source,
                members,
                filter,
                health_check,
                default_utls_fingerprint: global_fingerprint,
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
                    provider.default_utls_fingerprint,
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
