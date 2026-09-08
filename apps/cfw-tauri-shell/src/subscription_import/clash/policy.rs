//! Clash group and rule conversion; the profile crate owns graph validation.

use std::collections::BTreeMap;

use serde_json::json;

use super::{MAX_OUTBOUNDS, OutboundCollector, ProxyFields, YamlValue};

struct Group {
    tag: String,
    members: Vec<String>,
    algorithm: GroupAlgorithm,
}

enum GroupAlgorithm {
    Select,
    UrlTest {
        url: String,
        interval_seconds: u32,
        tolerance_ms: u16,
    },
}

pub(super) fn import_policy(
    root: &mut ProxyFields,
    collector: &mut OutboundCollector,
    mut names: BTreeMap<String, String>,
) -> Result<(), String> {
    for key in ["proxy-providers", "rule-providers"] {
        if let Some(value) = root.take(key) {
            let empty = match value {
                YamlValue::Mapping(mapping) => mapping.into_entries().is_empty(),
                _ => false,
            };
            if !empty {
                return Err(format!(
                    "Clash {key} requires provider import support; no partial profile was saved"
                ));
            }
        }
    }
    let mut groups = Vec::new();
    if let Some(value) = root.take("proxy-groups") {
        let YamlValue::Sequence(entries) = value else {
            return Err("Clash proxy-groups must be a sequence".into());
        };
        if entries.len() + collector.outbounds.len() > MAX_OUTBOUNDS {
            return Err("Clash nodes and groups exceed the supported outbound count".into());
        }
        for (index, value) in entries.into_iter().enumerate() {
            let YamlValue::Mapping(mapping) = value else {
                return Err(format!("proxy-groups[{index}] must be a mapping"));
            };
            let mut fields = ProxyFields::new(mapping, format!("proxy-groups[{index}]"));
            let name = fields.require_string("name")?;
            if names.contains_key(&name) || matches!(name.as_str(), "DIRECT" | "REJECT") {
                return Err(format!(
                    "proxy-groups[{index}] has a duplicate or reserved name"
                ));
            }
            let algorithm = match fields.require_string("type")?.as_str() {
                "select" => GroupAlgorithm::Select,
                "url-test" => {
                    let url = fields.require_string("url")?;
                    let interval_seconds = fields
                        .require_string("interval")?
                        .parse::<u32>()
                        .map_err(|_| {
                            format!("proxy-groups[{index}] interval must be an integer")
                        })?;
                    let tolerance_ms = fields
                        .take_string("tolerance")?
                        .map(|value| value.parse::<u16>())
                        .transpose()
                        .map_err(|_| format!("proxy-groups[{index}] tolerance must be an integer"))?
                        .unwrap_or(0);
                    if fields.take_bool("lazy")? == Some(false) {
                        return Err(format!(
                            "proxy-groups[{index}] requires continuous idle probing, which the runtime does not support"
                        ));
                    }
                    GroupAlgorithm::UrlTest {
                        url,
                        interval_seconds,
                        tolerance_ms,
                    }
                }
                _ => {
                    return Err(format!(
                        "proxy-groups[{index}] uses an unsupported group algorithm; no partial profile was saved"
                    ));
                }
            };
            let members = fields
                .take_string_list("proxies")?
                .ok_or_else(|| format!("proxy-groups[{index}] has no proxies list"))?;
            if fields.take_bool("disable-udp")? == Some(true) {
                return Err(format!(
                    "proxy-groups[{index}] requires unsupported group UDP filtering"
                ));
            }
            // Cosmetic Clash dashboard metadata does not affect routing.
            fields.take_string("icon")?;
            fields.take_bool("hidden")?;
            fields.reject_leftovers()?;
            let tag = collector.unique_tag(name.clone())?;
            names.insert(name, tag.clone());
            groups.push(Group {
                tag,
                members,
                algorithm,
            });
        }
    }
    for group in groups {
        let members = group
            .members
            .iter()
            .map(|name| resolve_target(name, collector, &mut names))
            .collect::<Result<Vec<_>, _>>()?;
        let outbound = match group.algorithm {
            GroupAlgorithm::Select => {
                json!({"type": "selector", "tag": group.tag, "outbounds": members})
            }
            GroupAlgorithm::UrlTest {
                url,
                interval_seconds,
                tolerance_ms,
            } => json!({
                "type": "urltest", "tag": group.tag, "outbounds": members,
                "url": url, "interval_seconds": interval_seconds, "tolerance_ms": tolerance_ms,
                "idle_timeout_seconds": interval_seconds.max(1800),
            }),
        };
        collector.outbounds.push(outbound);
    }
    collector.detours = collector
        .detours
        .iter()
        .map(|(source, target)| {
            let source = names
                .get(source)
                .ok_or("Clash detour source is undeclared")?;
            let target = names
                .get(target)
                .ok_or("Clash dialer-proxy target is undeclared")?;
            Ok((source.clone(), target.clone()))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    if let Some(value) = root.take("rules") {
        let YamlValue::Sequence(entries) = value else {
            return Err("Clash rules must be a sequence".into());
        };
        if entries.len() > 8_192 {
            return Err("Clash routing rule count exceeds 8192".into());
        }
        let count = entries.len();
        let mut rules = Vec::new();
        let mut final_tag = None;
        for (index, entry) in entries.into_iter().enumerate() {
            let YamlValue::Scalar(scalar) = entry else {
                return Err(format!("rules[{index}] must be a string"));
            };
            let parts = scalar.text().split(',').map(str::trim).collect::<Vec<_>>();
            if parts.first() == Some(&"MATCH") {
                if parts.len() != 2 || index + 1 != count {
                    return Err(format!(
                        "rules[{index}] MATCH must be the final rule with one target"
                    ));
                }
                final_tag = Some(resolve_target(parts[1], collector, &mut names)?);
                continue;
            }
            if !(3..=4).contains(&parts.len()) || (parts.len() == 4 && parts[3] != "no-resolve") {
                return Err(format!("rules[{index}] has an unsupported rule shape"));
            }
            let kind = match parts[0] {
                "DOMAIN" => "domain",
                "DOMAIN-SUFFIX" => "domain_suffix",
                "DOMAIN-KEYWORD" => "domain_keyword",
                "DOMAIN-REGEX" => "domain_regex",
                "IP-CIDR" | "IP-CIDR6" => "ip_cidr",
                "SRC-IP-CIDR" => "source_ip_cidr",
                "DST-PORT" => "port",
                "SRC-PORT" => "source_port",
                "NETWORK" => "network",
                "PROCESS-NAME" => "process_name",
                "PROCESS-PATH" => "process_path",
                "GEOIP" => "geo_ip",
                _ => {
                    return Err(format!(
                        "rules[{index}] uses an unsupported rule type; no partial profile was saved"
                    ));
                }
            };
            rules.push(json!({
                "type": kind,
                "value": if parts[0] == "NETWORK" { parts[1].to_ascii_lowercase() } else { parts[1].to_owned() },
                "outbound": resolve_target(parts[2], collector, &mut names)?,
                "no_resolve": parts.len() == 4,
            }));
        }
        let mut route = json!({"rules": rules});
        if let Some(final_tag) = final_tag {
            route["final"] = json!(final_tag);
        }
        collector.route = Some(route);
    }
    Ok(())
}

fn resolve_target(
    name: &str,
    collector: &mut OutboundCollector,
    names: &mut BTreeMap<String, String>,
) -> Result<String, String> {
    if let Some(tag) = names.get(name) {
        return Ok(tag.clone());
    }
    let kind = match name {
        "DIRECT" => "direct",
        "REJECT" => "block",
        _ => return Err("Clash rule or group references an undeclared target".into()),
    };
    let tag = collector.unique_tag(name.to_owned())?;
    collector.outbounds.push(json!({"type": kind, "tag": tag}));
    names.insert(name.to_owned(), tag.clone());
    Ok(tag)
}
