//! Validated profile routing policy and its sing-box projection.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ConfigError;
use crate::profile::{ProfileDocument, ProfileOutbound};

const MAX_RULES: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    IpCidr,
    SourceIpCidr,
    Port,
    SourcePort,
    Network,
    ProcessName,
    ProcessPath,
    GeoIp,
    RuleSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileRule {
    #[serde(rename = "type")]
    pub(crate) kind: RuleKind,
    pub(crate) value: String,
    pub(crate) outbound: String,
    #[serde(default)]
    pub(crate) no_resolve: bool,
}

fn invalid(path: impl Into<String>, reason: &str) -> ConfigError {
    ConfigError::UnsupportedPolicyShape {
        path: path.into(),
        reason: reason.to_owned(),
    }
}

impl ProfileDocument {
    pub(crate) fn validate_routing(&self, tags: &BTreeSet<&str>) -> Result<(), ConfigError> {
        let by_tag: BTreeMap<_, _> = self
            .outbounds
            .iter()
            .map(|outbound| (outbound.tag(), outbound))
            .collect();
        if let Some(providers) = &self.providers {
            providers.validate(self, tags)?;
        }
        for (source, target) in &self.detours {
            if !by_tag
                .get(source.as_str())
                .is_some_and(|outbound| outbound.is_remote())
                || !by_tag.get(target.as_str()).is_some_and(|outbound| {
                    outbound.is_remote() || outbound.group_members().is_some()
                })
            {
                return Err(invalid(
                    "$.detours",
                    "a detour must connect a declared remote outbound to a remote outbound or group",
                ));
            }
        }
        let mut completed = BTreeMap::new();
        for outbound in &self.outbounds {
            if let Some(outbounds) = outbound.group_members()
                && outbounds
                    .iter()
                    .any(|member| !tags.contains(member.as_str()))
            {
                return Err(invalid(
                    "$.outbounds",
                    "group member must name a declared outbound",
                ));
            }
            self.validate_group_path(
                outbound.tag(),
                &by_tag,
                &mut BTreeSet::new(),
                &mut completed,
            )?;
        }
        if let Some(route) = &self.route {
            if route.rules.len() > MAX_RULES {
                return Err(invalid("$.route.rules", "routing rule count exceeds 8192"));
            }
            let mut expanded = 0usize;
            for (index, rule) in route.rules.iter().enumerate() {
                rule.validate(&format!("$.route.rules[{index}]"), tags)?;
                expanded += if rule.kind == RuleKind::RuleSet {
                    self.providers
                        .as_ref()
                        .and_then(|catalog| {
                            catalog
                                .rules
                                .iter()
                                .find(|provider| provider.name == rule.value)
                        })
                        .ok_or_else(|| {
                            invalid("$.route.rules", "rule references an undeclared provider")
                        })?
                        .rules
                        .len()
                } else {
                    1
                };
                if expanded > MAX_RULES {
                    return Err(invalid(
                        "$.route.rules",
                        "expanded provider routing rule count exceeds 8192",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_group_path<'a>(
        &'a self,
        tag: &'a str,
        by_tag: &BTreeMap<&'a str, &'a ProfileOutbound>,
        visiting: &mut BTreeSet<&'a str>,
        completed: &mut BTreeMap<&'a str, usize>,
    ) -> Result<usize, ConfigError> {
        if let Some(depth) = completed.get(tag) {
            return Ok(*depth);
        }
        if visiting.len() >= 32 {
            return Err(invalid(
                "$.outbounds",
                "outbound dependency depth exceeds 32",
            ));
        }
        if !visiting.insert(tag) {
            return Err(invalid("$.outbounds", "group references form a cycle"));
        }
        let mut depth = 1;
        if let Some(outbounds) = by_tag
            .get(tag)
            .and_then(|outbound| outbound.group_members())
        {
            for member in outbounds {
                depth =
                    depth.max(1 + self.validate_group_path(member, by_tag, visiting, completed)?);
            }
        }
        if let Some(detour) = self.detours.get(tag) {
            depth = depth.max(1 + self.validate_group_path(detour, by_tag, visiting, completed)?);
        }
        if depth > 32 {
            return Err(invalid(
                "$.outbounds",
                "outbound dependency depth exceeds 32",
            ));
        }
        visiting.remove(tag);
        completed.insert(tag, depth);
        Ok(depth)
    }

    pub(crate) fn selected_route_is_remote(&self) -> bool {
        self.route_is_remote(
            self.effective_final_outbound_tag(),
            &mut std::collections::BTreeMap::new(),
        )
    }

    fn route_is_remote<'a>(
        &'a self,
        tag: &'a str,
        completed: &mut std::collections::BTreeMap<&'a str, bool>,
    ) -> bool {
        if let Some(result) = completed.get(tag) {
            return *result;
        }
        // The validated group graph is acyclic. Memoization bounds shared subgroups.
        let result = match self.outbounds.iter().find(|outbound| outbound.tag() == tag) {
            Some(ProfileOutbound::Selector {
                outbounds, default, ..
            }) => self.route_is_remote(default.as_deref().unwrap_or(&outbounds[0]), completed),
            Some(
                ProfileOutbound::UrlTest { outbounds, .. }
                | ProfileOutbound::Fallback { outbounds, .. }
                | ProfileOutbound::LoadBalance { outbounds, .. },
            ) => outbounds
                .iter()
                .all(|member| self.route_is_remote(member, completed)),
            Some(outbound) => outbound.is_remote(),
            None => unreachable!("validated route target must exist"),
        };
        completed.insert(tag, result);
        result
    }

    pub(crate) fn project_rules(&self, download_outbound: &str) -> (Vec<Value>, Vec<Value>) {
        let mut rules = Vec::new();
        let mut countries = BTreeSet::new();
        if let Some(route) = &self.route {
            for source_rule in &route.rules {
                let expanded;
                let inputs = if source_rule.kind == RuleKind::RuleSet {
                    let provider = self
                        .providers
                        .as_ref()
                        .and_then(|catalog| {
                            catalog
                                .rules
                                .iter()
                                .find(|provider| provider.name == source_rule.value)
                        })
                        .expect("validated rule provider");
                    expanded = provider
                        .rules
                        .iter()
                        .map(|condition| ProfileRule {
                            kind: condition.kind,
                            value: condition.value.clone(),
                            outbound: source_rule.outbound.clone(),
                            no_resolve: source_rule.no_resolve
                                && matches!(condition.kind, RuleKind::IpCidr | RuleKind::GeoIp),
                        })
                        .collect::<Vec<_>>();
                    expanded.as_slice()
                } else {
                    std::slice::from_ref(source_rule)
                };
                for rule in inputs {
                    if !rule.no_resolve
                        && matches!(
                            rule.kind,
                            RuleKind::IpCidr | RuleKind::GeoIp | RuleKind::RuleSet
                        )
                    {
                        rules.push(json!({"action": "resolve"}));
                    }
                    if rule.kind == RuleKind::GeoIp && rule.value != "LAN" {
                        countries.insert(rule.value.to_ascii_lowercase());
                    }
                    rules.push(rule.project());
                }
            }
        }
        let rule_sets = countries.into_iter().map(|country| json!({
            "type": "remote",
            "tag": format!("cfw-geoip-{country}"),
            "format": "binary",
            "url": format!("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{country}.srs"),
            "download_detour": download_outbound,
            "update_interval": "1d",
        })).collect();
        (rules, rule_sets)
    }
}

impl ProfileRule {
    pub(crate) fn validate(&self, path: &str, tags: &BTreeSet<&str>) -> Result<(), ConfigError> {
        if !tags.contains(self.outbound.as_str()) {
            return Err(invalid(path, "rule target must name a declared outbound"));
        }
        if self.value.is_empty()
            || self.value.len() > 2_048
            || self.value.trim() != self.value
            || self.value.chars().any(char::is_control)
        {
            return Err(invalid(
                path,
                "rule value is empty, oversized or contains control characters",
            ));
        }
        if self.no_resolve
            && !matches!(
                self.kind,
                RuleKind::IpCidr | RuleKind::GeoIp | RuleKind::RuleSet
            )
        {
            return Err(invalid(
                path,
                "no_resolve is only valid for destination IP rules",
            ));
        }
        let valid = match self.kind {
            RuleKind::IpCidr | RuleKind::SourceIpCidr => {
                self.value.split_once('/').is_some_and(|(address, prefix)| {
                    match (address.parse::<IpAddr>(), prefix.parse::<u8>()) {
                        (Ok(address), Ok(prefix)) => {
                            prefix <= if address.is_ipv4() { 32 } else { 128 }
                        }
                        _ => false,
                    }
                })
            }
            RuleKind::Port | RuleKind::SourcePort => {
                self.value.parse::<u16>().is_ok_and(|port| port > 0)
            }
            RuleKind::Network => matches!(self.value.as_str(), "tcp" | "udp"),
            RuleKind::GeoIp => {
                self.value == "LAN"
                    || (self.value.len() == 2 && self.value.bytes().all(|b| b.is_ascii_uppercase()))
            }
            RuleKind::Domain | RuleKind::DomainSuffix | RuleKind::DomainKeyword => {
                !self.value.chars().any(char::is_whitespace)
            }
            RuleKind::ProcessName => !self.value.contains('/'),
            RuleKind::ProcessPath => self.value.starts_with('/'),
            RuleKind::DomainRegex => regex::RegexBuilder::new(&self.value)
                .size_limit(2 * 1024 * 1024)
                .nest_limit(32)
                .build()
                .is_ok(),
            RuleKind::RuleSet => true,
        };
        if !valid {
            return Err(invalid(path, "rule value does not match its declared type"));
        }
        Ok(())
    }

    pub(crate) fn project(&self) -> Value {
        let key = match self.kind {
            RuleKind::Domain => "domain",
            RuleKind::DomainSuffix => "domain_suffix",
            RuleKind::DomainKeyword => "domain_keyword",
            RuleKind::DomainRegex => "domain_regex",
            RuleKind::IpCidr => "ip_cidr",
            RuleKind::SourceIpCidr => "source_ip_cidr",
            RuleKind::Port => "port",
            RuleKind::SourcePort => "source_port",
            RuleKind::Network => "network",
            RuleKind::ProcessName => "process_name",
            RuleKind::ProcessPath => "process_path",
            RuleKind::GeoIp if self.value == "LAN" => "ip_is_private",
            RuleKind::GeoIp | RuleKind::RuleSet => "rule_set",
        };
        let value = match self.kind {
            RuleKind::GeoIp if self.value == "LAN" => Value::Bool(true),
            RuleKind::GeoIp => json!(format!("cfw-geoip-{}", self.value.to_ascii_lowercase())),
            RuleKind::Port | RuleKind::SourcePort => {
                json!(self.value.parse::<u16>().expect("validated rule port"))
            }
            _ => json!(self.value),
        };
        json!({key: value, "action": "route", "outbound": self.outbound})
    }
}
