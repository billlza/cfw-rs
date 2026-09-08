//! Validated profile routing policy and its sing-box projection.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ConfigError;
use crate::profile::{ProfileDocument, ProfileOutbound};

const MAX_RULES: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuleKind {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileRule {
    #[serde(rename = "type")]
    kind: RuleKind,
    value: String,
    outbound: String,
    #[serde(default)]
    no_resolve: bool,
}

fn invalid(path: impl Into<String>, reason: &str) -> ConfigError {
    ConfigError::UnsupportedPolicyShape {
        path: path.into(),
        reason: reason.to_owned(),
    }
}

impl ProfileDocument {
    pub(crate) fn validate_routing(&self, tags: &BTreeSet<&str>) -> Result<(), ConfigError> {
        let mut completed = BTreeSet::new();
        for outbound in &self.outbounds {
            if let ProfileOutbound::Selector { tag, outbounds, .. } = outbound {
                if outbounds
                    .iter()
                    .any(|member| !tags.contains(member.as_str()))
                {
                    return Err(invalid(
                        "$.outbounds",
                        "selector member must name a declared outbound",
                    ));
                }
                self.validate_selector_path(tag, &mut BTreeSet::new(), &mut completed)?;
            }
        }
        if let Some(route) = &self.route {
            if route.rules.len() > MAX_RULES {
                return Err(invalid("$.route.rules", "routing rule count exceeds 8192"));
            }
            for (index, rule) in route.rules.iter().enumerate() {
                rule.validate(&format!("$.route.rules[{index}]"), tags)?;
            }
        }
        Ok(())
    }

    fn validate_selector_path<'a>(
        &'a self,
        tag: &'a str,
        visiting: &mut BTreeSet<&'a str>,
        completed: &mut BTreeSet<&'a str>,
    ) -> Result<(), ConfigError> {
        if completed.contains(tag) {
            return Ok(());
        }
        if !visiting.insert(tag) {
            return Err(invalid("$.outbounds", "selector references form a cycle"));
        }
        if let Some(ProfileOutbound::Selector { outbounds, .. }) =
            self.outbounds.iter().find(|item| item.tag() == tag)
        {
            for member in outbounds {
                self.validate_selector_path(member, visiting, completed)?;
            }
        }
        visiting.remove(tag);
        completed.insert(tag);
        Ok(())
    }

    pub(crate) fn selected_route_is_remote(&self) -> bool {
        let mut tag = self.effective_final_outbound_tag();
        // The validated selector graph is acyclic and bounded by MAX_OUTBOUNDS.
        for _ in 0..self.outbounds.len() {
            match self.outbounds.iter().find(|outbound| outbound.tag() == tag) {
                Some(ProfileOutbound::Selector {
                    outbounds, default, ..
                }) => {
                    tag = default.as_deref().unwrap_or(&outbounds[0]);
                }
                Some(outbound) => return outbound.is_remote(),
                None => unreachable!("validated route target must exist"),
            }
        }
        unreachable!("validated selectors cannot contain a cycle")
    }

    pub(crate) fn project_rules(&self, download_outbound: &str) -> (Vec<Value>, Vec<Value>) {
        let mut rules = Vec::new();
        let mut countries = BTreeSet::new();
        if let Some(route) = &self.route {
            for rule in &route.rules {
                if !rule.no_resolve && matches!(rule.kind, RuleKind::IpCidr | RuleKind::GeoIp) {
                    rules.push(json!({"action": "resolve"}));
                }
                if rule.kind == RuleKind::GeoIp && rule.value != "LAN" {
                    countries.insert(rule.value.to_ascii_lowercase());
                }
                rules.push(rule.project());
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
    fn validate(&self, path: &str, tags: &BTreeSet<&str>) -> Result<(), ConfigError> {
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
        if self.no_resolve && !matches!(self.kind, RuleKind::IpCidr | RuleKind::GeoIp) {
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
            RuleKind::DomainRegex => true,
        };
        if !valid {
            return Err(invalid(path, "rule value does not match its declared type"));
        }
        Ok(())
    }

    fn project(&self) -> Value {
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
            RuleKind::GeoIp => "rule_set",
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
