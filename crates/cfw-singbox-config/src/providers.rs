//! Materialized, application-owned provider resources. The core receives only
//! validated nodes and inline rule sets; remote input is fetched before commit.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::profile::{ProfileDocument, ProfileOutbound};
use crate::routing::{ProfileRule, RuleKind};
use crate::{ConfigError, ValidatedSingBoxProfile};

pub const MAX_PROVIDERS: usize = 32;
pub const MAX_PROVIDER_RULES: usize = 8192;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCatalog {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<ProxyProvider>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RuleProvider>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ProviderGroup>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSource {
    #[serde(default, skip_serializing)]
    pub url: Option<String>,
    pub interval_seconds: u32,
}

impl fmt::Debug for ProviderSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderSource")
            .field("remote", &self.url.is_some())
            .field("interval_seconds", &self.interval_seconds)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
}

impl ProviderFilter {
    pub fn compile(&self) -> Result<CompiledProviderFilter, ConfigError> {
        let compile = |pattern: &str| {
            if pattern.len() > 2048 {
                return Err(invalid("provider filter exceeds 2048 bytes"));
            }
            RegexBuilder::new(pattern)
                .size_limit(2 * 1024 * 1024)
                .nest_limit(32)
                .build()
                .map_err(|_| {
                    invalid("provider filter is not a supported bounded regular expression")
                })
        };
        Ok(CompiledProviderFilter {
            include: self.include.as_deref().map(compile).transpose()?,
            exclude: self.exclude.as_deref().map(compile).transpose()?,
        })
    }
    pub fn accepts(&self, name: &str) -> Result<bool, ConfigError> {
        Ok(self.compile()?.accepts(name))
    }
}

pub struct CompiledProviderFilter {
    include: Option<Regex>,
    exclude: Option<Regex>,
}
impl CompiledProviderFilter {
    pub fn accepts(&self, name: &str) -> bool {
        self.include
            .as_ref()
            .is_none_or(|regex| regex.is_match(name))
            && !self
                .exclude
                .as_ref()
                .is_some_and(|regex| regex.is_match(name))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderHealthCheck {
    pub url: String,
    pub interval_seconds: u32,
    pub lazy: bool,
    #[serde(default = "default_health_timeout")]
    pub timeout_ms: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<String>,
}

fn default_health_timeout() -> u16 {
    5000
}

pub fn validate_expected_status(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > 128 {
        return Err(invalid("expected HTTP status is too long"));
    }
    for item in value.split('/') {
        let parts = item.split('-').collect::<Vec<_>>();
        if parts.is_empty() || parts.len() > 2 {
            return Err(invalid(
                "expected HTTP status must contain codes or ranges separated by /",
            ));
        }
        let mut codes = Vec::new();
        for part in parts {
            if part.len() != 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid("expected HTTP status must use three-digit codes"));
            }
            let code = part
                .parse::<u16>()
                .map_err(|_| invalid("expected HTTP status is invalid"))?;
            if !(100..=599).contains(&code) {
                return Err(invalid("expected HTTP status must be 100..=599"));
            }
            codes.push(code);
        }
        if codes.len() == 2 && codes[0] > codes[1] {
            return Err(invalid("expected HTTP status range is reversed"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMember {
    pub tag: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyProvider {
    pub name: String,
    pub source: ProviderSource,
    pub members: Vec<ProviderMember>,
    #[serde(default)]
    pub filter: ProviderFilter,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<ProviderHealthCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRuleFormat {
    Yaml,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRuleBehavior {
    Domain,
    IpCidr,
    Classical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRule {
    #[serde(rename = "type")]
    pub kind: RuleKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleProvider {
    pub name: String,
    pub source: ProviderSource,
    pub format: ProviderRuleFormat,
    pub behavior: ProviderRuleBehavior,
    pub rules: Vec<ProviderRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderGroup {
    pub group: String,
    pub local_members: Vec<String>,
    pub providers: Vec<String>,
    #[serde(default)]
    pub filter: ProviderFilter,
}

fn invalid(reason: &str) -> ConfigError {
    ConfigError::UnsupportedPolicyShape {
        path: "$.providers".into(),
        reason: reason.into(),
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.trim() == name
        && !name.chars().any(char::is_control)
}

impl ProviderSource {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(url) = &self.url {
            let parsed = url::Url::parse(url).map_err(|_| invalid("provider URL is invalid"))?;
            if url.len() > 8192
                || parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
                || parsed.port() == Some(0)
                || !(60..=604800).contains(&self.interval_seconds)
            {
                return Err(invalid(
                    "remote providers require bounded HTTPS URLs and update intervals of 60..=604800 seconds",
                ));
            }
        } else if self.interval_seconds != 0 && !(60..=604800).contains(&self.interval_seconds) {
            return Err(invalid(
                "materialized providers need either an inline source or a bounded update interval",
            ));
        }
        Ok(())
    }
}

impl ProviderCatalog {
    pub fn sources(&self) -> BTreeMap<String, String> {
        self.proxies
            .iter()
            .filter_map(|provider| {
                provider
                    .source
                    .url
                    .as_ref()
                    .map(|url| (format!("proxy:{}", provider.name), url.clone()))
            })
            .chain(self.rules.iter().filter_map(|provider| {
                provider
                    .source
                    .url
                    .as_ref()
                    .map(|url| (format!("rule:{}", provider.name), url.clone()))
            }))
            .collect()
    }

    pub fn group_members(&self, group: &ProviderGroup) -> Result<Vec<String>, ConfigError> {
        let mut members = group.local_members.clone();
        let filter = group.filter.compile()?;
        let mut included = members.iter().cloned().collect::<BTreeSet<_>>();
        for name in &group.providers {
            let provider = self
                .proxies
                .iter()
                .find(|provider| provider.name == *name)
                .ok_or_else(|| invalid("group references an undeclared proxy provider"))?;
            for member in &provider.members {
                if filter.accepts(&member.name) && included.insert(member.tag.clone()) {
                    members.push(member.tag.clone());
                }
            }
        }
        Ok(members)
    }

    pub(crate) fn validate(
        &self,
        document: &ProfileDocument,
        tags: &BTreeSet<&str>,
    ) -> Result<(), ConfigError> {
        if self.proxies.len() + self.rules.len() > MAX_PROVIDERS {
            return Err(invalid("provider count exceeds 32"));
        }
        let mut names = BTreeSet::new();
        let mut owned = BTreeSet::new();
        for provider in &self.proxies {
            if !valid_name(&provider.name) || !names.insert(&provider.name) {
                return Err(invalid("proxy provider names must be unique and bounded"));
            }
            provider.source.validate()?;
            provider.filter.accepts("")?;
            if provider.members.is_empty() {
                return Err(invalid("proxy provider has no usable members"));
            }
            for member in &provider.members {
                if !valid_name(&member.name)
                    || !owned.insert(&member.tag)
                    || !document
                        .outbounds
                        .iter()
                        .any(|node| node.tag() == member.tag && node.is_remote())
                {
                    return Err(invalid(
                        "provider members must be disjoint declared remote nodes",
                    ));
                }
            }
            if let Some(health) = &provider.health_check {
                if !(100..=10000).contains(&health.timeout_ms) {
                    return Err(invalid(
                        "provider health timeout must be 100..=10000 milliseconds",
                    ));
                }
                if let Some(status) = &health.expected_status {
                    validate_expected_status(status)?;
                }
                // Reuse the exact URL, timing and member checks of automatic groups.
                let checker = ProfileOutbound::UrlTest {
                    tag: "provider-health".into(),
                    outbounds: provider
                        .members
                        .iter()
                        .map(|member| member.tag.clone())
                        .collect(),
                    url: health.url.clone(),
                    interval_seconds: health.interval_seconds,
                    tolerance_ms: 0,
                    idle_timeout_seconds: health.interval_seconds.max(1800),
                    lazy: Some(health.lazy),
                    hidden: Some(true),
                };
                checker.validate("$.providers.health_check")?;
            }
        }
        names.clear();
        let mut total_rules = 0usize;
        for provider in &self.rules {
            if !valid_name(&provider.name) || !names.insert(&provider.name) {
                return Err(invalid("rule provider names must be unique and bounded"));
            }
            provider.source.validate()?;
            total_rules = total_rules.saturating_add(provider.rules.len());
            if provider.rules.is_empty() || total_rules > MAX_PROVIDER_RULES {
                return Err(invalid("rule providers require 1..=8192 total conditions"));
            }
            for rule in &provider.rules {
                if rule.kind == RuleKind::RuleSet {
                    return Err(invalid(
                        "rule-provider conditions cannot recursively include rule sets",
                    ));
                }
                ProfileRule {
                    kind: rule.kind,
                    value: rule.value.clone(),
                    outbound: document.outbounds[0].tag().into(),
                    no_resolve: false,
                }
                .validate("$.providers.rules", tags)?;
            }
        }
        let mut groups = BTreeMap::new();
        for group in &self.groups {
            if groups.insert(&group.group, ()).is_some()
                || group.providers.iter().collect::<BTreeSet<_>>().len() != group.providers.len()
            {
                return Err(invalid("provider group bindings must be unique"));
            }
            group.filter.accepts("")?;
            let expected = self.group_members(group)?;
            let actual = document
                .outbounds
                .iter()
                .find(|node| node.tag() == group.group)
                .and_then(ProfileOutbound::group_members)
                .ok_or_else(|| invalid("provider binding must name a group"))?;
            if actual != expected {
                return Err(invalid(
                    "materialized group membership differs from its provider bindings",
                ));
            }
        }
        Ok(())
    }
}

impl ValidatedSingBoxProfile {
    pub fn providers(&self) -> Option<&ProviderCatalog> {
        self.document.providers.as_ref()
    }

    /// Token-bearing resource URLs are envelope metadata, never part of the
    /// public profile body, its digest, QR exports or native configuration.
    pub fn provider_sources(&self) -> BTreeMap<String, String> {
        self.document
            .providers
            .as_ref()
            .map(ProviderCatalog::sources)
            .unwrap_or_default()
    }
    pub fn with_provider_sources(
        mut self,
        sources: BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        let Some(catalog) = self.document.providers.as_mut() else {
            if sources.is_empty() {
                return Ok(self);
            }
            return Err(invalid("provider URLs have no matching catalog"));
        };
        let mut remaining = sources;
        for provider in &mut catalog.proxies {
            if let Some(url) = remaining.remove(&format!("proxy:{}", provider.name)) {
                provider.source.url = Some(url);
                provider.source.validate()?;
            }
        }
        for provider in &mut catalog.rules {
            if let Some(url) = remaining.remove(&format!("rule:{}", provider.name)) {
                provider.source.url = Some(url);
                provider.source.validate()?;
            }
        }
        if !remaining.is_empty() {
            return Err(invalid("provider URLs must match declared providers"));
        }
        Ok(self)
    }
}
