//! The document-level projection: the app's proxy selector, the members a
//! group may select, and the runtime outbound list.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde_json::json;

use crate::{
    ConfigError,
    profile::{ProfileDocument, ProfileOutbound},
    profile_projection::{DomainResolverTags, RuntimeOutboundProjection},
};

const APP_SELECTOR_TAG: &str = "cfw-proxy-selector";

/// The selector the app puts in front of a profile that names no final route
/// and starts with a remote node: every remote node is a member and the
/// profile's effective final route is the default. It exists only in the
/// projection, never in the saved document, so a choice made in it lives in
/// the profile's proxy selections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSelector {
    pub tag: String,
    pub members: Vec<String>,
    pub default: String,
}

impl ProfileDocument {
    pub(crate) fn app_selector(&self) -> Option<AppSelector> {
        let has_explicit_final = self
            .route
            .as_ref()
            .and_then(|route| route.final_tag.as_ref())
            .is_some();
        if has_explicit_final || !self.outbounds[0].is_remote() {
            return None;
        }
        let members = self
            .outbounds
            .iter()
            .filter(|outbound| outbound.is_remote())
            .map(|outbound| outbound.tag().to_owned())
            .collect::<Vec<_>>();
        if members.len() < 2 {
            return None;
        }
        Some(AppSelector {
            tag: self.unused_tag(APP_SELECTOR_TAG),
            members,
            default: self.effective_final_outbound_tag().to_owned(),
        })
    }

    /// The nodes a choice for `group` may name: a saved selector's members, or
    /// the app selector's remote nodes. `None` when no selector has that tag.
    pub(crate) fn selectable_members(&self, group: &str) -> Option<Vec<String>> {
        let saved = self.outbounds.iter().find_map(|outbound| match outbound {
            ProfileOutbound::Selector { tag, outbounds, .. } if tag == group => {
                Some(outbounds.clone())
            }
            _ => None,
        });
        saved.or_else(|| {
            self.app_selector()
                .filter(|selector| selector.tag == group)
                .map(|selector| selector.members)
        })
    }

    pub(crate) fn runtime_outbounds(
        &self,
        profile_id: &str,
        bootstrap_resolver: DomainResolverTags<'_>,
        proxy_selections: &BTreeMap<String, String>,
    ) -> Result<RuntimeOutboundProjection, ConfigError> {
        let proxy_tags = self
            .dns
            .as_ref()
            .and_then(|dns| dns.proxy_servers.as_ref())
            .map(|pool| crate::dns_policy::resolver_tags("cfw-proxy-server-dns", pool.len()));
        let bootstrap_resolver =
            proxy_tags
                .as_ref()
                .map_or(bootstrap_resolver, |tags| DomainResolverTags {
                    server: &tags[0],
                    fallback_servers: &tags[1..],
                });
        let direct_resolver = self.dns.as_ref().map(|dns| match &dns.direct_servers {
            Some(_) if dns.direct_follow_policy && !dns.nameserver_policy.is_empty() => {
                json!({"policy":"cfw-direct"})
            }
            Some(pool) => crate::dns_policy::resolver_value(&crate::dns_policy::resolver_tags(
                "cfw-direct-dns",
                pool.len(),
            )),
            None => json!({"policy":"default"}),
        });
        let mut outbounds = Vec::with_capacity(self.outbounds.len() + 1);
        let mut endpoints = Vec::new();
        let mut slots = Vec::new();
        for outbound in &self.outbounds {
            let endpoint = outbound.is_endpoint();
            let index = if endpoint {
                endpoints.len()
            } else {
                outbounds.len()
            };
            let (mut projected, mut outbound_slots) =
                outbound.runtime_projection(index, profile_id, bootstrap_resolver)?;
            if let Some(detour) = self.detours.get(outbound.tag()) {
                let object = projected
                    .as_object_mut()
                    .expect("outbound projection is an object");
                object.insert("detour".into(), json!(detour));
                object.remove("domain_resolver");
            } else if outbound
                .server()
                .is_some_and(|server| self.hosts.contains_key(&server.to_ascii_lowercase()))
            {
                projected["domain_resolver"] = json!({"server": crate::dns_policy::HOSTS_DNS_TAG});
            } else if self
                .dns
                .as_ref()
                .is_some_and(|dns| !dns.proxy_server_policy.is_empty())
                && outbound
                    .server()
                    .is_some_and(|server| server.parse::<IpAddr>().is_err())
            {
                projected["domain_resolver"] = json!({"policy":"cfw-proxy-endpoint"});
            } else if let (Some(dns), Some(server)) = (&self.dns, outbound.server())
                && server.parse::<IpAddr>().is_err()
                && let Some(resolver) = dns.implicit_endpoint_resolver(server)?
            {
                projected["domain_resolver"] = resolver;
            }
            if endpoint {
                endpoints.push(projected);
            } else {
                outbounds.push(projected);
            }
            slots.append(&mut outbound_slots);
        }

        let profile_final = self.effective_final_outbound_tag().to_owned();
        if let Some(providers) = &self.providers {
            for (index, provider) in providers.proxies.iter().enumerate() {
                if let Some(health) = &provider.health_check {
                    let tag = self.unused_tag(&format!("cfw-provider-health-{index}"));
                    outbounds.push(json!({"type":"urltest", "tag":tag, "outbounds":provider.members.iter().map(|member|&member.tag).collect::<Vec<_>>(),
                        "url":health.url, "interval":format!("{}s",health.interval_seconds), "idle_timeout":format!("{}s",health.interval_seconds.max(1800)),
                        "lazy":health.lazy, "hidden":true, "timeout":format!("{}ms",health.timeout_ms), "expected_status":health.expected_status.as_deref().unwrap_or_default(), "tolerance":0, "interrupt_exist_connections":false}));
                }
            }
        }
        let remote_tags = self
            .outbounds
            .iter()
            .filter(|outbound| outbound.is_remote())
            .map(|outbound| outbound.tag().to_owned())
            .collect::<Vec<_>>();
        let has_explicit_final = self
            .route
            .as_ref()
            .and_then(|route| route.final_tag.as_ref())
            .is_some();
        let app_selector = self.app_selector();
        let injected_route_final = app_selector.as_ref().map(|selector| selector.tag.clone());
        if let Some(selector) = app_selector {
            let default = match proxy_selections.get(&selector.tag) {
                Some(chosen) if selector.members.contains(chosen) => chosen.clone(),
                Some(chosen) => {
                    return Err(ConfigError::UnsupportedPolicyShape {
                        path: "$.outbounds".into(),
                        reason: format!(
                            "the saved choice {chosen} is not a node of {}",
                            selector.tag
                        ),
                    });
                }
                None => selector.default,
            };
            outbounds.push(json!({
                "type": "selector",
                "tag": selector.tag,
                "outbounds": selector.members,
                "default": default,
                "interrupt_exist_connections": false,
            }));
        }
        let selected_outbound = injected_route_final
            .clone()
            .unwrap_or_else(|| profile_final.clone());
        let direct_outbound = self
            .outbounds
            .iter()
            .find_map(|outbound| match outbound {
                ProfileOutbound::Direct { tag } => Some(tag.clone()),
                _ => None,
            })
            .unwrap_or_else(|| {
                let tag = self.unused_tag("cfw-direct");
                outbounds.push(json!({"type": "direct", "tag": tag}));
                tag
            });
        let global_outbound = injected_route_final
            .clone()
            .or_else(|| {
                self.outbounds.iter().find_map(|outbound| match outbound {
                    ProfileOutbound::Selector { tag, .. }
                    | ProfileOutbound::UrlTest { tag, .. }
                    | ProfileOutbound::Fallback { tag, .. }
                    | ProfileOutbound::LoadBalance { tag, .. } => Some(tag.clone()),
                    _ => None,
                })
            })
            .or_else(|| remote_tags.first().cloned())
            .unwrap_or_else(|| selected_outbound.clone());
        // Endpoint-backed policies must not fall through to the synthesized
        // DIRECT outbound simply because endpoints use a separate array.
        let injected_route_final = injected_route_final.or_else(|| {
            (!has_explicit_final && self.outbounds[0].is_endpoint()).then(|| profile_final.clone())
        });
        if let Some(resolver) = direct_resolver {
            for outbound in &mut outbounds {
                if outbound["type"] == "direct" {
                    outbound["domain_resolver"] = resolver.clone();
                }
            }
        }
        Ok(RuntimeOutboundProjection {
            outbounds,
            endpoints,
            credential_slots: slots,
            selected_outbound,
            direct_outbound,
            global_outbound,
            injected_route_final,
        })
    }

    fn unused_tag(&self, prefix: &str) -> String {
        let profile_tags = self
            .outbounds
            .iter()
            .map(ProfileOutbound::tag)
            .collect::<BTreeSet<_>>();
        if !profile_tags.contains(prefix) {
            return prefix.to_owned();
        }
        for suffix in 2..=self.outbounds.len() + 1 {
            let candidate = format!("{prefix}-{suffix}");
            if !profile_tags.contains(candidate.as_str()) {
                return candidate;
            }
        }
        unreachable!("a bounded selector tag search must find a free tag")
    }
}
