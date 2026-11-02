//! The outbound-only configuration explicit node latency tests run.

use super::*;

/// Every rule-set tag `value` names, through logical sub-rules and response
/// filters included. The probe's rules name only tags by then
/// ([`retain_loadable_rules`]).
fn rule_set_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                match (key.as_str(), nested) {
                    ("rule_set", Value::Array(tags)) => {
                        names.extend(tags.iter().filter_map(Value::as_str).map(str::to_owned));
                    }
                    _ => rule_set_names(nested, names),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                rule_set_names(item, names);
            }
        }
        _ => {}
    }
}

/// Whether every rule set `value` names, through logical sub-rules and
/// response filters included, is a tag in `loadable`. The projection names
/// rule sets in arrays; any other form counts as not loadable.
fn names_only(value: &Value, loadable: &BTreeSet<String>) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .all(|(key, nested)| match (key.as_str(), nested) {
                ("rule_set", Value::Array(tags)) => tags
                    .iter()
                    .all(|tag| tag.as_str().is_some_and(|tag| loadable.contains(tag))),
                ("rule_set", _) => false,
                _ => names_only(nested, loadable),
            }),
        Value::Array(items) => items.iter().all(|item| names_only(item, loadable)),
        _ => true,
    }
}

/// Whether `rule` reads a response: sing-box binds a `respond` rule, and a rule
/// with `match_response` in its logical tree, to the latest anonymous evaluate
/// before it, and refuses one with none (v1.14.4 `dns/router.go`).
fn reads_response(rule: &Value) -> bool {
    fn matches_response(rule: &Value) -> bool {
        rule["match_response"] == Value::Bool(true)
            || rule["rules"]
                .as_array()
                .is_some_and(|rules| rules.iter().any(matches_response))
    }
    rule["action"] == "respond" || matches_response(rule)
}

/// Keeps the rules of `rules` that name only rule sets in `loadable`. A reader
/// of an evaluate that is left out goes with it: it would otherwise read an
/// older, unrelated response, or none.
fn retain_loadable_rules(rules: Option<&mut Value>, loadable: &BTreeSet<String>) {
    if let Some(Value::Array(rules)) = rules {
        let mut evaluate_kept = true;
        rules.retain(|rule| {
            let keep = names_only(rule, loadable) && (evaluate_kept || !reads_response(rule));
            if rule["action"] == "evaluate" && rule.get("tag").is_none() {
                evaluate_kept = keep;
            }
            keep
        });
    }
}

/// The probe configuration and credentials derived from one projection, with
/// the tags the probe cannot measure.
pub(crate) struct ProxyProbeTemplate {
    pub(crate) json: String,
    pub(crate) credential_slots: Vec<CredentialSlot>,
    pub(crate) excluded_tags: Vec<String>,
}

fn projected_tag(outbound: &Value) -> String {
    outbound["tag"]
        .as_str()
        .expect("every projected outbound carries a tag")
        .to_owned()
}

impl ProjectedConfig {
    /// A transient, outbound-only view for explicit node latency tests. The
    /// normal projection remains the source of protocol/DNS/credential policy;
    /// listeners, system routes, persistence and autonomous tests are excluded.
    ///
    /// The probe has no rule-set cache, so a remote dataset would be fetched
    /// through the proxy under test before every measurement. DNS rules that
    /// name any rule set other than an inline one are therefore left out of
    /// `dns.rules` and of every DNS policy, together with the rules that read
    /// the response of an evaluate left out, and queries they would match
    /// fall through to the rules after them. The inline sets the remaining
    /// rules name are kept: sing-box refuses a rule that names an undeclared
    /// set.
    ///
    /// Tailscale endpoints stay with the running core (see below), and the
    /// template names the tags it therefore cannot measure.
    pub(crate) fn proxy_probe_template(&self) -> Result<ProxyProbeTemplate, ConfigError> {
        let mut root: Map<String, Value> = serde_json::from_str(&self.json)?;
        root.retain(|key, _| matches!(key.as_str(), "outbounds" | "endpoints" | "dns"));
        let mut original: Value = serde_json::from_str(&self.json)?;
        let inline: Vec<Value> = original["route"]["rule_set"]
            .as_array()
            .map(|resources| {
                resources
                    .iter()
                    .filter(|resource| resource["type"] == "inline")
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let loadable: BTreeSet<String> = inline
            .iter()
            .filter_map(|resource| resource["tag"].as_str().map(str::to_owned))
            .collect();
        if let Some(dns) = root.get_mut("dns") {
            retain_loadable_rules(dns.get_mut("rules"), &loadable);
            if let Some(Value::Array(policies)) = dns.get_mut("policies") {
                for policy in policies {
                    retain_loadable_rules(policy.get_mut("rules"), &loadable);
                }
            }
        }
        let mut named = BTreeSet::new();
        if let Some(dns) = root.get("dns") {
            rule_set_names(dns, &mut named);
        }
        let kept: Vec<Value> = inline
            .into_iter()
            .filter(|resource| {
                resource["tag"]
                    .as_str()
                    .is_some_and(|tag| named.contains(tag))
            })
            .collect();
        let mut route = Map::new();
        if let Some(resolver) = original["route"].get_mut("default_domain_resolver") {
            route.insert("default_domain_resolver".into(), resolver.take());
        }
        if !kept.is_empty() {
            route.insert("rule_set".into(), Value::Array(kept));
        }
        if !route.is_empty() {
            root.insert("route".into(), Value::Object(route));
        }
        if let Some(Value::Array(outbounds)) = root.get_mut("outbounds") {
            for outbound in outbounds {
                if matches!(
                    outbound["type"].as_str(),
                    Some("urltest" | "fallback" | "loadbalance")
                ) {
                    *outbound = json!({
                        "type": "selector",
                        "tag": outbound["tag"],
                        "outbounds": outbound["outbounds"],
                    });
                }
            }
        }
        // A Tailscale endpoint registers a tailnet node from its persistent
        // state directory. A transient probe would register a second node from
        // the same key, or fail outright on a single-use key, so the probe
        // leaves those endpoints out together with every group left without a
        // member, and the slots of the remaining endpoints move up with them.
        let mut excluded = BTreeSet::new();
        let mut endpoint_positions = Vec::new();
        if let Some(Value::Array(endpoints)) = root.get_mut("endpoints") {
            let mut kept = Vec::with_capacity(endpoints.len());
            for endpoint in endpoints.drain(..) {
                if endpoint["type"] == "tailscale" {
                    excluded.insert(projected_tag(&endpoint));
                    endpoint_positions.push(None);
                } else {
                    endpoint_positions.push(Some(kept.len()));
                    kept.push(endpoint);
                }
            }
            *endpoints = kept;
        }
        if root
            .get("endpoints")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            root.remove("endpoints");
        }
        if let Some(Value::Array(outbounds)) = root.get_mut("outbounds") {
            while !excluded.is_empty() {
                let mut emptied = Vec::new();
                for outbound in outbounds.iter_mut() {
                    if outbound["type"] != "selector" {
                        continue;
                    }
                    let tag = projected_tag(outbound);
                    let Some(Value::Array(members)) = outbound.get_mut("outbounds") else {
                        continue;
                    };
                    members.retain(|member| {
                        !member
                            .as_str()
                            .is_some_and(|member| excluded.contains(member))
                    });
                    if members.is_empty() {
                        emptied.push(tag);
                    } else if outbound["default"]
                        .as_str()
                        .is_some_and(|default| excluded.contains(default))
                    {
                        outbound
                            .as_object_mut()
                            .expect("selector projection is an object")
                            .remove("default");
                    }
                }
                if emptied.is_empty() {
                    break;
                }
                outbounds.retain(|outbound| !emptied.contains(&projected_tag(outbound)));
                excluded.extend(emptied);
            }
        }
        let credential_slots = self
            .credential_slots
            .iter()
            .filter_map(|slot| {
                if slot.target().container() != "endpoints" {
                    return Some(Ok(slot.clone()));
                }
                let position = endpoint_positions
                    .get(usize::from(slot.outbound_index()))
                    .copied()
                    .expect("every endpoint slot indexes a projected endpoint");
                position.map(|index| {
                    CredentialSlot::new(slot.reference().clone(), slot.target(), index)
                        .map_err(ConfigError::from)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let template = Value::Object(root);
        validate_slots(&template, &credential_slots)?;
        Ok(ProxyProbeTemplate {
            json: serde_json::to_string(&template)?,
            credential_slots,
            excluded_tags: excluded.into_iter().collect(),
        })
    }
}

/// What an explicit node latency test runs: the outbound-only probe
/// configuration and the credentials it needs, from one projection
/// ([`ValidatedSingBoxProfile::project_proxy_probe`]).
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyProbe {
    credential_audience: CredentialAudience,
    credential_slots: Vec<CredentialSlot>,
    json: String,
    excluded_tags: Vec<String>,
}

impl fmt::Debug for ProxyProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyProbe")
            .field("credential_audience", &self.credential_audience)
            .field("credential_slots", &self.credential_slots)
            .field("excluded_tags", &self.excluded_tags)
            .field("json", &"[REDACTED CONFIG TEMPLATE]")
            .finish()
    }
}

impl ProxyProbe {
    pub fn credential_audience(&self) -> &CredentialAudience {
        &self.credential_audience
    }

    pub fn credential_slots(&self) -> &[CredentialSlot] {
        &self.credential_slots
    }

    pub fn as_json(&self) -> &str {
        &self.json
    }

    /// Tags the probe cannot measure: Tailscale endpoints, whose node state
    /// belongs to the running core, and groups left without a member.
    pub fn excluded_tags(&self) -> &[String] {
        &self.excluded_tags
    }
}

impl ValidatedSingBoxProfile {
    /// The transient, outbound-only configuration explicit node latency tests
    /// run, with its credential audience and slots, all from one projection
    /// made with mainland China direct off: the probe keeps the DNS servers
    /// and rules but no rule sets, and the switch's DNS rules name rule sets.
    pub fn project_proxy_probe(
        &self,
        profile_id: &str,
        mode: ProjectionMode,
        settings: &EngineSettings,
    ) -> Result<ProxyProbe, ConfigError> {
        let settings = EngineSettings {
            mainland_china_direct: false,
            ..settings.clone()
        };
        let projected = self.project(profile_id, mode, &settings)?;
        let template = projected.proxy_probe_template()?;
        Ok(ProxyProbe {
            json: template.json,
            credential_audience: projected.credential_audience,
            credential_slots: template.credential_slots,
            excluded_tags: template.excluded_tags,
        })
    }
}
