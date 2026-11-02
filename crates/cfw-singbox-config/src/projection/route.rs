//! The `route` section: mode, LAN and DNS rules around the profile's rules,
//! and the rule sets they name.

use super::*;

/// What the route takes from the outbound and DNS projections.
pub(super) struct RouteSources<'a> {
    pub(super) selected_outbound: &'a str,
    pub(super) direct_outbound: &'a str,
    pub(super) global_outbound: &'a str,
    pub(super) injected_route_final: Option<String>,
    pub(super) default_domain_resolver: Value,
    pub(super) profile_dns_rule_sets: Vec<Value>,
    pub(super) mainland: bool,
}

impl ValidatedSingBoxProfile {
    /// The route of one projection: the Clash mode selectors, DNS hijack and
    /// leak protection in a tunnel, the LAN access rule and the profile's own
    /// rules, with every rule set they name.
    pub(super) fn project_route(
        &self,
        mode: ProjectionMode,
        tunnel_stack: TunnelStack,
        settings: &EngineSettings,
        sources: RouteSources<'_>,
    ) -> Map<String, Value> {
        let RouteSources {
            selected_outbound,
            direct_outbound,
            global_outbound,
            injected_route_final,
            default_domain_resolver,
            profile_dns_rule_sets,
            mainland,
        } = sources;
        let mut route = Map::new();
        if let Some(final_tag) = self
            .document
            .route
            .as_ref()
            .and_then(|route| route.final_tag.as_ref())
            .cloned()
            .or(injected_route_final)
        {
            route.insert("final".into(), Value::String(final_tag));
        }
        route.insert("default_domain_resolver".into(), default_domain_resolver);
        let appended = if mainland {
            crate::mainland::route_rules(direct_outbound, selected_outbound).to_vec()
        } else {
            Vec::new()
        };
        let (mut rules, mut rule_sets) = self.document.project_rules(selected_outbound, &appended);
        for resource in profile_dns_rule_sets {
            if !rule_sets
                .iter()
                .any(|existing| existing["tag"] == resource["tag"])
            {
                rule_sets.push(resource);
            }
        }
        rules.splice(
            0..0,
            [
                json!({"clash_mode": "Direct", "action": "route", "outbound": direct_outbound}),
                json!({"clash_mode": "Global", "action": "route", "outbound": global_outbound}),
            ],
        );
        crate::dns_policy::add_connection_dns_rules(
            &self.document,
            &mut rules,
            direct_outbound,
            route
                .get("final")
                .and_then(Value::as_str)
                .unwrap_or(selected_outbound),
        );
        if mode.has_tunnel() {
            rules.insert(0, json!({ "port": 53, "action": "hijack-dns" }));
            // DNS leak protection applies to every ordinary Tunnel projection,
            // whatever the selected route, and never to release evidence.
            if settings.dns_leak_protection
                && self.dns_projection == DnsProjection::Ordinary
                && self.release_packet_evidence_case.is_none()
            {
                rules.insert(1, crate::dns_leak::route_rule());
            }
        }
        if let Some(lan) = &settings.lan_proxy {
            rules.insert(0, crate::lan::access_rule(lan));
        }
        if !rules.is_empty() {
            route.insert("rules".into(), Value::Array(rules));
        }
        if !rule_sets.is_empty() {
            route.insert("rule_set".into(), Value::Array(rule_sets));
        }
        // The Windows packet-endpoint stack runs the engine as an ordinary
        // process while its platform owner routes the default route into the
        // tunnel adapter. Outside any Network Extension exemption, its own
        // sockets must bind to the physical default interface or they would
        // loop back into the tunnel.
        if mode.has_tunnel() && tunnel_stack == TunnelStack::Gvisor {
            route.insert("auto_detect_interface".into(), Value::Bool(true));
        }
        route
    }
}
