//! Latency probes declare every rule set their DNS rules and policies name.

use super::*;

/// Every rule-set tag `value` names, through logical sub-rules and response
/// filters included.
fn named_rule_sets(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                match (key.as_str(), nested) {
                    ("rule_set", Value::String(tag)) => {
                        names.insert(tag.clone());
                    }
                    ("rule_set", Value::Array(tags)) => names.extend(
                        tags.iter()
                            .map(|tag| tag.as_str().expect("rule-set tag").to_owned()),
                    ),
                    ("rule_set", other) => panic!("rule_set must name tags: {other}"),
                    _ => named_rule_sets(nested, names),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| named_rule_sets(item, names)),
        _ => {}
    }
}

/// The rule sets `config` declares, each with its type.
fn declared_rule_sets(config: &Value) -> BTreeMap<String, String> {
    config["route"]["rule_set"]
        .as_array()
        .map(|resources| {
            resources
                .iter()
                .map(|resource| {
                    (
                        resource["tag"].as_str().expect("tag").to_owned(),
                        resource["type"].as_str().expect("type").to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `rule` reads a response: sing-box binds a `respond` rule, and a rule
/// with `match_response` in its logical tree, to the latest anonymous
/// evaluate before it (`dns/router.go`, validateLegacyDNSModeDisabledRules).
fn reads_response(rule: &Value) -> bool {
    fn matches_response(rule: &Value) -> bool {
        rule["match_response"] == json!(true)
            || rule["rules"]
                .as_array()
                .is_some_and(|rules| rules.iter().any(matches_response))
    }
    rule["action"] == "respond" || matches_response(rule)
}

fn is_anonymous_evaluate(rule: &Value) -> bool {
    rule["action"] == "evaluate" && rule.get("tag").is_none()
}

/// The positions of the rules of `rules` a probe keeps: none that names one
/// of `excluded`, and no reader of an evaluate that is left out, which would
/// otherwise read an older, unrelated response or none.
fn probe_rule_positions(rules: &[Value], excluded: &BTreeSet<String>) -> Vec<usize> {
    let names_excluded = |rule: &Value| {
        let mut names = BTreeSet::new();
        named_rule_sets(rule, &mut names);
        !names.is_disjoint(excluded)
    };
    let mut latest: Option<&Value> = None;
    let mut kept = Vec::new();
    for (position, rule) in rules.iter().enumerate() {
        let reads_left_out = reads_response(rule) && latest.is_some_and(names_excluded);
        if !names_excluded(rule) && !reads_left_out {
            kept.push(position);
        }
        if is_anonymous_evaluate(rule) {
            latest = Some(rule);
        }
    }
    kept
}

/// The kept rules must load as the runtime's do: every kept reader binds the
/// evaluate it binds in `rules`, so none reads another server's response,
/// and none lacks one.
fn assert_same_bindings(rules: &[Value], kept: &[usize]) {
    let mut latest = None;
    let mut bound = vec![None; rules.len()];
    for (position, rule) in rules.iter().enumerate() {
        if reads_response(rule) {
            bound[position] = latest;
        }
        if is_anonymous_evaluate(rule) {
            latest = Some(position);
        }
    }
    let mut latest_kept = None;
    for &position in kept {
        let rule = &rules[position];
        if reads_response(rule) {
            assert!(latest_kept.is_some(), "reader without an evaluate: {rule}");
            assert_eq!(latest_kept, bound[position], "{rule}");
        }
        if is_anonymous_evaluate(rule) {
            latest_kept = Some(position);
        }
    }
}

/// The rules at `positions` of `rules`.
fn at(rules: &[Value], positions: &[usize]) -> Vec<Value> {
    positions
        .iter()
        .map(|&position| rules[position].clone())
        .collect()
}

#[test]
fn latency_probes_declare_every_rule_set_their_dns_rules_and_policies_name() {
    let mut input = source();
    input["providers"] = json!({"rules":[
        {"name":"sites","source":{"interval_seconds":86400},"format":"yaml","behavior":"classical",
        "rules":[{"type":"domain_suffix","value":"example.org"}]},
        {"name":"unproxied","source":{"interval_seconds":86400},"format":"yaml","behavior":"classical",
        "rules":[{"type":"domain_suffix","value":"example.net"}]}
    ]});
    input["dns"]["nameserver_policy"] = json!([
        {"domain":"geosite:cn","servers":[{"type":"tcp","server":"223.5.5.5","server_port":53}]},
        {"domain":"rule-set:sites","servers":[{"type":"tcp","server":"223.6.6.6","server_port":53}]}
    ]);
    input["dns"]["proxy_server_policy"] = json!([
        {"domain":"geosite:geolocation-!cn","servers":[{"type":"udp","server":"8.8.8.8","server_port":53,"route":"direct"}]},
        {"domain":"rule-set:sites","servers":[{"type":"udp","server":"1.0.0.1","server_port":53,"route":"direct"}]}
    ]);
    input["dns"]["fallback_servers"] = json!([{"type":"udp","server":"8.8.4.4","server_port":53}]);
    input["dns"]["fallback_filter"] = json!({"geoip_code":"cn","geosite":["geolocation-!cn"]});
    input["dns"]["fake_ip"] = json!({"exclude":["geosite:cn","rule-set:unproxied"]});
    let profile =
        ValidatedSingBoxProfile::parse(&input.to_string()).expect("validated DNS profile");
    let settings = EngineSettings::default();
    let runtime: Value = serde_json::from_str(
        profile
            .project(PROFILE_ID, ProjectionMode::SystemProxy, &settings)
            .expect("projection")
            .as_json(),
    )
    .expect("runtime JSON");
    let probe: Value = serde_json::from_str(
        profile
            .project_proxy_probe(PROFILE_ID, ProjectionMode::SystemProxy, &settings)
            .expect("probe")
            .as_json(),
    )
    .expect("probe JSON");

    // The user's own projection is unchanged: it names and declares the
    // datasets and the provider's inline rule set.
    let runtime_declared = declared_rule_sets(&runtime);
    let mut runtime_named = BTreeSet::new();
    named_rule_sets(&runtime["dns"], &mut runtime_named);
    for tag in [
        "cfw-geosite-cn",
        "cfw-geosite-geolocation-!cn",
        "cfw-geoip-cn",
        "cfw-dns-provider-0",
    ] {
        assert!(runtime_named.contains(tag), "{tag}");
        assert!(runtime_declared.contains_key(tag), "{tag}");
    }
    let remote: BTreeSet<String> = runtime_declared
        .iter()
        .filter(|(_, kind)| kind.as_str() == "remote")
        .map(|(tag, _)| tag.clone())
        .collect();
    assert!(remote.contains("cfw-geoip-cn"));

    // sing-box refuses a DNS rule that names an undeclared rule set, so the
    // probe declares every one it names, and downloads none.
    let probe_declared = declared_rule_sets(&probe);
    let mut probe_named = BTreeSet::new();
    named_rule_sets(&probe["dns"], &mut probe_named);
    let undeclared: Vec<_> = probe_named
        .iter()
        .filter(|tag| !probe_declared.contains_key(*tag))
        .collect();
    assert!(
        undeclared.is_empty(),
        "undeclared rule sets: {undeclared:?}"
    );
    assert!(
        probe_declared.values().all(|kind| kind == "inline"),
        "{probe_declared:?}"
    );
    // Only the sets the kept rules name: the fake-IP rule that alone names the
    // second provider's set needs a dataset too, so both go.
    assert_eq!(
        probe_declared.keys().cloned().collect::<BTreeSet<_>>(),
        probe_named
    );
    assert!(runtime_declared.contains_key("cfw-dns-provider-1"));
    assert!(!probe_declared.contains_key("cfw-dns-provider-1"));
    assert!(probe_named.contains("cfw-dns-provider-0"));

    // Exactly the rules that need a downloaded dataset are left out, with the
    // readers of the evaluates among them, in order, from the rules and from
    // every DNS policy; every kept reader keeps its evaluate.
    let probe_rules_kept = probe["dns"]["rules"].as_array().expect("probe rules");
    let runtime_rules = runtime["dns"]["rules"].as_array().expect("runtime rules");
    let kept = probe_rule_positions(runtime_rules, &remote);
    assert_eq!(probe_rules_kept, &at(runtime_rules, &kept));
    assert!(probe_rules_kept.len() < runtime_rules.len());
    assert_same_bindings(runtime_rules, &kept);
    let runtime_policies = runtime["dns"]["policies"].as_array().expect("policies");
    let probe_policies = probe["dns"]["policies"].as_array().expect("probe policies");
    assert_eq!(probe_policies.len(), runtime_policies.len());
    for (kept, original) in probe_policies.iter().zip(runtime_policies) {
        assert_eq!(kept["tag"], original["tag"]);
        assert_eq!(kept["final"], original["final"]);
        let original_rules = original["rules"].as_array().expect("rules");
        let positions = probe_rule_positions(original_rules, &remote);
        assert_eq!(
            kept["rules"].as_array().expect("policy rules"),
            &at(original_rules, &positions)
        );
        assert_same_bindings(original_rules, &positions);
    }
    // The GeoIP response filter's evaluates go, and their responds with them.
    let filtered = |rules: &[Value]| {
        rules
            .iter()
            .filter(|rule| rule.get("response_filter").is_some())
            .count()
    };
    assert!(filtered(runtime_rules) > 0);
    assert_eq!(filtered(probe_rules_kept), 0);
    for key in ["servers", "final", "strategy"] {
        assert_eq!(probe["dns"].get(key), runtime["dns"].get(key), "{key}");
    }
}
