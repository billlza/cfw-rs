//! Provider catalogs: filters, expected statuses, sources, bindings, and the
//! provider URLs that stay outside the profile body.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::{
    ConfigError, ProviderCatalog, ProviderFilter, ProviderGroup, ProviderSource,
    ValidatedSingBoxProfile, validate_expected_status,
};

const SOURCE_URL: &str = "https://provider.example.com/subscription?token=secret";

/// A selector bound to one proxy provider whose two nodes it lists after
/// its local DIRECT member, and one inline rule provider.
fn profile() -> Value {
    json!({
        "outbounds": [
            {"type":"selector","tag":"Proxy","outbounds":["DIRECT","hk-1","jp-1"]},
            {"type":"socks5","tag":"hk-1","server":"hk1.example.com","server_port":1080},
            {"type":"socks5","tag":"jp-1","server":"jp1.example.com","server_port":1080},
            {"type":"direct","tag":"DIRECT"}
        ],
        "route": {"final":"Proxy","rules":[{"type":"rule_set","value":"lists","outbound":"DIRECT"}]},
        "providers": {
            "proxies": [{
                "name":"subscription",
                "source":{"interval_seconds":3600},
                "members":[{"tag":"hk-1","name":"HK 1"},{"tag":"jp-1","name":"JP 1"}]
            }],
            "rules": [{
                "name":"lists",
                "source":{"interval_seconds":0},
                "format":"yaml",
                "behavior":"classical",
                "rules":[{"type":"domain_suffix","value":"cn.example"}]
            }],
            "groups": [{"group":"Proxy","local_members":["DIRECT"],"providers":["subscription"]}]
        }
    })
}

fn parse(value: &Value) -> Result<ValidatedSingBoxProfile, ConfigError> {
    ValidatedSingBoxProfile::parse(&value.to_string())
}

#[track_caller]
fn rejection(result: Result<ValidatedSingBoxProfile, ConfigError>) -> (String, String) {
    match result {
        Err(ConfigError::UnsupportedPolicyShape { path, reason }) => (path, reason),
        Err(other) => panic!("unexpected error {other:?}"),
        Ok(_) => panic!("the profile was accepted"),
    }
}

#[track_caller]
fn provider_rejection(value: &Value) -> String {
    let (path, reason) = rejection(parse(value));
    assert_eq!(path, "$.providers");
    reason
}

#[test]
fn the_reference_catalog_is_accepted() {
    let profile = parse(&profile()).expect("reference catalog");
    let catalog = profile.providers().expect("catalog");
    assert_eq!(catalog.proxies[0].members.len(), 2);
    assert!(profile.provider_sources().is_empty());
}

#[test]
fn filters_are_bounded_regular_expressions() {
    let include = |pattern: &str| ProviderFilter {
        include: Some(pattern.to_owned()),
        exclude: None,
    };
    for (filter, reason) in [
        (
            include(&"a".repeat(2049)),
            "provider filter exceeds 2048 bytes",
        ),
        (
            include("("),
            "provider filter is not a supported bounded regular expression",
        ),
    ] {
        assert!(matches!(
            filter.accepts("HK"),
            Err(ConfigError::UnsupportedPolicyShape { reason: actual, .. }) if actual == reason
        ));
    }
    assert!(include(&"a".repeat(2048)).compile().is_ok());

    let filter = ProviderFilter {
        include: Some("^(HK|JP)".into()),
        exclude: Some("(?i)test".into()),
    }
    .compile()
    .expect("bounded filter");
    assert!(filter.accepts("HK 1"));
    assert!(!filter.accepts("SG 1"));
    assert!(!filter.accepts("JP Test"));
    assert!(
        ProviderFilter::default()
            .compile()
            .unwrap()
            .accepts("anything")
    );
}

#[test]
fn expected_statuses_are_codes_and_ranges_of_three_digits() {
    for valid in ["", "200", "204/301-302", "100-599"] {
        validate_expected_status(valid).unwrap_or_else(|error| panic!("{valid}: {error:?}"));
    }
    let long = "200/".repeat(32) + "2";
    for (invalid, reason) in [
        (long.as_str(), "expected HTTP status is too long"),
        ("2000", "expected HTTP status must use three-digit codes"),
        ("20a", "expected HTTP status must use three-digit codes"),
        ("200/", "expected HTTP status must use three-digit codes"),
        (
            "200-201-202",
            "expected HTTP status must contain codes or ranges separated by /",
        ),
        ("099", "expected HTTP status must be 100..=599"),
        ("600", "expected HTTP status must be 100..=599"),
        ("299-200", "expected HTTP status range is reversed"),
    ] {
        assert!(
            matches!(
                validate_expected_status(invalid),
                Err(ConfigError::UnsupportedPolicyShape { reason: actual, .. }) if actual == reason
            ),
            "{invalid}"
        );
    }
}

#[test]
fn inline_sources_refresh_never_or_within_bounds() {
    for interval in [0, 60, 604_800] {
        let mut profile = profile();
        profile["providers"]["proxies"][0]["source"]["interval_seconds"] = json!(interval);
        parse(&profile).unwrap_or_else(|error| panic!("{interval}: {error:?}"));
    }
    for interval in [59, 604_801] {
        let mut profile = profile();
        profile["providers"]["proxies"][0]["source"]["interval_seconds"] = json!(interval);
        assert_eq!(
            provider_rejection(&profile),
            "materialized providers need either an inline source or a bounded update interval"
        );
    }
}

#[test]
fn remote_sources_are_bounded_https_urls_kept_outside_the_profile_body() {
    // A remote rule provider refreshes within the same bounds as a proxy one.
    let mut refreshed = profile();
    refreshed["providers"]["rules"][0]["source"]["interval_seconds"] = json!(86_400);
    let attached = parse(&refreshed)
        .unwrap()
        .with_provider_sources(BTreeMap::from([
            ("proxy:subscription".to_owned(), SOURCE_URL.to_owned()),
            (
                "rule:lists".to_owned(),
                SOURCE_URL.replace("subscription", "lists"),
            ),
        ]))
        .expect("bounded provider URLs");
    assert_eq!(
        attached.provider_sources(),
        BTreeMap::from([
            ("proxy:subscription".to_owned(), SOURCE_URL.to_owned()),
            (
                "rule:lists".to_owned(),
                SOURCE_URL.replace("subscription", "lists")
            ),
        ])
    );
    assert!(!attached.as_json().contains("token=secret"));
    let source = &attached.providers().unwrap().proxies[0].source;
    let rendered = format!("{source:?}");
    assert!(rendered.contains("remote: true"), "{rendered}");
    assert!(!rendered.contains("token"), "{rendered}");

    let attach = |url: &str| {
        parse(&profile())
            .unwrap()
            .with_provider_sources(BTreeMap::from([(
                "proxy:subscription".to_owned(),
                url.to_owned(),
            )]))
    };
    let bounded =
        "remote providers require bounded HTTPS URLs and update intervals of 60..=604800 seconds";
    for url in [
        "http://provider.example.com/subscription",
        "https://user:password@provider.example.com/",
        "https://user@provider.example.com/",
        "https://provider.example.com/#fragment",
        "https://provider.example.com:0/",
        &format!("https://provider.example.com/{}", "a".repeat(8192)),
    ] {
        assert_eq!(rejection(attach(url)).1, bounded, "{url}");
    }
    assert_eq!(rejection(attach("not a url")).1, "provider URL is invalid");
    assert_eq!(rejection(attach("data:text/plain,x")).1, bounded);

    let mut unrefreshed = profile();
    unrefreshed["providers"]["proxies"][0]["source"]["interval_seconds"] = json!(0);
    let remote_without_interval =
        parse(&unrefreshed)
            .unwrap()
            .with_provider_sources(BTreeMap::from([(
                "proxy:subscription".to_owned(),
                SOURCE_URL.to_owned(),
            )]));
    assert_eq!(rejection(remote_without_interval).1, bounded);
}

#[test]
fn provider_urls_must_match_the_declared_providers() {
    let unmatched = parse(&profile())
        .unwrap()
        .with_provider_sources(BTreeMap::from([(
            "proxy:other".to_owned(),
            SOURCE_URL.to_owned(),
        )]));
    assert_eq!(
        rejection(unmatched).1,
        "provider URLs must match declared providers"
    );

    let mut plain = profile();
    plain.as_object_mut().unwrap().remove("providers");
    plain["route"] = json!({"final":"Proxy"});
    plain["outbounds"][0]["outbounds"] = json!(["DIRECT", "hk-1", "jp-1"]);
    let plain = parse(&plain).expect("profile without providers");
    assert!(plain.providers().is_none());
    assert!(plain.provider_sources().is_empty());
    let without_catalog = plain.clone().with_provider_sources(BTreeMap::new());
    assert!(without_catalog.is_ok());
    assert_eq!(
        rejection(plain.with_provider_sources(BTreeMap::from([(
            "proxy:subscription".to_owned(),
            SOURCE_URL.to_owned(),
        )])))
        .1,
        "provider URLs have no matching catalog"
    );
}

#[test]
fn catalogs_hold_at_most_32_providers() {
    let rules = |count: usize| {
        (0..count)
            .map(|index| {
                json!({"name":format!("rules-{index}"),"source":{"interval_seconds":0},
                    "format":"text","behavior":"domain","rules":[{"type":"domain","value":"example.com"}]})
            })
            .collect::<Vec<_>>()
    };
    // The reference profile already declares one proxy and one rule provider.
    let mut at_limit = profile();
    let mut providers = rules(30);
    providers.push(at_limit["providers"]["rules"][0].clone());
    at_limit["providers"]["rules"] = json!(providers);
    parse(&at_limit).expect("32 providers");

    let mut over = at_limit.clone();
    over["providers"]["rules"]
        .as_array_mut()
        .unwrap()
        .extend(rules(31).into_iter().skip(30));
    assert_eq!(provider_rejection(&over), "provider count exceeds 32");
}

#[test]
fn proxy_providers_own_disjoint_declared_remote_nodes() {
    let rejected = |change: fn(&mut Value)| {
        let mut profile = profile();
        change(&mut profile);
        provider_rejection(&profile)
    };
    let names = "proxy provider names must be unique and bounded";
    assert_eq!(
        rejected(|profile| profile["providers"]["proxies"][0]["name"] = json!("")),
        names
    );
    assert_eq!(
        rejected(|profile| profile["providers"]["proxies"][0]["name"] = json!(" padded")),
        names
    );
    assert_eq!(
        rejected(|profile| {
            let copy = profile["providers"]["proxies"][0].clone();
            profile["providers"]["proxies"]
                .as_array_mut()
                .unwrap()
                .push(copy);
        }),
        names
    );
    assert_eq!(
        rejected(|profile| profile["providers"]["proxies"][0]["members"] = json!([])),
        "proxy provider has no usable members"
    );
    let members = "provider members must be disjoint declared remote nodes";
    for change in [
        (|profile: &mut Value| {
            profile["providers"]["proxies"][0]["members"][0]["tag"] = json!("DIRECT")
        }) as fn(&mut Value),
        |profile| profile["providers"]["proxies"][0]["members"][0]["tag"] = json!("missing"),
        |profile| profile["providers"]["proxies"][0]["members"][1]["tag"] = json!("hk-1"),
        |profile| profile["providers"]["proxies"][0]["members"][0]["name"] = json!("\u{7}"),
    ] {
        assert_eq!(rejected(change), members);
    }
    assert_eq!(
        rejected(|profile| profile["providers"]["proxies"][0]["filter"] = json!({"exclude":"("})),
        "provider filter is not a supported bounded regular expression"
    );
}

#[test]
fn provider_health_checks_reuse_the_automatic_group_bounds() {
    let with_health = |health: Value| {
        let mut profile = profile();
        profile["providers"]["proxies"][0]["health_check"] = health;
        parse(&profile)
    };
    let health = |timeout_ms: u32| json!({"url":"https://www.gstatic.com/generate_204","interval_seconds":300,"lazy":true,"timeout_ms":timeout_ms});
    for timeout in [100, 10_000] {
        with_health(health(timeout)).unwrap_or_else(|error| panic!("{timeout}: {error:?}"));
    }
    for timeout in [99, 10_001] {
        assert_eq!(
            rejection(with_health(health(timeout))).1,
            "provider health timeout must be 100..=10000 milliseconds"
        );
    }
    let mut defaulted = health(5_000);
    defaulted.as_object_mut().unwrap().remove("timeout_ms");
    defaulted["expected_status"] = json!("204");
    with_health(defaulted).expect("default timeout and an expected status");

    let mut reversed = health(5_000);
    reversed["expected_status"] = json!("299-200");
    assert_eq!(
        rejection(with_health(reversed)).1,
        "expected HTTP status range is reversed"
    );
    let mut ftp = health(5_000);
    ftp["url"] = json!("ftp://example.com/");
    assert_eq!(
        rejection(with_health(ftp)),
        (
            "$.providers.health_check".to_owned(),
            "health-check URL must be bounded HTTP(S) without credentials or a fragment".to_owned()
        )
    );
}

#[test]
fn rule_providers_hold_bounded_non_recursive_conditions() {
    let rejected = |change: fn(&mut Value)| {
        let mut profile = profile();
        change(&mut profile);
        rejection(parse(&profile))
    };
    let shape = |reason: &str| ("$.providers".to_owned(), reason.to_owned());
    assert_eq!(
        rejected(|profile| {
            let copy = profile["providers"]["rules"][0].clone();
            profile["providers"]["rules"]
                .as_array_mut()
                .unwrap()
                .push(copy);
        }),
        shape("rule provider names must be unique and bounded")
    );
    assert_eq!(
        rejected(|profile| profile["providers"]["rules"][0]["rules"] = json!([])),
        shape("rule providers require 1..=8192 total conditions")
    );
    assert_eq!(
        rejected(|profile| {
            profile["providers"]["rules"][0]["rules"] = json!([{"type":"rule_set","value":"lists"}])
        }),
        shape("rule-provider conditions cannot recursively include rule sets")
    );
    let (path, _) = rejected(|profile| {
        profile["providers"]["rules"][0]["rules"] = json!([{"type":"ip_cidr","value":"not-a-cidr"}])
    });
    assert!(path.starts_with("$.providers.rules"), "{path}");

    let condition = json!({"type":"domain","value":"example.com"});
    let mut at_limit = profile();
    at_limit["providers"]["rules"][0]["rules"] =
        json!(vec![condition.clone(); crate::MAX_PROVIDER_RULES]);
    parse(&at_limit).expect("8192 conditions");
    let mut over = at_limit.clone();
    over["providers"]["rules"].as_array_mut().unwrap().push(
        json!({"name":"more","source":{"interval_seconds":0},"format":"text",
            "behavior":"domain","rules":[condition]}),
    );
    assert_eq!(
        provider_rejection(&over),
        "rule providers require 1..=8192 total conditions"
    );
}

#[test]
fn group_bindings_name_groups_whose_members_they_reproduce() {
    let rejected = |change: fn(&mut Value)| {
        let mut profile = profile();
        change(&mut profile);
        provider_rejection(&profile)
    };
    let unique = "provider group bindings must be unique";
    assert_eq!(
        rejected(|profile| {
            let copy = profile["providers"]["groups"][0].clone();
            profile["providers"]["groups"]
                .as_array_mut()
                .unwrap()
                .push(copy);
        }),
        unique
    );
    assert_eq!(
        rejected(|profile| {
            profile["providers"]["groups"][0]["providers"] = json!(["subscription", "subscription"])
        }),
        unique
    );
    assert_eq!(
        rejected(|profile| profile["providers"]["groups"][0]["filter"] = json!({"include":"("})),
        "provider filter is not a supported bounded regular expression"
    );
    assert_eq!(
        rejected(|profile| profile["providers"]["groups"][0]["providers"] = json!(["other"])),
        "group references an undeclared proxy provider"
    );
    assert_eq!(
        rejected(|profile| profile["providers"]["groups"][0]["group"] = json!("hk-1")),
        "provider binding must name a group"
    );
    assert_eq!(
        rejected(|profile| profile["outbounds"][0]["outbounds"] = json!(["DIRECT", "jp-1", "hk-1"])),
        "materialized group membership differs from its provider bindings"
    );

    let mut filtered = profile();
    filtered["providers"]["groups"][0]["filter"] = json!({"exclude":"^JP"});
    filtered["outbounds"][0]["outbounds"] = json!(["DIRECT", "hk-1"]);
    parse(&filtered).expect("a filtered binding");
}

#[test]
fn group_members_keep_local_members_first_and_add_each_node_once() {
    let catalog: ProviderCatalog = serde_json::from_value(json!({
        "proxies":[
            {"name":"a","source":{"interval_seconds":0},
             "members":[{"tag":"hk-1","name":"HK 1"},{"tag":"jp-1","name":"JP 1"}]},
            {"name":"b","source":{"interval_seconds":0},
             "members":[{"tag":"hk-1","name":"HK 1"},{"tag":"sg-1","name":"SG 1"}]}]
    }))
    .unwrap();
    let group = |local: &[&str], filter: Value| -> ProviderGroup {
        serde_json::from_value(json!({"group":"Proxy","local_members":local,
            "providers":["a","b"],"filter":filter}))
        .unwrap()
    };
    assert_eq!(
        catalog
            .group_members(&group(&["DIRECT"], json!({})))
            .unwrap(),
        ["DIRECT", "hk-1", "jp-1", "sg-1"]
    );
    assert_eq!(
        catalog
            .group_members(&group(&["sg-1"], json!({"exclude":"^JP"})))
            .unwrap(),
        ["sg-1", "hk-1"]
    );
    assert!(
        catalog
            .group_members(&group(&[], json!({"include":"("})))
            .is_err()
    );
}

#[test]
fn sources_list_every_remote_provider_by_kind() {
    let catalog: ProviderCatalog = serde_json::from_value(json!({
        "proxies":[{"name":"nodes","source":{"interval_seconds":3600},"members":[{"tag":"hk-1","name":"HK"}]}],
        "rules":[{"name":"lists","source":{"interval_seconds":0},"format":"text","behavior":"domain",
                  "rules":[{"type":"domain","value":"example.com"}]}]
    }))
    .unwrap();
    assert!(catalog.sources().is_empty());
    let mut remote = catalog.clone();
    remote.proxies[0].source = ProviderSource {
        url: Some(SOURCE_URL.to_owned()),
        interval_seconds: 3600,
    };
    remote.rules[0].source.url = Some("https://lists.example.com/list.txt".to_owned());
    assert_eq!(
        remote.sources(),
        BTreeMap::from([
            ("proxy:nodes".to_owned(), SOURCE_URL.to_owned()),
            (
                "rule:lists".to_owned(),
                "https://lists.example.com/list.txt".to_owned()
            ),
        ])
    );
}
