//! The edges of provider declarations, payloads, materialization and stored
//! refresh requests: what the import refuses, skips or leaves out.

use super::*;

fn clash_with(providers: &str) -> String {
    format!(
        "proxies:\n  - {{name: local, type: socks5, server: local.example.com, port: 1080}}\n{providers}"
    )
}

fn proxy_request() -> ProviderRequest {
    requests(ROOT)
        .expect("requests")
        .into_iter()
        .find(|request| request.kind == ProviderKind::Proxy)
        .expect("the Japan provider")
}

#[test]
fn requests_skip_other_documents_and_keep_source_urls_out_of_debug_output() {
    assert!(
        requests("vmess://not-a-clash-document")
            .expect("not Clash")
            .is_empty()
    );
    // A Clash root key inside a literal block: the root is a scalar, which
    // the import itself refuses, so there is nothing to download.
    assert!(
        requests("|\nproxy-providers: {}\n")
            .expect("a scalar root")
            .is_empty()
    );
    let rendered = format!("{:?}", proxy_request());
    assert!(rendered.contains("Japan"), "{rendered}");
    assert!(!rendered.contains("private-source-token"), "{rendered}");
    assert!(
        requests(&clash_with(
            "proxy-providers:\n  Inline: {type: inline, payload: []}\n"
        ))
        .expect("an inline provider")
        .is_empty()
    );
}

#[test]
fn a_declaration_is_a_bounded_mapping_with_an_https_or_inline_source() {
    for (providers, message) in [
        (
            "proxy-providers: none\n",
            "proxy-providers must be a mapping",
        ),
        (
            "proxy-providers:\n  Japan: none\n",
            "proxy-providers entry must be a mapping",
        ),
        (
            "proxy-providers:\n  Japan: {type: http, url: 'https://p.example.com/x', proxy: PROXY}\n",
            "provider download via a named proxy requires the profile resource transport",
        ),
        (
            "proxy-providers:\n  Japan: {type: http, url: 'http://p.example.com/x'}\n",
            "provider downloads require HTTPS without userinfo or a fragment",
        ),
        (
            "proxy-providers:\n  Japan: {type: http, url: 'https://p.example.com/x', interval: 30}\n",
            "provider interval must be 60..=604800 seconds",
        ),
        (
            "proxy-providers:\n  Japan: {type: file, path: ./nodes.yaml}\n",
            "provider requires type http with a URL, or type inline with a payload",
        ),
        (
            "rule-providers:\n  r: {type: http, url: 'https://r.example.com/x', behavior: domain, format: mrs}\n",
            "rule provider format must be yaml or text",
        ),
    ] {
        let error = requests(&clash_with(providers)).expect_err(message);
        assert!(error.contains(message), "{providers:?}: {error}");
    }
    let many = (0..=32)
        .map(|index| format!("  P{index}: {{type: http, url: 'https://p.example.com/{index}'}}\n"))
        .collect::<String>();
    assert_eq!(
        requests(&clash_with(&format!("proxy-providers:\n{many}"))).map(|list| list.len()),
        Err("provider count exceeds 32".into())
    );
}

#[test]
fn materialization_needs_the_providers_it_downloaded() {
    assert_eq!(materialize(ROOT, &[]).as_deref(), Ok(ROOT));
    let downloaded = [(proxy_request(), PAYLOAD.to_owned())];
    assert_eq!(
        materialize("- not\n- a mapping\n", &downloaded),
        Err("provider root must be a mapping".into())
    );
    assert_eq!(
        materialize(&clash_with(""), &downloaded),
        Err("provider collection changed while downloading".into())
    );
    assert_eq!(
        materialize(&ROOT.replace("  Japan:\n", "  Korea:\n"), &downloaded),
        Err("provider changed while downloading".into())
    );
}

#[test]
fn an_imported_provider_needs_its_payload_in_the_declared_shape() {
    for (providers, message) in [
        ("rule-providers: none\n", "rule-providers must be a mapping"),
        (
            "proxy-providers:\n  Inline: {type: inline, payload: none}\n",
            "proxy provider payload must be a sequence",
        ),
        (
            "proxy-providers:\n  Inline:\n    type: inline\n    payload:\n      - {name: A, type: socks5, server: a.example.com, port: 1080}\n      - {name: A, type: socks5, server: b.example.com, port: 1080}\n",
            "provider node names must be unique",
        ),
        (
            "rule-providers:\n  r: {type: inline, behavior: geoip, payload: []}\n",
            "rule provider behavior must be domain, ipcidr or classical",
        ),
    ] {
        let error = import_subscription_document(&clash_with(providers)).expect_err(message);
        assert!(error.contains(message), "{providers:?}: {error}");
    }
}

#[test]
fn a_filtered_out_member_is_skipped() {
    let imported = import_subscription_document(&clash_with(
        "proxy-providers:\n  Inline:\n    type: inline\n    exclude-filter: skip\n    payload:\n      - {name: keep, type: socks5, server: a.example.com, port: 1080}\n      - {name: skip, type: socks5, server: b.example.com, port: 1080}\n",
    ))
    .expect("inline provider");
    let catalog = imported.profile.providers().expect("providers");
    assert_eq!(
        catalog.proxies[0]
            .members
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>(),
        ["keep"]
    );
}

#[test]
fn rule_payloads_keep_their_behavior_and_refuse_what_it_cannot_express() {
    let sequence = |text: &str| load_single_document(text).expect("YAML");
    let ip = import_rule_payload(sequence("- 10.0.0.0/8\n"), ProviderRuleBehavior::IpCidr)
        .expect("IP rules");
    assert_eq!(ip[0].kind, RuleKind::IpCidr);
    let wildcard = import_rule_payload(
        sequence("- '*.ads.example.com'\n"),
        ProviderRuleBehavior::Domain,
    )
    .expect("a whole-label wildcard");
    assert_eq!(wildcard[0].kind, RuleKind::DomainRegex);
    let partial = import_rule_payload(
        sequence("- 'ads_*.example.com'\n"),
        ProviderRuleBehavior::Domain,
    )
    .expect_err("a partial-label wildcard");
    assert!(
        partial.contains("expected bounded domain labels"),
        "{partial}"
    );
    for (payload, behavior, message) in [
        (
            "- example.com\n",
            ProviderRuleBehavior::Classical,
            "classical provider rule requires a type and value",
        ),
        (
            "none\n",
            ProviderRuleBehavior::Domain,
            "rule provider payload must be a sequence",
        ),
        (
            "- [nested]\n",
            ProviderRuleBehavior::Domain,
            "provider rule must be a string",
        ),
        (
            "- DOMAIN,example.com,PROXY\n",
            ProviderRuleBehavior::Classical,
            "classical provider rules cannot include an outbound target",
        ),
        (
            "- MATCH,x\n",
            ProviderRuleBehavior::Classical,
            "unsupported classical provider rule",
        ),
    ] {
        assert_eq!(
            import_rule_payload(sequence(payload), behavior).map(|rules| rules.len()),
            Err(message.into()),
            "{payload:?}"
        );
    }
    let oversized = (0..=cfw_singbox_config::MAX_PROVIDER_RULES)
        .map(|index| format!("- 10.{}.{}.0/24\n", index / 256 % 256, index % 256))
        .collect::<String>();
    assert_eq!(
        import_rule_payload(sequence(&oversized), ProviderRuleBehavior::IpCidr)
            .map(|rules| rules.len()),
        Err("rule provider is too large".into())
    );
}

#[test]
fn a_downloaded_response_must_be_a_mapping_with_the_expected_list() {
    assert_eq!(
        decode_payload(ProviderKind::Proxy, ProviderRuleFormat::Yaml, "- a\n").map(|_| ()),
        Err("provider response must be a mapping".into())
    );
    assert_eq!(
        decode_payload(ProviderKind::Rule, ProviderRuleFormat::Yaml, "rules: []\n").map(|_| ()),
        Err("provider response is missing payload".into())
    );
    assert!(
        decode_payload(
            ProviderKind::Rule,
            ProviderRuleFormat::Yaml,
            "payload: []\n"
        )
        .is_ok()
    );
}

#[test]
fn a_refresh_needs_the_same_rule_source_and_a_stored_remote_provider() {
    let old = materialized();
    let mut rule = stored_requests(&old.profile, ProviderKind::Rule, Some("domains"))
        .expect("rule request")
        .remove(0);
    rule.format = ProviderRuleFormat::Yaml;
    assert_eq!(
        replacement(&old.profile, &[(rule, "payload: []\n".into())], false).map(|_| ()),
        Err("rule provider source changed while downloading".into())
    );
    assert_eq!(
        stored_requests(&old.profile, ProviderKind::Proxy, Some("Korea")).map(|list| list.len()),
        Err("provider is not in the selected profile".into())
    );

    let inline = import_subscription_document(&clash_with(
        "proxy-providers:\n  Inline:\n    type: inline\n    payload:\n      - {name: keep, type: socks5, server: a.example.com, port: 1080}\n",
    ))
    .expect("inline provider");
    assert_eq!(
        stored_requests(&inline.profile, ProviderKind::Proxy, Some("Inline"))
            .map(|list| list.len()),
        Err("provider has no remote source URL; edit its materialized content in Profiles".into())
    );
    assert_eq!(
        stored_requests(&inline.profile, ProviderKind::Proxy, None).map(|list| list.len()),
        Ok(0)
    );
}

#[test]
fn an_imported_provider_collection_is_a_mapping_within_the_outbound_capacity() {
    assert_eq!(
        import_subscription_document(&clash_with("proxy-providers: none\n")).map(|_| ()),
        Err("proxy-providers must be a mapping".into())
    );
    let nodes = |count: usize| {
        let payload = (0..count)
            .map(|index| {
                format!(
                    "      - {{name: N{index}, type: socks5, server: n.example.com, port: 1080}}\n"
                )
            })
            .collect::<String>();
        clash_with(&format!(
            "proxy-providers:\n  Inline:\n    type: inline\n    payload:\n{payload}"
        ))
    };
    // With the one local node, the last provider node would be the outbound
    // past the capacity.
    assert_eq!(
        import_subscription_document(&nodes(cfw_singbox_config::MAX_OUTBOUNDS)).map(|_| ()),
        Err("provider nodes exceed the supported outbound capacity".into())
    );
    // One node fewer fits the collector; the profile validator then refuses
    // more nodes than a profile holds.
    assert_eq!(
        import_subscription_document(&nodes(cfw_singbox_config::MAX_OUTBOUNDS - 1)).map(|_| ()),
        Err("unsupported credential-free policy shape at $.outbounds: profile exceeds the node, group, or membership capacity".into())
    );
}

#[test]
fn a_disabled_health_check_is_not_stored() {
    let imported = import_subscription_document(&clash_with(
        "proxy-providers:\n  Inline:\n    type: inline\n    health-check: {enable: false, url: 'https://example.com/probe', interval: 600}\n    payload:\n      - {name: keep, type: socks5, server: a.example.com, port: 1080}\n",
    ))
    .expect("inline provider");
    assert!(
        imported.profile.providers().expect("catalog").proxies[0]
            .health_check
            .is_none()
    );
}
