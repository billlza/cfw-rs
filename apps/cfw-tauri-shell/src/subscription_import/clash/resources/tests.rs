use super::*;
use crate::subscription_import::import_subscription_document;

#[test]
fn rule_payload_preserves_implicit_null_and_explicit_empty_text() {
    let payload = load_single_document("-\n- ~\n- ''\n- !!str\n").expect("YAML sequence");
    let rules = import_rule_payload(payload, ProviderRuleBehavior::IpCidr)
        .expect("raw provider text before profile validation");
    assert_eq!(
        rules
            .iter()
            .map(|rule| rule.value.as_str())
            .collect::<Vec<_>>(),
        ["~", "~", "", ""]
    );
}

const ROOT: &str = r#"
proxies:
  - {name: local, type: socks5, server: local.example.com, port: 1080, username: local-user, password: local-secret}
proxy-providers:
  Japan:
    type: http
    url: https://subscription.example.com/nodes?token=private-source-token
    interval: 3600
    health-check: {enable: true, url: http://connectivity.example.com/generate_204, interval: 60, timeout: 1200, expected-status: 204, lazy: false}
rule-providers:
  domains: {type: http, url: https://rules.example.com/domain.txt, interval: 7200, behavior: domain, format: text}
proxy-groups:
  - {name: PROXY, type: select, proxies: [local], use: [Japan]}
  - {name: BALANCE, type: load-balance, use: [Japan], strategy: sticky-sessions, interval: 60, lazy: false, url: https://connectivity.example.com}
rules:
  - RULE-SET,domains,PROXY
  - MATCH,BALANCE
"#;

const PAYLOAD: &str = "proxies:\n  - {name: 日本, type: socks5, server: node.example.com, port: 1080, username: 000123, password: True}\n";

fn materialized() -> crate::subscription_import::ImportedSubscription {
    let requests = requests(ROOT).expect("provider requests");
    let resources = requests
        .into_iter()
        .map(|request| {
            let payload = if request.kind == ProviderKind::Proxy {
                PAYLOAD
            } else {
                "# retained order\n+.example.net\nexact.example.org\n"
            };
            (request, payload.into())
        })
        .collect::<Vec<_>>();
    import_subscription_document(&materialize(ROOT, &resources).expect("materialize"))
        .expect("import providers")
}

#[test]
fn provider_materialization_preserves_secrets_names_and_source_privacy() {
    let imported = materialized();
    let catalog = imported.profile.providers().expect("catalog");
    assert_eq!(catalog.proxies[0].members[0].name, "日本");
    let members = &catalog.groups[0];
    assert_eq!(members.local_members, ["local"]);
    assert_eq!(catalog.group_members(members).unwrap().len(), 2);
    assert!(
        imported
            .credentials
            .iter()
            .any(|credential| credential.secret == "000123")
    );
    assert!(
        imported
            .credentials
            .iter()
            .any(|credential| credential.secret == "True")
    );
    assert!(!imported.profile.as_json().contains("private-source-token"));
    assert!(!format!("{:?}", imported.profile).contains("private-source-token"));
    assert_eq!(imported.profile.provider_sources().len(), 2);
    assert_eq!(
        catalog.proxies[0].health_check.as_ref().unwrap().timeout_ms,
        1200
    );
    assert_eq!(
        catalog.proxies[0]
            .health_check
            .as_ref()
            .unwrap()
            .expected_status
            .as_deref(),
        Some("204")
    );
    assert_eq!(catalog.rules[0].rules[0].kind, RuleKind::DomainSuffix);
}

#[test]
fn updating_one_provider_preserves_other_nodes_and_handles_removed_selection() {
    let old = materialized();
    let tag = old.profile.providers().unwrap().proxies[0].members[0]
        .tag
        .clone();
    let old_profile = old.profile.with_selected_outbound("PROXY", &tag).unwrap();
    let request = stored_requests(&old_profile, ProviderKind::Proxy, Some("Japan"))
        .unwrap()
        .remove(0);
    let payload = PAYLOAD
        .replace("日本", "新节点")
        .replace("node.example.com", "new.example.com");
    let updated = replacement(&old_profile, &[(request.clone(), payload.clone())], true).unwrap();
    let (updated_profile, reset) = updated
        .profile
        .inherit_proxy_selections(&old_profile)
        .unwrap();
    assert_eq!(reset, ["PROXY"]);
    assert_eq!(
        updated_profile.provider_sources(),
        old_profile.provider_sources()
    );
    let refs = updated_profile
        .retained_credential_references(&old_profile)
        .unwrap();
    assert_eq!(
        refs.len(),
        2,
        "both unchanged local SOCKS credentials survive"
    );
    assert_eq!(
        updated_profile.providers().unwrap().rules,
        old_profile.providers().unwrap().rules
    );
    let old_local: serde_json::Value = serde_json::from_str(old_profile.as_json()).unwrap();
    let new_local: serde_json::Value = serde_json::from_str(updated_profile.as_json()).unwrap();
    assert_eq!(old_local["outbounds"][0], new_local["outbounds"][0]);

    let invalid = payload.replace("socks5", "unsupported-protocol");
    assert!(replacement(&old_profile, &[(request, invalid)], false).is_err());
    assert_eq!(old_profile.proxy_selections()["PROXY"], tag);
}

#[test]
fn rule_only_update_can_rebind_every_unchanged_credential() {
    let old = materialized();
    let request = stored_requests(&old.profile, ProviderKind::Rule, Some("domains"))
        .unwrap()
        .remove(0);
    let updated = replacement(
        &old.profile,
        &[(request, "+.new.example.org\n".into())],
        false,
    )
    .unwrap();
    assert!(updated.credentials.is_empty());
    assert_ne!(old.profile.digest(), updated.profile.digest());
    assert_eq!(
        updated
            .profile
            .retained_credential_references(&old.profile)
            .unwrap()
            .len(),
        old.profile.credential_references().len()
    );
}

#[test]
fn provider_updates_reject_source_drift_and_invalid_status_bounds() {
    let old = materialized();
    let mut request = stored_requests(&old.profile, ProviderKind::Proxy, Some("Japan"))
        .unwrap()
        .remove(0);
    request.url = "https://other.example.com/nodes".into();
    assert!(replacement(&old.profile, &[(request, PAYLOAD.into())], false).is_err());
    for policy in ["204", "200-299/304", ""] {
        cfw_singbox_config::validate_expected_status(policy).unwrap();
    }
    for policy in ["200/", "600", "299-200", "20", "200,204", "+20"] {
        assert!(cfw_singbox_config::validate_expected_status(policy).is_err());
    }
}
