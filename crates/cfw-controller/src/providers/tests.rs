use super::*;

#[derive(Debug, Deserialize)]
struct PinnedProxyProvidersResponse {
    providers: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct PinnedRuleProvidersResponse {
    providers: Vec<String>,
}

#[test]
fn pinned_provider_golden_responses_are_stub_shapes() {
    // Exact bodies emitted by experimental/clashapi/provider.go and
    // ruleprovider.go, captured from sing-box 1.13.15; both handlers are
    // byte-identical in the pinned 1.14.4 source.
    let proxy: PinnedProxyProvidersResponse = serde_json::from_str(include_str!(
        "../../tests/fixtures/sing-box-1.13.15-proxy-providers.json"
    ))
    .expect("pinned proxy-provider response");
    let rules: PinnedRuleProvidersResponse = serde_json::from_str(include_str!(
        "../../tests/fixtures/sing-box-1.13.15-rule-providers.json"
    ))
    .expect("pinned rule-provider response");

    assert!(proxy.providers.is_empty());
    assert!(rules.providers.is_empty());
}

#[test]
fn batch_succeeds_only_when_every_requested_provider_succeeded() {
    let batch = |requested, succeeded: &[&str], failed: &[&str]| ProviderBatchResult {
        action: "update".into(),
        requested,
        succeeded: succeeded.iter().map(|name| (*name).to_owned()).collect(),
        failed: failed
            .iter()
            .map(|name| ProviderBatchFailure {
                name: (*name).to_owned(),
                error: "refused".into(),
            })
            .collect(),
    };
    assert!(batch(2, &["a", "b"], &[]).is_complete_success());
    assert!(batch(0, &[], &[]).is_complete_success());
    assert!(!batch(2, &["a"], &["b"]).is_complete_success());
    assert!(!batch(2, &["a"], &[]).is_complete_success());
    assert!(!batch(1, &["a"], &["b"]).is_complete_success());
}
