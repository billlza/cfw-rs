use cfw_singbox_config::ValidatedSingBoxProfile;

fn profile(members: &[&str]) -> ValidatedSingBoxProfile {
    let nodes: Vec<_> = members
        .iter()
        .map(|name| serde_json::json!({"type":"direct","tag":name}))
        .collect();
    let mut outbounds = nodes;
    outbounds.push(serde_json::json!({"type":"selector","tag":"PROXY","outbounds":members,"default":members[0]}));
    ValidatedSingBoxProfile::parse(
        &serde_json::json!({"outbounds":outbounds,"route":{"final":"PROXY"}}).to_string(),
    )
    .unwrap()
}

#[test]
fn refreshed_profile_keeps_an_existing_manual_choice_without_changing_credential_audience() {
    let before = profile(&["A", "B"])
        .with_selected_outbound("PROXY", "B")
        .unwrap();
    let fresh = profile(&["A", "B", "C"]);
    let (updated, removed) = fresh.inherit_proxy_selections(&before).unwrap();
    assert!(removed.is_empty());
    assert_eq!(
        updated.proxy_selections().get("PROXY").map(String::as_str),
        Some("B")
    );
    assert_eq!(fresh.digest(), updated.digest());
    assert_eq!(fresh.as_json(), updated.as_json());
}

#[test]
fn a_removed_manual_choice_reports_the_group_and_retains_the_new_default() {
    let before = profile(&["A", "B"])
        .with_selected_outbound("PROXY", "B")
        .unwrap();
    let fresh = profile(&["A", "C"]);
    let (updated, removed) = fresh.inherit_proxy_selections(&before).unwrap();
    assert_eq!(removed, ["PROXY"]);
    assert!(updated.proxy_selections().is_empty());
    assert_eq!(updated, fresh);
}
