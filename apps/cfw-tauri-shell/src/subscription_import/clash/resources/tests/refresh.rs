//! What a provider keeps across import and refresh: dialer-proxy chains stay
//! inside the provider, and a stored selector default stays only while it is
//! still a member.

use cfw_singbox_config::ValidatedSingBoxProfile;
use serde_json::{Value, json};

use super::*;

/// The Japan provider's nodes, the second dialing through the first.
const CHAINED: &str = "proxies:\n  - {name: entry, type: socks5, server: entry.example.com, port: 1080}\n  - {name: exit, type: socks5, server: exit.example.com, port: 1080, dialer-proxy: entry}\n";

fn json_of(profile: &ValidatedSingBoxProfile) -> Value {
    serde_json::from_str(profile.as_json()).expect("profile JSON")
}

fn member_tag(profile: &ValidatedSingBoxProfile, name: &str) -> String {
    profile.providers().expect("catalog").proxies[0]
        .members
        .iter()
        .find(|member| member.name == name)
        .expect("provider member")
        .tag
        .clone()
}

#[test]
fn a_provider_chain_resolves_inside_the_provider_and_follows_each_refresh() {
    let chained = materialized_with(ROOT, CHAINED);
    let chain = json!({
        member_tag(&chained.profile, "exit"): member_tag(&chained.profile, "entry")
    });
    assert_eq!(json_of(&chained.profile)["detours"], chain);

    // A refresh adds the chain to a profile that had none, keeps it on an
    // unchanged payload, and drops it when the payload no longer dials.
    let added = refreshed_japan(&materialized().profile, CHAINED).expect("chain added");
    assert_eq!(json_of(&added.profile)["detours"], chain);
    let kept = refreshed_japan(&added.profile, CHAINED).expect("chain kept");
    assert_eq!(json_of(&kept.profile)["detours"], chain);
    let dropped = refreshed_japan(&kept.profile, PAYLOAD).expect("chain dropped");
    assert!(json_of(&dropped.profile).get("detours").is_none());
}

#[test]
fn a_chain_follows_a_provider_node_whose_tag_was_already_taken() {
    // A local node named exactly like the provider node's derived tag pushes
    // that node to a suffixed tag; its chain must move with it.
    let taken = payload::provider_tag("Japan", "exit");
    let root = ROOT.replacen(
        "proxies:\n",
        &format!(
            "proxies:\n  - {{name: '{taken}', type: socks5, server: taken.example.com, port: 1080}}\n"
        ),
        1,
    );
    let imported = materialized_with(&root, CHAINED);
    let exit = member_tag(&imported.profile, "exit");
    assert_eq!(exit, format!("{taken}-2"));
    assert_eq!(
        json_of(&imported.profile)["detours"],
        json!({ exit: member_tag(&imported.profile, "entry") })
    );
}

#[test]
fn a_refresh_keeps_a_stored_default_only_while_it_is_a_member() {
    let old = materialized();
    let member = member_tag(&old.profile, "日本");
    for (default, kept) in [(member.as_str(), false), ("local", true)] {
        let mut stored = json_of(&old.profile);
        stored["outbounds"]
            .as_array_mut()
            .expect("outbounds")
            .iter_mut()
            .find(|outbound| outbound["tag"] == "PROXY")
            .expect("PROXY group")["default"] = json!(default);
        let profile = ValidatedSingBoxProfile::parse(&stored.to_string())
            .and_then(|profile| profile.with_provider_sources(old.profile.provider_sources()))
            .expect("a stored default");
        let refreshed =
            refreshed_japan(&profile, &PAYLOAD.replace("日本", "新节点")).expect("refresh");
        let refreshed = json_of(&refreshed.profile);
        let group = refreshed["outbounds"]
            .as_array()
            .expect("outbounds")
            .iter()
            .find(|outbound| outbound["tag"] == "PROXY")
            .expect("PROXY group");
        assert_eq!(group.get("default").is_some(), kept, "{default}");
    }
}
