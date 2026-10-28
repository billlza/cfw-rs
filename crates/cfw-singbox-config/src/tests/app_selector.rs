//! A profile that declares no selector group runs behind the app's own
//! selector. The node chosen in that selector must be kept and applied like a
//! choice made in a saved group.

use serde_json::{Value, json};

use crate::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const APP_SELECTOR: &str = "cfw-proxy-selector";

fn nodes_only() -> Value {
    json!({
        "outbounds": [
            {"type":"socks5","tag":"first","server":"first.example.com","server_port":1080},
            {"type":"socks5","tag":"second","server":"second.example.com","server_port":1080},
            {"type":"direct","tag":"DIRECT"}
        ]
    })
}

fn parse(value: &Value) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&value.to_string()).expect("valid profile")
}

fn runtime(profile: &ValidatedSingBoxProfile, mode: ProjectionMode) -> Value {
    let projected = profile
        .project(PROFILE_ID, mode, &EngineSettings::default())
        .expect("projection");
    serde_json::from_str(projected.as_json()).expect("runtime json")
}

fn outbound(runtime: &Value, tag: &str) -> Value {
    runtime["outbounds"]
        .as_array()
        .expect("outbounds")
        .iter()
        .find(|outbound| outbound["tag"] == tag)
        .cloned()
        .unwrap_or_else(|| panic!("the projection declares {tag}"))
}

fn app_selector(default: &str) -> Value {
    json!({"type":"selector","tag":APP_SELECTOR,"outbounds":["first","second"],
        "default":default,"interrupt_exist_connections":false})
}

#[test]
fn a_profile_without_a_selector_group_keeps_the_node_chosen_in_the_app_selector() {
    let profile = parse(&nodes_only());
    assert!(profile.proxy_selections().is_empty());
    let chosen = profile
        .with_selected_outbound(APP_SELECTOR, "second")
        .expect("the app selector accepts one of its nodes");
    assert_eq!(chosen.proxy_selections()[APP_SELECTOR], "second");
    assert_eq!(chosen.as_json(), profile.as_json());
    assert_eq!(chosen.digest(), profile.digest());
    assert_eq!(
        chosen.credential_references(),
        profile.credential_references()
    );
    assert!(chosen.routes_through_remote());
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let plain = runtime(&profile, mode);
        assert_eq!(plain["route"]["final"], APP_SELECTOR, "{mode:?}");
        assert_eq!(
            outbound(&plain, APP_SELECTOR),
            app_selector("first"),
            "{mode:?}"
        );
        let with_choice = runtime(&chosen, mode);
        assert_eq!(with_choice["route"]["final"], APP_SELECTOR, "{mode:?}");
        assert_eq!(
            outbound(&with_choice, APP_SELECTOR),
            app_selector("second"),
            "{mode:?}"
        );
    }
    let settings = EngineSettings::default();
    let original = profile
        .project(PROFILE_ID, ProjectionMode::SystemProxy, &settings)
        .expect("original");
    let changed = chosen
        .project(PROFILE_ID, ProjectionMode::SystemProxy, &settings)
        .expect("chosen");
    assert_eq!(
        changed.credential_audience(),
        original.credential_audience()
    );
    assert_ne!(changed.digest(), original.digest());
}

#[test]
fn a_node_choice_in_the_app_selector_must_name_one_of_its_remote_nodes() {
    let profile = parse(&nodes_only());
    for (group, node) in [
        (APP_SELECTOR, "DIRECT"),
        (APP_SELECTOR, "absent"),
        ("first", "second"),
        ("absent", "second"),
    ] {
        assert!(
            profile.with_selected_outbound(group, node).is_err(),
            "{group} → {node} must be refused"
        );
    }
    let mut explicit_final = nodes_only();
    explicit_final["route"] = json!({"final": "first"});
    let error = parse(&explicit_final)
        .with_selected_outbound(APP_SELECTOR, "second")
        .expect_err("a profile with an explicit final route has no app selector");
    assert!(error.to_string().contains("selector group"), "{error}");
    let mut single_node = nodes_only();
    single_node["outbounds"].as_array_mut().unwrap().remove(1);
    assert!(
        parse(&single_node)
            .with_selected_outbound(APP_SELECTOR, "first")
            .is_err(),
        "one remote node injects no selector"
    );
}

#[test]
fn the_app_selector_choice_survives_an_update_that_keeps_the_node_and_is_reset_when_it_is_gone() {
    let previous = parse(&nodes_only())
        .with_selected_outbound(APP_SELECTOR, "second")
        .expect("choice");
    let (kept, reset) = parse(&nodes_only())
        .inherit_proxy_selections(&previous)
        .expect("inherit");
    assert_eq!(kept.proxy_selections()[APP_SELECTOR], "second");
    assert!(reset.is_empty());

    let mut renamed = nodes_only();
    renamed["outbounds"][1]["tag"] = json!("third");
    let (without_node, reset) = parse(&renamed)
        .inherit_proxy_selections(&previous)
        .expect("inherit");
    assert!(without_node.proxy_selections().is_empty());
    assert_eq!(reset, vec![APP_SELECTOR.to_owned()]);

    let mut explicit_final = nodes_only();
    explicit_final["route"] = json!({"final": "first"});
    let (without_selector, reset) = parse(&explicit_final)
        .inherit_proxy_selections(&previous)
        .expect("inherit");
    assert!(without_selector.proxy_selections().is_empty());
    assert_eq!(reset, vec![APP_SELECTOR.to_owned()]);
}

#[test]
fn a_saved_group_that_uses_the_app_selector_tag_keeps_its_own_rule() {
    let document = json!({
        "outbounds": [
            {"type":"socks5","tag":"first","server":"first.example.com","server_port":1080},
            {"type":"socks5","tag":"second","server":"second.example.com","server_port":1080},
            {"type":"selector","tag":APP_SELECTOR,"outbounds":["first","second"]}
        ]
    });
    let profile = parse(&document);
    let injected = "cfw-proxy-selector-2";
    let saved_choice = profile
        .with_selected_outbound(APP_SELECTOR, "second")
        .expect("the saved group accepts its member");
    assert_eq!(saved_choice.proxy_selections()[APP_SELECTOR], "second");
    let saved_runtime = runtime(&saved_choice, ProjectionMode::SystemProxy);
    assert_eq!(saved_runtime["route"]["final"], injected);
    assert_eq!(outbound(&saved_runtime, APP_SELECTOR)["default"], "second");
    assert_eq!(outbound(&saved_runtime, injected)["default"], "first");
    let injected_choice = saved_choice
        .with_selected_outbound(injected, "second")
        .expect("the injected selector accepts its node");
    assert_eq!(injected_choice.proxy_selections()[injected], "second");
    assert_eq!(injected_choice.as_json(), profile.as_json());
    let injected_runtime = runtime(&injected_choice, ProjectionMode::SystemProxy);
    assert_eq!(
        outbound(&injected_runtime, injected),
        json!({"type":"selector","tag":injected,"outbounds":["first","second"],
            "default":"second","interrupt_exist_connections":false})
    );
}
