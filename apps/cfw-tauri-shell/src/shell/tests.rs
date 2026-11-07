use std::collections::BTreeSet;

use cfw_controller::{ProxyGroup, ProxyNode};

use super::{
    app_menu::{APP_MENU_ABOUT_ID, APP_MENU_CHECK_UPDATE_ID, AppMenuAction, app_menu_action},
    tray::{
        MAX_TRAY_GROUP_OPTIONS, MAX_TRAY_GROUPS, MAX_TRAY_LABEL_CHARS, TRAY_ABOUT_ID, TrayAction,
        TrayProxyGroup, TrayProxySelection, tray_action,
    },
    *,
};

fn group(name: &str, now: Option<&str>, options: &[&str]) -> ProxyGroup {
    ProxyGroup {
        name: name.to_owned(),
        kind: "Selector".into(),
        now: now.map(ToOwned::to_owned),
        options: options.iter().map(|option| (*option).to_owned()).collect(),
        history: Vec::new(),
    }
}

fn snapshot(groups: Vec<ProxyGroup>) -> ProxiesSnapshot {
    ProxiesSnapshot {
        groups,
        proxies: Vec::<ProxyNode>::new(),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RendererPageContract {
    id: String,
    title: String,
    summary: String,
}

fn renderer_page_ids() -> BTreeSet<String> {
    let pages: Vec<RendererPageContract> =
        serde_json::from_str(include_str!("../../ui/src/pages.json"))
            .expect("renderer page contract must be strict JSON");
    assert!(
        !pages.is_empty(),
        "renderer page contract must not be empty"
    );
    for page in &pages {
        assert!(
            page.id.split('-').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            }),
            "renderer page id must be canonical lowercase kebab-case"
        );
        assert!(
            !page.title.trim().is_empty() && !page.summary.trim().is_empty(),
            "renderer page title and summary must not be empty"
        );
    }
    let unique = pages
        .iter()
        .map(|page| page.id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        unique.len(),
        pages.len(),
        "renderer page ids must be unique"
    );
    unique
}

#[test]
fn every_native_page_is_part_of_the_renderer_page_contract() {
    let renderer_pages = renderer_page_ids();

    for page in MainPage::ALL {
        assert!(
            renderer_pages.contains(page.id()),
            "native page '{}' is absent from renderer PAGES",
            page.id()
        );
    }
}

#[test]
fn about_and_update_actions_open_the_feedback_page() {
    assert_eq!(
        app_menu_action(APP_MENU_ABOUT_ID),
        Some(AppMenuAction::OpenPage(MainPage::Feedback))
    );
    assert_eq!(
        app_menu_action(APP_MENU_CHECK_UPDATE_ID),
        Some(AppMenuAction::CheckForUpdates(MainPage::Feedback))
    );
    assert_eq!(
        tray_action(TRAY_ABOUT_ID),
        TrayAction::OpenPage(MainPage::Feedback)
    );
}

#[test]
fn tray_groups_are_bounded_and_sanitised() {
    let long = "n".repeat(MAX_TRAY_LABEL_CHARS + 1);
    let groups = tray_proxy_groups(snapshot(vec![
        group("Proxy", Some("HK"), &["HK", "JP"]),
        group("Control\u{7}", None, &["HK"]),
        group(&long, None, &["HK"]),
        group("Empty", None, &[]),
        group("Filtered", None, &["ok", "bad\nname"]),
    ]));

    assert_eq!(
        groups,
        vec![
            TrayProxyGroup {
                name: "Proxy".into(),
                now: Some("HK".into()),
                options: vec!["HK".into(), "JP".into()],
                selectable: true,
            },
            TrayProxyGroup {
                name: "Filtered".into(),
                now: None,
                options: vec!["ok".into()],
                selectable: true,
            },
        ]
    );

    let oversized = tray_proxy_groups(snapshot(
        (0..MAX_TRAY_GROUPS + 5)
            .map(|index| group(&format!("Group {index}"), None, &["HK"]))
            .collect(),
    ));
    assert_eq!(oversized.len(), MAX_TRAY_GROUPS);

    let wide = tray_proxy_groups(snapshot(vec![ProxyGroup {
        options: (0..MAX_TRAY_GROUP_OPTIONS + 5)
            .map(|index| format!("node-{index}"))
            .collect(),
        ..group("Wide", None, &[])
    }]));
    assert_eq!(wide[0].options.len(), MAX_TRAY_GROUP_OPTIONS);
}

#[test]
fn tray_selection_is_resolved_by_generated_id_only() {
    let state = TrayMenuState::default();
    assert!(state.resolve("cfw-proxy-0").is_none());
    state
        .replace(BTreeMap::from([(
            "cfw-proxy-0".to_owned(),
            TrayProxySelection {
                group: "Proxy".into(),
                proxy: "HK".into(),
            },
        )]))
        .expect("store selections");

    assert_eq!(
        state.resolve("cfw-proxy-0"),
        Some(TrayProxySelection {
            group: "Proxy".into(),
            proxy: "HK".into(),
        })
    );
    // A renderer-chosen or stale id resolves to nothing, so no proxy change
    // can be triggered by an id the menu did not generate.
    assert!(state.resolve("cfw-proxy-1").is_none());
    assert!(state.resolve("dashboard").is_none());
    state.replace(BTreeMap::new()).expect("clear selections");
    assert!(state.resolve("cfw-proxy-0").is_none());
}

#[test]
fn stale_selection_marker_is_dropped_when_it_is_not_an_option() {
    let groups = tray_proxy_groups(snapshot(vec![group("Proxy", Some("Gone"), &["HK"])]));
    assert_eq!(groups[0].now, None);
}

#[test]
fn tray_network_actions_keep_explicit_intent_and_automatic_groups_are_read_only() {
    for (id, expected) in [
        ("core-start", TrayEngineAction::StartCore),
        ("core-stop", TrayEngineAction::StopCore),
        ("proxy-enable", TrayEngineAction::SystemProxy(true)),
        ("proxy-disable", TrayEngineAction::SystemProxy(false)),
        ("tun-enable", TrayEngineAction::Tunnel(true)),
        ("tun-disable", TrayEngineAction::Tunnel(false)),
        ("route-rule", TrayEngineAction::RouteMode("rule")),
        ("route-global", TrayEngineAction::RouteMode("global")),
        ("route-direct", TrayEngineAction::RouteMode("direct")),
    ] {
        assert_eq!(tray_action(id), TrayAction::Engine(expected));
    }
    for kind in ["URLTest", "Fallback", "LoadBalance"] {
        let mut automatic = group("Auto", Some("HK"), &["HK", "JP"]);
        automatic.kind = kind.into();
        let groups = tray_proxy_groups(snapshot(vec![automatic]));
        assert!(!groups[0].selectable);
        assert_eq!(groups[0].now.as_deref(), Some("HK"));
    }
}

#[test]
fn tray_never_marks_failed_or_pending_intent_as_connected() {
    use cfw_engine_api::{EngineCommandContext, EngineOwner, RuntimeIdentity};
    let runtime = RuntimeIdentity {
        owner: EngineOwner::ProxyAgent,
        context: EngineCommandContext {
            installation_id: "fixture".into(),
            config_epoch: 1,
            generation: 2,
        },
        config_digest: "ab".repeat(32),
        ready: true,
    };
    let mut snapshot = EngineSnapshot {
        desired_mode: EngineMode::SystemProxy,
        state: EngineState::ProxyActive {
            runtime: runtime.clone(),
        },
        generation: 2,
        config_digest: Some(runtime.config_digest.clone()),
    };
    assert_eq!(
        ready_mode(cfw_engine_api::EngineRuntimePlatform::MacOs, &snapshot),
        Some(EngineMode::SystemProxy)
    );
    assert_eq!(
        ready_mode(cfw_engine_api::EngineRuntimePlatform::Windows, &snapshot),
        None
    );
    snapshot.state = EngineState::ProxyActive {
        runtime: RuntimeIdentity {
            owner: EngineOwner::WindowsUserAgent,
            ..runtime.clone()
        },
    };
    assert_eq!(
        ready_mode(cfw_engine_api::EngineRuntimePlatform::Windows, &snapshot),
        Some(EngineMode::SystemProxy)
    );
    assert_eq!(
        ready_mode(cfw_engine_api::EngineRuntimePlatform::MacOs, &snapshot),
        None
    );
    for state in [
        EngineState::Off,
        EngineState::ProxyStarting { generation: 2 },
        EngineState::Failed {
            generation: 2,
            target: EngineMode::SystemProxy,
            error: "fixture failure".into(),
            recheck_pending: false,
        },
        EngineState::ProxyActive {
            runtime: RuntimeIdentity {
                ready: false,
                ..runtime.clone()
            },
        },
        EngineState::ProxyActive {
            runtime: RuntimeIdentity {
                owner: EngineOwner::PacketTunnelSystemExtension,
                ..runtime.clone()
            },
        },
    ] {
        snapshot.state = state;
        assert_eq!(
            ready_mode(cfw_engine_api::EngineRuntimePlatform::MacOs, &snapshot),
            None
        );
    }
    snapshot.state = EngineState::ProxyActive { runtime };
    snapshot.generation += 1;
    assert_eq!(
        ready_mode(cfw_engine_api::EngineRuntimePlatform::MacOs, &snapshot),
        None
    );
    snapshot.generation -= 1;
    snapshot.config_digest = Some("cd".repeat(32));
    assert_eq!(
        ready_mode(cfw_engine_api::EngineRuntimePlatform::MacOs, &snapshot),
        None
    );
}
