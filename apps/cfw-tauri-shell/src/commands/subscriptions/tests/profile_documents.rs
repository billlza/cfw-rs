//! Profile documents as the renderer sees them: imports that project for both
//! modes, profile text without projections or paths, the app selector, and
//! QR codes that carry only a subscription URL.

use super::*;

#[test]
fn imports_require_a_profile_that_projects_for_both_modes() {
    let settings = EngineSettings::default();
    let profile = validated_profile(PROFILE_JSON, &settings).expect("valid profile");
    assert_eq!(profile.credential_references().len(), 1);

    // The projection owns listeners, logging, DNS and the experimental
    // controller, so a document that tries to supply them is refused before
    // anything is stored.
    for rejected in [
        r#"{"outbounds":[{"type":"direct","tag":"direct"}],"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}"#,
        r#"{"outbounds":[{"type":"direct","tag":"direct"}],"inbounds":[{"type":"mixed","listen":"0.0.0.0","listen_port":7890}]}"#,
        r#"{"outbounds":[{"type":"direct","tag":"direct"}],"log":{"level":"debug"}}"#,
        "not json",
        "{}",
    ] {
        assert!(
            validated_profile(rejected, &settings).is_err(),
            "accepted unsupported document: {rejected}"
        );
    }
}

#[test]
fn profile_text_payload_carries_no_projection_or_path() {
    let payload = serde_json::to_value(UiProfileText {
        digest: "ab".repeat(32),
        id: "34db18b6-9903-4e9f-8854-15648e19e4f3".into(),
        name: "Work".into(),
        body: PROFILE_JSON.to_owned(),
        proxy_selections: std::collections::BTreeMap::new(),
        app_selector: None,
        active: true,
        source_url: Some("https://example.com/sub?token=t".into()),
        bytes: PROFILE_JSON.len(),
        updated_epoch_secs: 42,
    })
    .expect("serialize profile text");
    let keys = payload
        .as_object()
        .expect("object payload")
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            "active",
            "app_selector",
            "body",
            "bytes",
            "digest",
            "id",
            "name",
            "proxy_selections",
            "source_url",
            "updated_epoch_secs",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>()
    );
    assert!(!payload.to_string().contains("generated_body"));
    assert!(!payload.to_string().contains("clash_api"));
}

#[test]
fn profile_text_offers_the_app_selector_of_a_profile_without_a_final_route() {
    const NODES_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const FINAL_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let nodes = serde_json::json!({"outbounds": [
        {"type":"socks5","tag":"first","server":"first.example.com","server_port":1080},
        {"type":"socks5","tag":"second","server":"second.example.com","server_port":1080},
        {"type":"direct","tag":"DIRECT"}
    ]});
    let mut explicit_final = nodes.clone();
    explicit_final["route"] = serde_json::json!({"final": "first"});
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    for (id, document) in [(NODES_ID, &nodes), (FINAL_ID, &explicit_final)] {
        let profile = ValidatedSingBoxProfile::parse(&document.to_string()).expect("profile");
        repository
            .import_with_id_and_source(id, Some("Nodes"), &profile, None)
            .expect("import profile");
    }
    let text = |id| {
        serde_json::to_value(profile_text(&repository, id).expect("profile text"))
            .expect("serialize profile text")
    };
    assert_eq!(
        text(NODES_ID)["app_selector"],
        serde_json::json!({"tag":"cfw-proxy-selector","members":["first","second"],"default":"first"})
    );
    assert_eq!(text(FINAL_ID)["app_selector"], serde_json::Value::Null);
}

#[test]
fn qrcode_rendering_encodes_only_a_subscription_url() {
    let code = QrCode::new(b"https://example.com/sub?token=t").expect("qr code");
    let rendered = code
        .render::<svg::Color<'_>>()
        .min_dimensions(190, 190)
        .dark_color(svg::Color("#2c3e50"))
        .light_color(svg::Color("#ffffff"))
        .build();
    assert!(rendered.starts_with("<?xml"));
    assert!(rendered.contains("svg"));
    assert!(
        !rendered.contains("token=t"),
        "the URL is encoded, not written"
    );
}
