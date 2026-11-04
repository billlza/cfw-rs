//! WireGuard and Tailscale endpoints: projection, validation and latency
//! probes.

use super::*;

#[test]
fn wireguard_uses_userspace_endpoints_and_preserves_separate_credential_addresses() {
    let profile = ValidatedSingBoxProfile::parse(&json!({"outbounds":[wireguard()]}).to_string())
        .expect("WireGuard");
    assert!(profile.routes_through_remote());
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("projection");
    let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime");
    assert_eq!(runtime["route"]["final"], "wg");
    assert_eq!(runtime["endpoints"][0]["system"], false);
    assert_eq!(runtime["endpoints"][0]["private_key"], "");
    assert_eq!(runtime["endpoints"][0]["peers"][0]["pre_shared_key"], "");
    assert_eq!(
        runtime["endpoints"][0]["peers"][0]["allowed_ips"],
        json!(["0.0.0.0/0", "::/0"])
    );
    assert_eq!(
        projected.credential_slots()[0].json_pointer(),
        "/endpoints/0/private_key"
    );
    assert_eq!(
        projected.credential_slots()[1].json_pointer(),
        "/endpoints/0/peers/0/pre_shared_key"
    );

    let mut mixed = json!({"outbounds":[wireguard(), tls_profile(json!({"enabled":true,"server_name":"proxy.example.com"}))["outbounds"][0].clone()]});
    mixed["outbounds"][1]["credential_ref"]["id"] = json!("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    let profile = ValidatedSingBoxProfile::parse(&mixed.to_string()).expect("mixed profile");
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("mixed projection");
    assert_eq!(
        projected.credential_slots()[2].json_pointer(),
        "/outbounds/0/password"
    );
}

#[test]
fn wireguard_rejects_invalid_keys_addresses_and_credential_kinds() {
    for (key, value) in [
        ("peer_public_key", json!("invalid")),
        ("local_addresses", json!([])),
        ("local_addresses", json!(["127.0.0.1/32"])),
        ("local_addresses", json!(["10.0.0.1/33"])),
        ("local_addresses", json!(["10.0.0.1/32", "10.0.0.2/32"])),
        ("mtu", json!(1279)),
        ("persistent_keepalive_seconds", json!(3601)),
        (
            "private_key_credential_ref",
            json!({"id":PROFILE_ID,"kind":"trojan_password"}),
        ),
    ] {
        let mut outbound = wireguard();
        outbound[key] = value;
        assert!(
            ValidatedSingBoxProfile::parse(&json!({"outbounds":[outbound]}).to_string()).is_err(),
            "admitted {key}"
        );
    }
    for kind in [
        crate::CredentialKind::WireGuardPrivateKey,
        crate::CredentialKind::WireGuardPreSharedKey,
    ] {
        for invalid in [
            "AAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==",
        ] {
            assert!(
                crate::CredentialSecret::new(invalid)
                    .expect("text")
                    .validate_for_kind(kind)
                    .is_err()
            );
        }
    }
}

#[test]
fn tailscale_projects_an_exit_node_endpoint_with_its_vault_slot() {
    let profile = ValidatedSingBoxProfile::parse(&json!({"outbounds":[tailscale()]}).to_string())
        .expect("Tailscale");
    assert!(profile.routes_through_remote());
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("projection");
    let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime");
    assert_eq!(runtime["route"]["final"], "ts");
    assert!(
        runtime["outbounds"]
            .as_array()
            .expect("outbounds")
            .iter()
            .all(|outbound| outbound["type"] != "tailscale")
    );
    let endpoint = &runtime["endpoints"][0];
    assert_eq!(endpoint["type"], "tailscale");
    assert_eq!(endpoint["tag"], "ts");
    assert_eq!(endpoint["auth_key"], "");
    assert_eq!(endpoint["exit_node"], "exit-mac");
    assert_eq!(
        endpoint["state_directory"],
        format!("tailscale/{PROFILE_ID}")
    );
    assert!(endpoint["domain_resolver"].is_object());
    for absent in [
        "control_url",
        "control_server",
        "hostname",
        "accept_routes",
        "exit_node_allow_lan_access",
        "advertise_exit_node",
        "advertise_routes",
        "ephemeral",
        "system_interface",
    ] {
        assert!(endpoint.get(absent).is_none(), "{absent}");
    }
    assert_eq!(projected.credential_slots().len(), 1);
    assert_eq!(
        projected.credential_slots()[0].json_pointer(),
        "/endpoints/0/auth_key"
    );
    assert_eq!(
        projected.credential_slots()[0].target(),
        crate::CredentialTarget::TailscaleAuthKey
    );

    let mut tuned = tailscale();
    tuned["control_server"] = json!("https://headscale.example.com");
    tuned["hostname"] = json!("office-mac");
    tuned["accept_routes"] = json!(true);
    tuned["exit_node_allow_lan_access"] = json!(true);
    let profile = ValidatedSingBoxProfile::parse(&json!({"outbounds":[tuned]}).to_string())
        .expect("tuned Tailscale");
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("tunnel projection");
    let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime");
    let endpoint = &runtime["endpoints"][0];
    assert_eq!(endpoint["control_url"], "https://headscale.example.com");
    assert_eq!(endpoint["hostname"], "office-mac");
    assert_eq!(endpoint["accept_routes"], true);
    assert_eq!(endpoint["exit_node_allow_lan_access"], true);
}

#[test]
fn tailscale_rejects_invalid_exit_nodes_urls_hostnames_and_credential_kinds() {
    for (key, value) in [
        ("exit_node", json!("")),
        ("exit_node", json!("exit node")),
        ("exit_node", json!("127.0.0.1")),
        ("control_server", json!("http://headscale.example.com")),
        (
            "control_server",
            json!("https://user:secret@headscale.example.com"),
        ),
        (
            "control_server",
            json!("https://headscale.example.com/?next=1"),
        ),
        (
            "control_server",
            json!("https://headscale.example.com/#login"),
        ),
        ("control_server", json!("headscale.example.com")),
        ("control_url", json!("https://headscale.example.com")),
        ("hostname", json!("")),
        ("hostname", json!("-office")),
        ("hostname", json!("office.mac")),
        ("hostname", json!("x".repeat(64))),
        (
            "auth_key_credential_ref",
            json!({"id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","kind":"trojan_password"}),
        ),
        ("advertise_exit_node", json!(true)),
        ("advertise_routes", json!(["192.168.1.0/24"])),
        ("ephemeral", json!(true)),
        ("system_interface", json!(true)),
        ("ssh_server", json!(true)),
    ] {
        let mut outbound = tailscale();
        outbound[key] = value;
        assert!(
            ValidatedSingBoxProfile::parse(&json!({"outbounds":[outbound]}).to_string()).is_err(),
            "admitted {key}"
        );
    }
    crate::CredentialSecret::new("tskey-auth-kTEST1CNTRL-abcdefghijklmnopqrstuvwxyz0123456789")
        .expect("auth key")
        .validate_for_kind(crate::CredentialKind::TailscaleAuthKey)
        .expect("printable token");
    for invalid in ["tskey auth", "tskey-auth-\u{fc}", &"x".repeat(257)] {
        assert!(
            crate::CredentialSecret::new(invalid)
                .and_then(|secret| secret.validate_for_kind(crate::CredentialKind::TailscaleAuthKey))
                .is_err(),
            "{invalid:?}"
        );
    }
}

#[test]
fn latency_probe_leaves_tailscale_endpoints_to_the_running_core() {
    let mixed = json!({"outbounds":[tailscale(), wireguard(),
        {"type":"selector","tag":"auto","outbounds":["ts","wg"],"default":"ts"},
        {"type":"selector","tag":"only-ts","outbounds":["ts"]},
        {"type":"selector","tag":"nested","outbounds":["only-ts"]}],
        "route":{"final":"auto"}});
    let profile = ValidatedSingBoxProfile::parse(&mixed.to_string()).expect("mixed profile");
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("projection");
    assert_eq!(
        projected.credential_slots()[0].json_pointer(),
        "/endpoints/0/auth_key"
    );
    assert_eq!(
        projected.credential_slots()[1].json_pointer(),
        "/endpoints/1/private_key"
    );
    let probe = profile
        .project_proxy_probe(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("probe");
    let template: Value = serde_json::from_str(probe.as_json()).expect("probe JSON");
    let endpoints = template["endpoints"].as_array().expect("endpoints");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0]["type"], "wireguard");
    let outbounds = template["outbounds"].as_array().expect("outbounds");
    let tags = outbounds
        .iter()
        .map(|outbound| outbound["tag"].as_str().expect("tag"))
        .collect::<Vec<_>>();
    assert!(
        !tags.contains(&"only-ts") && !tags.contains(&"nested"),
        "{tags:?}"
    );
    let auto = outbounds
        .iter()
        .find(|outbound| outbound["tag"] == "auto")
        .expect("auto group");
    assert_eq!(auto["outbounds"], json!(["wg"]));
    assert!(auto.get("default").is_none());
    assert_eq!(probe.excluded_tags(), ["nested", "only-ts", "ts"]);
    let pointers = probe
        .credential_slots()
        .iter()
        .map(|slot| slot.json_pointer())
        .collect::<Vec<_>>();
    assert_eq!(
        pointers,
        [
            "/endpoints/0/private_key",
            "/endpoints/0/peers/0/pre_shared_key"
        ]
    );
}
