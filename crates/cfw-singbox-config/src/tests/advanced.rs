use serde_json::{Value, json};

use crate::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

#[test]
fn hosts_bootstrap_and_fake_ip_have_distinct_runtime_roles() {
    let source = json!({"outbounds":[{"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080}],
        "hosts":{"node.example.com":["9.9.9.9"]},
        "dns":{"servers":[{"type":"udp","server":"1.1.1.1","server_port":53}],
            "bootstrap_servers":["8.8.8.8","1.1.1.1"],"ipv6":false,
            "fake_ip":{"exclude":["+.lan","*.local","localhost"]}}});
    let profile = ValidatedSingBoxProfile::parse(&source.to_string()).expect("DNS and hosts");
    for mode in [
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let runtime: Value = serde_json::from_str(
            profile
                .project(PROFILE_ID, mode, &EngineSettings::default())
                .expect("project")
                .as_json(),
        )
        .expect("runtime");
        assert_eq!(runtime["dns"]["servers"][0]["server"], "8.8.8.8");
        assert_eq!(
            runtime["outbounds"][0]["domain_resolver"],
            json!({"server":"cfw-profile-hosts"})
        );
        assert_eq!(
            runtime["dns"]["rules"][0],
            json!({"query_type":["AAAA"],"action":"predefined","rcode":"NOERROR"})
        );
        let fake = runtime["dns"]["servers"]
            .as_array()
            .expect("servers")
            .iter()
            .find(|server| server["type"] == "fakeip");
        assert_eq!(fake.is_some(), mode.has_tunnel());
        if let Some(fake) = fake {
            assert_eq!(fake["inet4_range"], "198.19.0.0/16");
            assert!(fake.get("inet6_range").is_none());
            assert_eq!(runtime["experimental"]["cache_file"]["store_fakeip"], true);
        }
    }
    for (key, invalid) in [
        ("hosts", json!({"*.example.com":["9.9.9.9"]})),
        ("hosts", json!({"node.example.com":["9.9.9.9","9.9.9.9"]})),
        (
            "dns",
            json!({"servers":[{"type":"udp","server":"1.1.1.1","server_port":53}],"fake_ip":{"exclude":["bad[regex].test"]}}),
        ),
    ] {
        let mut bad = source.clone();
        bad[key] = invalid;
        assert!(ValidatedSingBoxProfile::parse(&bad.to_string()).is_err());
    }
}

#[test]
fn selected_dns_transports_keep_authentication_and_stay_on_the_selected_route() {
    for kind in ["udp", "tcp", "tls", "quic", "https", "h3"] {
        let mut server = json!({"type":kind,"server":"1.1.1.1","server_port":853});
        if !matches!(kind, "udp" | "tcp") {
            server["tls"] =
                json!({"enabled":true,"server_name":"cloudflare-dns.com","min_version":"1.3"});
        }
        if matches!(kind, "https" | "h3") {
            server["path"] = json!("/dns-query");
            server["server_port"] = json!(443);
        }
        let value = json!({"outbounds":[wireguard()],"dns":{"servers":[server.clone()]}});
        let profile = ValidatedSingBoxProfile::parse(&value.to_string()).expect("DNS policy");
        let runtime: Value = serde_json::from_str(
            profile
                .project(
                    PROFILE_ID,
                    ProjectionMode::SystemProxy,
                    &EngineSettings::default(),
                )
                .expect("projection")
                .as_json(),
        )
        .expect("runtime");
        let servers = runtime["dns"]["servers"].as_array().expect("servers");
        let selected_servers = servers
            .iter()
            .filter(|server| server["tag"] == "cfw-profile-dns-0")
            .collect::<Vec<_>>();
        assert_eq!(selected_servers.len(), 1);
        let projected = selected_servers[0];
        assert_eq!(projected["type"], kind);
        assert_eq!(projected["server"], "1.1.1.1");
        assert_eq!(projected["detour"], "wg");
        assert_eq!(runtime["dns"]["final"], "cfw-profile-dns-0");
        assert_eq!(
            runtime["route"]["default_domain_resolver"],
            json!({"policy":"default"})
        );
        assert_eq!(
            servers.len(),
            if matches!(kind, "udp" | "tcp") { 3 } else { 2 }
        );
        if !matches!(kind, "udp" | "tcp") {
            assert_eq!(projected["tls"]["server_name"], "cloudflare-dns.com");
            assert!(projected["tls"].get("insecure").is_none());
        }
        let mut invalid = value.clone();
        invalid["dns"]["servers"][0]["server_port"] = json!(0);
        assert!(ValidatedSingBoxProfile::parse(&invalid.to_string()).is_err());
        invalid = value.clone();
        invalid["dns"]["servers"][0]["server"] = json!("127.0.0.1");
        assert!(ValidatedSingBoxProfile::parse(&invalid.to_string()).is_err());
        invalid = value;
        invalid["dns"]["servers"] = json!([server.clone(), server]);
        assert!(ValidatedSingBoxProfile::parse(&invalid.to_string()).is_err());
    }
}

#[test]
fn dns_fallback_is_explicit_and_ipv6_resolver_cannot_override_disabled_ipv6() {
    let value = json!({"outbounds":[wireguard()],"dns":{"servers":[
        {"type":"udp","server":"10.64.0.1","server_port":53},
        {"type":"udp","server":"2606:4700:4700::1111","server_port":53}
    ]}});
    let profile = ValidatedSingBoxProfile::parse(&value.to_string()).expect("DNS pair");
    assert!(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings {
                    enable_ipv6: false,
                    ..EngineSettings::default()
                }
            )
            .is_err()
    );
    let runtime: Value = serde_json::from_str(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("projection")
            .as_json(),
    )
    .expect("runtime");
    assert_eq!(runtime["dns"]["final"], "cfw-profile-dns-1");
    assert_eq!(
        runtime["route"]["default_domain_resolver"],
        json!({"policy":"default"})
    );
}

fn automatic_profile() -> Value {
    json!({
        "outbounds": [
            {"type":"socks5","tag":"first","server":"first.example.com","server_port":1080},
            {"type":"socks5","tag":"second","server":"second.example.com","server_port":1080},
            {"type":"urltest","tag":"automatic","outbounds":["first","second"],
             "url":"https://www.gstatic.com/generate_204","interval_seconds":300,
             "tolerance_ms":50,"idle_timeout_seconds":1800},
            {"type":"selector","tag":"PROXY","outbounds":["automatic","second"]}
        ],
        "route":{"final":"PROXY"}
    })
}

#[test]
fn fallback_groups_preserve_priority_and_do_not_become_lowest_latency_groups() {
    let mut source = automatic_profile();
    let group = source["outbounds"][2].as_object_mut().unwrap();
    group.insert("type".into(), json!("fallback"));
    group.remove("tolerance_ms");
    let profile = ValidatedSingBoxProfile::parse(&source.to_string()).unwrap();
    assert!(profile.routes_through_remote());
    assert!(
        profile
            .with_selected_outbound("automatic", "second")
            .is_err()
    );
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .unwrap();
        let runtime: Value = serde_json::from_str(projected.as_json()).unwrap();
        assert_eq!(
            runtime["outbounds"][2],
            json!({
                "type":"fallback", "tag":"automatic", "outbounds":["first","second"],
                "url":"https://www.gstatic.com/generate_204", "interval":"300s",
                "idle_timeout":"1800s", "interrupt_exist_connections":false
            })
        );
        let probe: Value =
            serde_json::from_str(&projected.proxy_probe_template().unwrap().json).unwrap();
        assert_eq!(probe["outbounds"][2]["type"], "selector");
        assert!(probe["outbounds"][2].get("url").is_none());
    }
    for (key, invalid) in [
        ("outbounds", json!(["first", "first"])),
        ("outbounds", json!(["missing"])),
        ("outbounds", json!(["PROXY"])),
        ("interval_seconds", json!(0)),
        ("url", json!("file:///tmp/probe")),
        ("tolerance_ms", json!(50)),
    ] {
        let mut invalid_source = source.clone();
        invalid_source["outbounds"][2][key] = invalid;
        assert!(
            ValidatedSingBoxProfile::parse(&invalid_source.to_string()).is_err(),
            "{key}"
        );
    }
}

#[test]
fn load_balance_strategy_and_continuous_probe_policy_survive_projection() {
    for strategy in ["consistent-hashing", "sticky-sessions", "round-robin"] {
        let mut source = automatic_profile();
        let group = source["outbounds"][2].as_object_mut().unwrap();
        group.insert("type".into(), json!("loadbalance"));
        group.insert("strategy".into(), json!(strategy));
        group.insert("lazy".into(), json!(false));
        group.remove("tolerance_ms");
        let profile = ValidatedSingBoxProfile::parse(&source.to_string()).unwrap();
        let projection = profile
            .project(
                PROFILE_ID,
                ProjectionMode::LocalProxy,
                &EngineSettings::default(),
            )
            .unwrap();
        let runtime: Value = serde_json::from_str(projection.as_json()).unwrap();
        assert_eq!(runtime["outbounds"][2]["type"], "loadbalance");
        assert_eq!(runtime["outbounds"][2]["strategy"], strategy);
        assert_eq!(runtime["outbounds"][2]["lazy"], false);
        assert!(profile.routes_through_remote());
        assert!(
            profile
                .with_selected_outbound("automatic", "first")
                .is_err()
        );
        let probe: Value =
            serde_json::from_str(&projection.proxy_probe_template().unwrap().json).unwrap();
        assert_eq!(probe["outbounds"][2]["type"], "selector");
        source["outbounds"][2]["strategy"] = json!("random");
        assert!(ValidatedSingBoxProfile::parse(&source.to_string()).is_err());
    }
}

#[test]
fn automatic_groups_preserve_timing_and_cannot_be_overridden_by_saved_selection() {
    let profile = ValidatedSingBoxProfile::parse(&automatic_profile().to_string())
        .expect("automatic profile");
    assert!(profile.routes_through_remote());
    assert!(
        profile
            .with_selected_outbound("automatic", "second")
            .is_err()
    );
    for mode in [
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("projection");
        let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime");
        assert_eq!(
            runtime["outbounds"][2],
            json!({
                "type":"urltest","tag":"automatic","outbounds":["first","second"],
                "url":"https://www.gstatic.com/generate_204","interval":"300s","tolerance":50,
                "idle_timeout":"1800s","interrupt_exist_connections":false
            })
        );
    }
    let mut mixed = automatic_profile();
    mixed["outbounds"][1] = json!({"type":"direct","tag":"second"});
    assert!(
        !ValidatedSingBoxProfile::parse(&mixed.to_string())
            .expect("mixed group")
            .routes_through_remote()
    );
}

#[test]
fn automatic_group_graph_and_probe_inputs_are_validated_before_runtime() {
    for (key, invalid) in [
        ("outbounds", json!([])),
        ("outbounds", json!(["first", "first"])),
        ("outbounds", json!(["missing"])),
        ("outbounds", json!(["PROXY"])),
        ("interval_seconds", json!(29)),
        ("interval_seconds", json!(86_401)),
        ("idle_timeout_seconds", json!(299)),
        ("idle_timeout_seconds", json!(604_801)),
        ("tolerance_ms", json!(10_001)),
        ("url", json!("file:///etc/passwd")),
        ("url", json!("https://name:secret@example.com/probe")),
        ("url", json!("https://example.com/#fragment")),
        ("url", json!("https://example.com:0")),
        ("url", json!("https://example.com/\nprobe")),
    ] {
        let mut value = automatic_profile();
        value["outbounds"][2][key] = invalid;
        assert!(
            ValidatedSingBoxProfile::parse(&value.to_string()).is_err(),
            "admitted {key}"
        );
    }
}

fn tls_profile(tls: Value) -> Value {
    json!({"outbounds":[{"type":"trojan","tag":"secure","server":"proxy.example.com","server_port":443,
        "credential_ref":{"id":PROFILE_ID,"kind":"trojan_password"},"tls":tls}]})
}

#[test]
fn detours_preserve_both_hops_and_reject_cycles_across_groups() {
    let mut value = automatic_profile();
    value["detours"] = json!({"first":"second"});
    let profile = ValidatedSingBoxProfile::parse(&value.to_string()).expect("two hops");
    let runtime: Value = serde_json::from_str(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("projection")
            .as_json(),
    )
    .expect("runtime");
    assert_eq!(runtime["outbounds"][0]["detour"], "second");
    assert!(runtime["outbounds"][0].get("domain_resolver").is_none());
    assert!(runtime["outbounds"][1].get("domain_resolver").is_some());
    for invalid in [
        json!({"first":"first"}),
        json!({"first":"second","second":"first"}),
        json!({"first":"PROXY"}),
        json!({"PROXY":"second"}),
        json!({"missing":"second"}),
    ] {
        value["detours"] = invalid;
        assert!(ValidatedSingBoxProfile::parse(&value.to_string()).is_err());
    }
}

fn wireguard() -> Value {
    json!({"type":"wireguard","tag":"wg","server":"vpn.example.com","server_port":51820,
        "local_addresses":["10.10.0.2/32","fd00::2/128"],"mtu":1420,"persistent_keepalive_seconds":25,
        "peer_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "private_key_credential_ref":{"id":PROFILE_ID,"kind":"wireguard_private_key"},
        "pre_shared_key_credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"wireguard_pre_shared_key"}})
}

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
fn required_hybrid_key_exchange_reaches_projection_without_classical_downgrade() {
    let tls = json!({"enabled":true,"server_name":"proxy.example.com","min_version":"1.3","curve_preferences":["X25519MLKEM768"]});
    let profile = ValidatedSingBoxProfile::parse(&tls_profile(tls.clone()).to_string())
        .expect("hybrid profile");
    let runtime: Value = serde_json::from_str(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("projection")
            .as_json(),
    )
    .expect("runtime");
    assert_eq!(runtime["outbounds"][0]["tls"], tls);
    for (field, invalid) in [
        ("min_version", json!("1.2")),
        ("min_version", json!("1.1")),
        ("enabled", json!(false)),
        ("utls", json!({"enabled":true,"fingerprint":"chrome"})),
        (
            "curve_preferences",
            json!(["X25519MLKEM768", "X25519MLKEM768"]),
        ),
        ("curve_preferences", json!(["invented"])),
    ] {
        let mut value = tls.clone();
        value[field] = invalid;
        assert!(
            ValidatedSingBoxProfile::parse(&tls_profile(value).to_string()).is_err(),
            "admitted {field}"
        );
    }
    let mut preferred = tls;
    preferred["curve_preferences"] = json!(["X25519MLKEM768", "X25519"]);
    ValidatedSingBoxProfile::parse(&tls_profile(preferred).to_string())
        .expect("explicit classical compatibility");
}

fn tailscale() -> Value {
    json!({"type":"tailscale","tag":"ts","exit_node":"exit-mac",
        "auth_key_credential_ref":{"id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","kind":"tailscale_auth_key"}})
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
