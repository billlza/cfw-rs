//! Bootstrap resolvers: inherited, explicit and default pools, and the endpoints that use them.

use super::*;

fn inherited_bootstrap_profile() -> serde_json::Value {
    serde_json::json!({
        "dns": {"servers": [
            {"type":"https","server":"1.1.1.1","server_port":443,
             "path":"/dns-query","tls":{"enabled":true,"server_name":"cloudflare-dns.com"}},
            {"type":"https","server":"223.5.5.5","server_port":443,
             "path":"/dns-query","tls":{"enabled":true,"server_name":"dns.alidns.com"}}
        ]},
        "outbounds":[{"type":"shadowsocks","tag":"proxy","server":"node.example.com",
            "server_port":443,"method":"aes-256-gcm",
            "credential_ref":{"id":SS_ID,"kind":"shadowsocks_password"}}]
    })
}

#[test]
fn inherited_bootstrap_uses_the_profiles_numeric_encrypted_resolvers_in_all_modes() {
    let profile = ValidatedSingBoxProfile::parse(&inherited_bootstrap_profile().to_string())
        .expect("encrypted DNS profile");
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
    ] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .unwrap();
        let config: serde_json::Value = serde_json::from_str(projected.as_json()).unwrap();
        for (index, (address, name)) in [
            ("1.1.1.1", "cloudflare-dns.com"),
            ("223.5.5.5", "dns.alidns.com"),
        ]
        .into_iter()
        .enumerate()
        {
            let resolver = &config["dns"]["servers"][index];
            assert_eq!(resolver["tag"], format!("cfw-bootstrap-dns-{index}"));
            assert_eq!(resolver["type"], "https");
            assert_eq!(resolver["server"], address);
            assert_eq!(resolver["tls"]["server_name"], name);
            assert_eq!(resolver["tls"]["min_version"], MINIMUM_REMOTE_TLS_VERSION);
            assert!(resolver.get("detour").is_none());
            assert!(resolver.get("domain_resolver").is_none());
        }
        assert_eq!(
            config["outbounds"][0]["domain_resolver"],
            serde_json::json!({
                "server":"cfw-bootstrap-dns-0", "fallback_server":"cfw-bootstrap-dns-1"
            })
        );
    }
}

#[test]
fn inherited_bootstrap_keeps_explicit_bootstrap_and_selected_route_contracts() {
    let mut input = inherited_bootstrap_profile();
    input["dns"]["bootstrap_servers"] = serde_json::json!(["9.9.9.9"]);
    let explicit = ValidatedSingBoxProfile::parse(&input.to_string())
        .unwrap()
        .project(
            PROFILE_ID,
            ProjectionMode::LocalProxy,
            &EngineSettings::default(),
        )
        .unwrap();
    let config: serde_json::Value = serde_json::from_str(explicit.as_json()).unwrap();
    assert_eq!(config["dns"]["servers"][0]["type"], "udp");
    assert_eq!(config["dns"]["servers"][0]["server"], "9.9.9.9");

    input["dns"]
        .as_object_mut()
        .unwrap()
        .remove("bootstrap_servers");
    for server in input["dns"]["servers"].as_array_mut().unwrap() {
        server["route"] = serde_json::json!("selected");
    }
    let selected = ValidatedSingBoxProfile::parse(&input.to_string())
        .unwrap()
        .project(
            PROFILE_ID,
            ProjectionMode::LocalProxy,
            &EngineSettings::default(),
        )
        .unwrap();
    let config: serde_json::Value = serde_json::from_str(selected.as_json()).unwrap();
    assert_eq!(config["dns"]["servers"][0]["type"], "udp");
    assert_eq!(config["dns"]["servers"][0]["server"], "223.6.6.6");
    assert_eq!(config["dns"]["servers"][1]["server"], "119.29.29.29");
}

#[test]
fn inherited_bootstrap_deduplicates_equivalent_direct_transports() {
    let mut input = inherited_bootstrap_profile();
    let first = input["dns"]["servers"][0].clone();
    let mut direct = first.clone();
    direct["route"] = serde_json::json!("direct");
    input["dns"]["servers"] = serde_json::json!([first, direct]);
    let projected = ValidatedSingBoxProfile::parse(&input.to_string())
        .unwrap()
        .project(
            PROFILE_ID,
            ProjectionMode::LocalProxy,
            &EngineSettings::default(),
        )
        .unwrap();
    let config: serde_json::Value = serde_json::from_str(projected.as_json()).unwrap();
    let bootstrap = config["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["tag"].as_str().unwrap().starts_with("cfw-bootstrap-dns-"))
        .collect::<Vec<_>>();
    assert_eq!(bootstrap.len(), 1);
    assert_eq!(bootstrap[0]["type"], "https");
}

#[test]
fn inherited_bootstrap_preserves_encrypted_transport_and_tls_minimum() {
    for kind in ["tls", "quic", "https", "h3"] {
        let mut input = inherited_bootstrap_profile();
        let mut resolver = serde_json::json!({
            "type":kind, "server":"1.1.1.1", "server_port":443,
            "tls":{"enabled":true,"server_name":"resolver.example.com","min_version":"1.3"}
        });
        if matches!(kind, "https" | "h3") {
            resolver["path"] = serde_json::json!("/custom-query");
        }
        input["dns"]["servers"] = serde_json::json!([resolver]);
        let projected = ValidatedSingBoxProfile::parse(&input.to_string())
            .unwrap()
            .project(
                PROFILE_ID,
                ProjectionMode::LocalProxy,
                &EngineSettings::default(),
            )
            .unwrap();
        let config: serde_json::Value = serde_json::from_str(projected.as_json()).unwrap();
        let bootstrap = &config["dns"]["servers"][0];
        assert_eq!(bootstrap["type"], kind);
        assert_eq!(bootstrap["tls"]["server_name"], "resolver.example.com");
        assert_eq!(bootstrap["tls"]["min_version"], "1.3");
        assert!(bootstrap.get("detour").is_none());
        assert!(config["dns"]["servers"][1].get("detour").is_some());
        if matches!(kind, "https" | "h3") {
            assert_eq!(bootstrap["path"], "/custom-query");
        }
    }
}

#[test]
fn inherited_bootstrap_does_not_reinterpret_plaintext_resolvers() {
    let mut input = inherited_bootstrap_profile();
    input["dns"]["servers"] = serde_json::json!([
        {"type":"udp","server":"8.8.8.8","server_port":53}
    ]);
    let projected = ValidatedSingBoxProfile::parse(&input.to_string())
        .unwrap()
        .project(
            PROFILE_ID,
            ProjectionMode::LocalProxy,
            &EngineSettings::default(),
        )
        .unwrap();
    let config: serde_json::Value = serde_json::from_str(projected.as_json()).unwrap();
    assert_eq!(config["dns"]["servers"][0]["type"], "udp");
    assert_eq!(config["dns"]["servers"][0]["server"], "223.6.6.6");
    assert_eq!(config["dns"]["servers"][1]["server"], "119.29.29.29");
}

#[test]
fn inherited_bootstrap_preserves_disabled_ipv6_resolver_refusal() {
    let mut input = inherited_bootstrap_profile();
    input["dns"]["servers"] = serde_json::json!([
        {"type":"https","server":"2001:4860:4860::8888","server_port":443,
         "path":"/dns-query","tls":{"enabled":true,"server_name":"dns.google"}}
    ]);
    let settings = EngineSettings {
        enable_ipv6: false,
        ..EngineSettings::default()
    };
    let error = ValidatedSingBoxProfile::parse(&input.to_string())
        .unwrap()
        .project(PROFILE_ID, ProjectionMode::LocalProxy, &settings)
        .unwrap_err();
    assert_eq!(
        error,
        ConfigError::UnsupportedPolicyShape {
            path: "$.dns".into(),
            reason: "IPv6 resolver requires IPv6 to be enabled".into()
        }
    );
}

#[test]
fn domain_named_proxy_endpoint_uses_the_bounded_bootstrap_pair_in_both_modes() {
    let profile = shadowsocks_profile(SS_ID);
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("remote projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        assert_eq!(
            config["outbounds"][0]["domain_resolver"],
            serde_json::json!({
                "server": "cfw-bootstrap-dns-0",
                "fallback_server": "cfw-bootstrap-dns-1",
            })
        );
        assert_eq!(
            config["route"]["default_domain_resolver"],
            serde_json::json!({
                "server": "cfw-authenticated-dns-0",
                "fallback_server": "cfw-authenticated-dns-1",
            })
        );
        assert_eq!(
            config["dns"]["rules"][0]["server"],
            "cfw-authenticated-dns-0"
        );
    }
}

#[test]
fn numeric_proxy_endpoint_does_not_consume_direct_bootstrap_dns() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"8.8.4.4","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}}]}}"#
    ))
    .expect("numeric endpoint profile");
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("numeric endpoint projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        assert!(config["outbounds"][0].get("domain_resolver").is_none());
    }
}

#[test]
fn ipv6_literal_proxy_endpoint_does_not_consume_direct_bootstrap_dns() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"2606:4700:4700::1111","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}}]}}"#
    ))
    .expect("IPv6 endpoint profile");
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("IPv6 endpoint projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        assert!(config["outbounds"][0].get("domain_resolver").is_none());
    }
}

#[test]
fn every_supported_remote_protocol_uses_the_same_bounded_bootstrap_pair() {
    let profile = remote_protocol_matrix_profile();
    let expected = serde_json::json!({
        "server": "cfw-bootstrap-dns-0",
        "fallback_server": "cfw-bootstrap-dns-1",
    });
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("remote protocol matrix projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        let outbounds = config["outbounds"].as_array().expect("outbound matrix");
        assert_eq!(outbounds.len(), 9);
        assert_eq!(
            outbounds[8],
            serde_json::json!({"type":"direct","tag":"cfw-direct"})
        );
        for outbound in &outbounds[..8] {
            assert_eq!(outbound["domain_resolver"], expected);
        }
    }
}

#[test]
fn tunnel_identity_binds_configured_numeric_bootstrap_dns() {
    let profile = ValidatedSingBoxProfile::direct();
    let baseline = profile
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("baseline tunnel");
    let changed = profile
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings {
                bootstrap_dns_servers: [
                    IpAddr::V4(Ipv4Addr::new(180, 76, 76, 76)),
                    IpAddr::V4(Ipv4Addr::new(101, 226, 4, 6)),
                ],
                ..EngineSettings::default()
            },
        )
        .expect("changed tunnel");
    assert_ne!(baseline.as_json(), changed.as_json());
    assert_ne!(
        baseline.configuration_digest(),
        changed.configuration_digest()
    );
    assert_ne!(baseline.digest(), changed.digest());

    let authenticated_changed = profile
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings {
                authenticated_dns_servers: [
                    AuthenticatedDnsServer {
                        address: IpAddr::V4(Ipv4Addr::new(1, 12, 12, 12)),
                        server_name: "doh.pub".to_owned(),
                    },
                    AuthenticatedDnsServer {
                        address: IpAddr::V4(Ipv4Addr::new(120, 53, 53, 53)),
                        server_name: "doh.pub".to_owned(),
                    },
                ],
                ..EngineSettings::default()
            },
        )
        .expect("changed authenticated DNS tunnel");
    assert_ne!(baseline.as_json(), authenticated_changed.as_json());
    assert_ne!(baseline.digest(), authenticated_changed.digest());
}
