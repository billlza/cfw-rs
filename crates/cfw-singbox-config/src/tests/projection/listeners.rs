//! Application-owned inbounds and the loopback controller.

use super::*;

#[test]
fn projections_have_exactly_one_application_owned_inbound() {
    let profile = ValidatedSingBoxProfile::direct();
    let proxy = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("proxy config");
    let tunnel = profile
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("tunnel config");

    assert!(proxy.as_json().contains("cfw-system-proxy"));
    assert!(!proxy.as_json().contains("cfw-tunnel"));
    assert!(tunnel.as_json().contains("cfw-tunnel"));
    assert!(!tunnel.as_json().contains("cfw-system-proxy"));
    assert!(tunnel.as_json().contains(r#""auto_route":false"#));
    assert!(
        tunnel
            .as_json()
            .contains(r#""address":["198.18.64.1/30","2001:2:0:64::1/126"]"#)
    );
    assert!(tunnel.as_json().contains(r#""mtu":1500"#));
    let tunnel_json: serde_json::Value =
        serde_json::from_str(tunnel.as_json()).expect("tunnel JSON");
    let dns = tunnel_json["dns"].as_object().expect("DNS object");
    assert_eq!(dns["final"], "cfw-authenticated-dns-1");
    assert_eq!(dns["strategy"], "prefer_ipv4");
    let servers = dns["servers"].as_array().expect("DNS servers");
    assert_eq!(servers.len(), 4);
    assert_eq!(servers[0]["type"], "udp");
    assert_eq!(servers[0]["server"], "223.6.6.6");
    assert!(servers[0].get("detour").is_none());
    assert_eq!(servers[1]["type"], "udp");
    assert_eq!(servers[1]["server"], "119.29.29.29");
    assert!(servers[1].get("detour").is_none());
    for (index, server) in servers[2..].iter().enumerate() {
        assert_eq!(server["type"], "https");
        assert_eq!(server["tag"], format!("cfw-authenticated-dns-{index}"));
        assert!(
            server.get("detour").is_none(),
            "explicit DIRECT uses the normal dialer"
        );
        assert_eq!(server["path"], "/dns-query");
        assert_eq!(server["tls"]["enabled"], true);
        assert!(server["tls"]["server_name"].is_string());
        assert_eq!(server["tls"]["min_version"], MINIMUM_REMOTE_TLS_VERSION);
    }
    for server in servers {
        assert_ne!(server["server"], TUNNEL_ADDRESS_PLAN.ipv4_dns_peer);
        assert_ne!(server["server"], TUNNEL_ADDRESS_PLAN.ipv6_dns_peer);
    }
    assert_eq!(dns["rules"][0]["domain_regex"], ".*");
    assert_eq!(dns["rules"][0]["action"], "evaluate");
    assert_eq!(dns["rules"][1]["action"], "respond");
    assert!(!dns.contains_key("independent_cache"));
    assert_eq!(dns["rules"][0]["server"], "cfw-authenticated-dns-0");
    assert_eq!(
        tunnel_json["route"]["default_domain_resolver"],
        serde_json::json!({
            "server": "cfw-authenticated-dns-0",
            "fallback_server": "cfw-authenticated-dns-1",
        })
    );
    assert_eq!(
        tunnel_json["route"]["rules"][0],
        serde_json::json!({"action":"hijack-dns","port":53})
    );
    assert_eq!(tunnel_json["route"]["rules"][1]["clash_mode"], "Direct");
    assert_eq!(tunnel_json["route"]["rules"][2]["clash_mode"], "Global");
    assert!(!proxy.as_json().contains("hijack-dns"));
    let proxy_json: serde_json::Value = serde_json::from_str(proxy.as_json()).expect("proxy JSON");
    assert_eq!(proxy_json["dns"]["final"], "cfw-authenticated-dns-1");
    assert_eq!(
        proxy_json["dns"]["rules"][0]["server"],
        "cfw-authenticated-dns-0"
    );
    assert_eq!(
        proxy_json["dns"]["servers"]
            .as_array()
            .expect("proxy DNS servers")
            .len(),
        4
    );
    assert_eq!(
        proxy_json["route"]["default_domain_resolver"],
        serde_json::json!({
            "server": "cfw-authenticated-dns-0",
            "fallback_server": "cfw-authenticated-dns-1",
        })
    );
    assert_ne!(proxy.digest(), tunnel.digest());
}

#[test]
fn application_injects_the_loopback_controller_that_profiles_may_never_supply() {
    // `experimental` stays forbidden for imported profiles at the top level and
    // at any depth, so the controller can only come from this projection.
    assert_eq!(
        ValidatedSingBoxProfile::parse(
            r#"{"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}"#
        )
        .expect_err("profiles must not carry experimental options"),
        ConfigError::UnsupportedTopLevelKey("experimental".into())
    );
    assert!(matches!(
        ValidatedSingBoxProfile::parse(
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"experimental":{"clash_api":{}}}}"#
        )
        .expect_err("nested experimental options must stay forbidden"),
        ConfigError::ForbiddenKey { key, .. } if key == "experimental"
    ));

    let settings = EngineSettings::default();
    let endpoint = settings.clash_api_endpoint().expect("default endpoint");
    let profile = ValidatedSingBoxProfile::direct();
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &settings)
            .expect("projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        let clash_api = &config["experimental"]["clash_api"];
        assert_eq!(
            clash_api["external_controller"],
            serde_json::json!(format!("127.0.0.1:{DEFAULT_CLASH_API_PORT}"))
        );
        let secret = clash_api["secret"].as_str().expect("controller secret");
        assert_eq!(secret.len(), 64);
        assert!(secret.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(secret, endpoint.expose_secret());
        assert_eq!(projected.clash_api(), endpoint);
        assert_eq!(endpoint.address(), Ipv4Addr::LOCALHOST);
        assert!(endpoint.address().is_loopback());
        assert_eq!(
            clash_api.as_object().expect("clash_api object").len(),
            2,
            "the injected block stays minimal"
        );
        // The secret must not leak through diagnostics.
        let rendered = format!("{projected:?}");
        assert!(!rendered.contains(secret));
        assert!(format!("{endpoint:?}").contains("[REDACTED]"));
    }
}

#[test]
fn controller_port_is_taken_from_settings_and_stays_bounded() {
    let profile = ValidatedSingBoxProfile::direct();
    let baseline = profile
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("baseline tunnel");
    let moved_settings = EngineSettings {
        controller_port: 19_090,
        ..EngineSettings::default()
    };
    let moved = profile
        .project(PROFILE_ID, ProjectionMode::Tunnel, &moved_settings)
        .expect("relocated controller tunnel");
    assert_eq!(
        moved.clash_api().external_controller(),
        "127.0.0.1:19090".to_owned()
    );
    assert_ne!(baseline.as_json(), moved.as_json());
    assert_ne!(
        baseline.configuration_digest(),
        moved.configuration_digest()
    );
    assert_ne!(baseline.digest(), moved.digest());

    for port in [
        0,
        80,
        MIN_CLASH_API_PORT - 1,
        EngineSettings::default().mixed_port,
    ] {
        let settings = EngineSettings {
            controller_port: port,
            ..EngineSettings::default()
        };
        assert_eq!(
            settings.clash_api_endpoint().expect_err("bounded port"),
            ConfigError::InvalidControllerPort(port)
        );
        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            assert_eq!(
                profile
                    .project(PROFILE_ID, mode, &settings)
                    .expect_err("projection refuses an unusable controller port"),
                ConfigError::InvalidControllerPort(port)
            );
        }
    }
}
