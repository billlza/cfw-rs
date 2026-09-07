use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    AuthenticatedDnsServer, CONFIGURATION_IDENTITY_SCHEMA_VERSION, ConfigError, CredentialSlot,
    DEFAULT_CLASH_API_PORT, DirectIpv4HostRoutes, EngineSettings, MIN_CLASH_API_PORT,
    MINIMUM_REMOTE_TLS_VERSION, ProjectionMode, RELEASE_PACKET_TRANSPORT_IPV4,
    ReleaseDnsEvidenceCase, ReleasePacketEvidenceCase, TUNNEL_ADDRESS_PLAN,
    ValidatedSingBoxProfile,
};

const SS_ID: &str = "11111111-1111-4111-8111-111111111111";
const SS_ID_2: &str = "77777777-7777-4777-8777-777777777777";
const VMESS_ID: &str = "22222222-2222-4222-8222-222222222222";
const VLESS_ID: &str = "33333333-3333-4333-8333-333333333333";
const TROJAN_ID: &str = "44444444-4444-4444-8444-444444444444";
const HYSTERIA_ID: &str = "55555555-5555-4555-8555-555555555555";
const HYSTERIA_OBFS_ID: &str = "66666666-6666-4666-8666-666666666666";
const ANYTLS_ID: &str = "88888888-8888-4888-8888-888888888888";
const TUIC_UUID_ID: &str = "99999999-9999-4999-8999-999999999999";
const TUIC_PASSWORD_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab";
const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TunnelAddressPlanContract {
    schema_version: u8,
    ipv4_address: String,
    ipv4_prefix_length: u8,
    ipv4_dns_peer: String,
    ipv6_address: String,
    ipv6_prefix_length: u8,
    ipv6_dns_peer: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EngineOwnerSchemaContract {
    configuration_identity_schema_version: u16,
    engine_owner_schema_version: u16,
}

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
        assert_eq!(server["detour"], "direct");
        assert_eq!(server["path"], "/dns-query");
        assert_eq!(server["tls"]["enabled"], true);
        assert!(server["tls"]["server_name"].is_string());
        assert_eq!(server["tls"]["min_version"], MINIMUM_REMOTE_TLS_VERSION);
    }
    for server in servers {
        assert_ne!(server["server"], TUNNEL_ADDRESS_PLAN.ipv4_dns_peer);
        assert_ne!(server["server"], TUNNEL_ADDRESS_PLAN.ipv6_dns_peer);
    }
    assert_eq!(dns["rules"][0]["ip_accept_any"], true);
    assert_eq!(dns["rules"][0]["server"], "cfw-authenticated-dns-0");
    assert_eq!(
        tunnel_json["route"]["default_domain_resolver"],
        serde_json::json!({
            "server": "cfw-authenticated-dns-0",
            "fallback_server": "cfw-authenticated-dns-1",
        })
    );
    assert!(
        tunnel
            .as_json()
            .contains(r#""rules":[{"action":"hijack-dns","port":53}]"#)
    );
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

#[test]
fn engine_dns_rejects_duplicate_virtual_local_and_disabled_ipv6_endpoints_in_both_modes() {
    let profile = ValidatedSingBoxProfile::direct();
    for endpoints in [
        [
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
        ],
        [
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
        ],
        [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
        ],
    ] {
        let settings = EngineSettings {
            bootstrap_dns_servers: endpoints,
            ..EngineSettings::default()
        };
        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            assert!(profile.project(PROFILE_ID, mode, &settings).is_err());
        }
    }

    let settings = EngineSettings {
        enable_ipv6: false,
        bootstrap_dns_servers: [
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
        ..EngineSettings::default()
    };
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        assert!(profile.project(PROFILE_ID, mode, &settings).is_err());
    }

    let duplicate_authenticated = EngineSettings {
        authenticated_dns_servers: [
            AuthenticatedDnsServer {
                address: IpAddr::V4(Ipv4Addr::new(1, 12, 12, 12)),
                server_name: "doh.pub".to_owned(),
            },
            AuthenticatedDnsServer {
                address: IpAddr::V4(Ipv4Addr::new(1, 12, 12, 12)),
                server_name: "other.example.com".to_owned(),
            },
        ],
        ..EngineSettings::default()
    };
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        assert!(
            profile
                .project(PROFILE_ID, mode, &duplicate_authenticated)
                .is_err()
        );
    }

    let invalid_tls_name = EngineSettings {
        authenticated_dns_servers: [
            AuthenticatedDnsServer {
                address: IpAddr::V4(Ipv4Addr::new(120, 53, 53, 53)),
                server_name: "120.53.53.53".to_owned(),
            },
            EngineSettings::default().authenticated_dns_servers[1].clone(),
        ],
        ..EngineSettings::default()
    };
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        assert!(
            profile
                .project(PROFILE_ID, mode, &invalid_tls_name)
                .is_err()
        );
    }
}

#[test]
fn ordinary_dns_is_authenticated_and_detoured_in_both_modes_while_bootstrap_is_endpoint_only() {
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
        let dns = &config["dns"];
        assert!(
            dns["final"]
                .as_str()
                .is_some_and(|tag| tag.starts_with("cfw-authenticated-dns-"))
        );
        for rule in dns["rules"].as_array().expect("DNS rules") {
            assert!(
                rule["server"]
                    .as_str()
                    .is_some_and(|tag| tag.starts_with("cfw-authenticated-dns-"))
            );
        }
        for key in ["server", "fallback_server"] {
            assert!(
                config["route"]["default_domain_resolver"][key]
                    .as_str()
                    .is_some_and(|tag| tag.starts_with("cfw-authenticated-dns-"))
            );
        }
        for server in dns["servers"].as_array().expect("DNS servers") {
            let tag = server["tag"].as_str().expect("DNS tag");
            if tag.starts_with("cfw-bootstrap-dns-") {
                assert_eq!(server["type"], "udp");
                assert!(server.get("detour").is_none());
            } else {
                assert!(tag.starts_with("cfw-authenticated-dns-"));
                assert_eq!(server["type"], "https");
                assert_eq!(server["detour"], "proxy");
            }
        }
    }
}

#[test]
fn application_injects_a_collision_free_selector_for_implicit_multi_remote_profiles() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[
          {{"type":"shadowsocks","tag":"cfw-proxy-selector","server":"first.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
          {{"type":"shadowsocks","tag":"second","server":"second.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID_2}","kind":"shadowsocks_password"}}}}
        ]}}"#
    ))
    .expect("implicit multi-remote profile");

    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("selector projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected selector JSON");
        let outbounds = config["outbounds"].as_array().expect("runtime outbounds");
        assert_eq!(outbounds.len(), 3);
        assert_eq!(outbounds[2]["type"], "selector");
        assert_eq!(outbounds[2]["tag"], "cfw-proxy-selector-2");
        assert_eq!(
            outbounds[2]["outbounds"],
            serde_json::json!(["cfw-proxy-selector", "second"])
        );
        assert_eq!(outbounds[2]["default"], "cfw-proxy-selector");
        assert_eq!(outbounds[2]["interrupt_exist_connections"], false);
        assert_eq!(config["route"]["final"], "cfw-proxy-selector-2");
        for server in config["dns"]["servers"]
            .as_array()
            .expect("DNS servers")
            .iter()
            .filter(|server| server["type"] == "https")
        {
            assert_eq!(server["detour"], "cfw-proxy-selector-2");
        }
        assert_eq!(projected.credential_slots().len(), 2);
        assert_eq!(
            projected.credential_slots()[0].json_pointer(),
            "/outbounds/0/password"
        );
        assert_eq!(
            projected.credential_slots()[1].json_pointer(),
            "/outbounds/1/password"
        );
    }
}

#[test]
fn explicit_profile_route_is_never_replaced_by_the_application_selector() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[
          {{"type":"shadowsocks","tag":"first","server":"first.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
          {{"type":"shadowsocks","tag":"second","server":"second.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID_2}","kind":"shadowsocks_password"}}}}
        ],"route":{{"final":"second"}}}}"#
    ))
    .expect("explicit multi-remote profile");
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("explicit route projection");
    let config: serde_json::Value =
        serde_json::from_str(projected.as_json()).expect("projected explicit route JSON");
    assert_eq!(config["outbounds"].as_array().expect("outbounds").len(), 2);
    assert_eq!(config["route"]["final"], "second");
    assert!(projected.as_json().contains(r#""detour":"second""#));
    assert!(!projected.as_json().contains(r#""type":"selector""#));
}

#[test]
fn vmess_legacy_protocol_alter_id_reaches_the_runtime_projection() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"vmess","tag":"vmess","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"alter_id":1}}]}}"#
    ))
    .expect("VMess legacy protocol profile");
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("VMess projection");
    let config: serde_json::Value =
        serde_json::from_str(projected.as_json()).expect("projected VMess JSON");
    assert_eq!(config["outbounds"][0]["alter_id"], 1);
}

#[test]
fn vless_raw_packet_encoding_is_distinct_from_an_omitted_field() {
    for (packet_encoding, expected) in [(Some("raw"), Some("")), (None, None)] {
        let packet_encoding = packet_encoding
            .map(|value| format!(r#","packet_encoding":"{value}""#))
            .unwrap_or_default();
        let profile = ValidatedSingBoxProfile::parse(&format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}}{packet_encoding}}}]}}"#
        ))
        .expect("typed VLESS profile");
        let projected = profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("VLESS projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected VLESS JSON");
        let outbound = config["outbounds"][0].as_object().expect("VLESS outbound");

        match expected {
            Some(value) => assert_eq!(
                outbound.get("packet_encoding"),
                Some(&serde_json::Value::String(value.to_owned()))
            ),
            None => assert!(!outbound.contains_key("packet_encoding")),
        }
    }
}

#[test]
fn release_dns_evidence_is_a_closed_udp53_tunnel_projection() {
    let cases = [
        (
            ReleaseDnsEvidenceCase::PrimaryIpv4,
            "34.80.107.183",
            "cfw-release-dns-primary-ipv4",
        ),
        (
            ReleaseDnsEvidenceCase::PrimaryIpv6,
            "2600:1900:4030:5afb:0:1::",
            "cfw-release-dns-primary-ipv6",
        ),
        (
            ReleaseDnsEvidenceCase::SecondaryIpv4,
            "35.200.12.109",
            "cfw-release-dns-secondary-ipv4",
        ),
        (
            ReleaseDnsEvidenceCase::SecondaryIpv6,
            "2600:1900:4050:8de::",
            "cfw-release-dns-secondary-ipv6",
        ),
    ];
    let mut digests = std::collections::BTreeSet::new();
    for (case, address, tag) in cases {
        let profile = ValidatedSingBoxProfile::release_dns_evidence(case);
        assert_eq!(
            profile.as_json(),
            ValidatedSingBoxProfile::direct().as_json()
        );
        assert_eq!(
            profile
                .project(
                    PROFILE_ID,
                    ProjectionMode::SystemProxy,
                    &EngineSettings::default(),
                )
                .expect_err("evidence projection is never a system proxy"),
            ConfigError::InvalidReleaseDnsEvidenceMode
        );
        let projected = profile
            .project(
                PROFILE_ID,
                ProjectionMode::Tunnel,
                &EngineSettings::default(),
            )
            .expect("fixed release DNS projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        let servers = config["dns"]["servers"].as_array().expect("DNS servers");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["type"], "udp");
        assert_eq!(servers[0]["server"], address);
        assert_eq!(servers[0]["server_port"], 53);
        assert_eq!(servers[0]["tag"], tag);
        assert_eq!(servers[0]["detour"], "direct");
        assert!(servers[0].get("path").is_none());
        assert!(servers[0].get("tls").is_none());
        assert_eq!(config["dns"]["rules"][0]["server"], tag);
        assert_eq!(config["dns"]["final"], tag);
        assert_eq!(
            config["route"]["default_domain_resolver"],
            serde_json::json!({ "server": tag })
        );
        assert!(!projected.as_json().contains("cfw-bootstrap-dns"));
        assert!(!projected.as_json().contains("cfw-authenticated-dns"));
        assert!(digests.insert(projected.digest().to_owned()));
    }
    assert_eq!(digests.len(), 4);
}

#[test]
fn release_dns_evidence_rejects_ipv6_disabled_settings_for_every_case() {
    let settings = EngineSettings {
        enable_ipv6: false,
        ..EngineSettings::default()
    };
    for case in [
        ReleaseDnsEvidenceCase::PrimaryIpv4,
        ReleaseDnsEvidenceCase::PrimaryIpv6,
        ReleaseDnsEvidenceCase::SecondaryIpv4,
        ReleaseDnsEvidenceCase::SecondaryIpv6,
    ] {
        assert_eq!(
            ValidatedSingBoxProfile::release_dns_evidence(case)
                .project(PROFILE_ID, ProjectionMode::Tunnel, &settings)
                .expect_err("release DNS evidence keeps the active IPv6 matrix exact"),
            ConfigError::InvalidReleaseDnsEvidenceMode
        );
    }
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
        assert_eq!(outbounds.len(), 8);
        for outbound in outbounds {
            assert_eq!(outbound["domain_resolver"], expected);
        }
    }
}

#[test]
fn every_enabled_remote_tls_projection_has_the_product_tls_floor() {
    let profile = remote_protocol_matrix_profile();
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("remote protocol matrix projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        let tls_outbounds = config["outbounds"]
            .as_array()
            .expect("outbound matrix")
            .iter()
            .filter(|outbound| outbound["tls"]["enabled"] == true)
            .collect::<Vec<_>>();
        assert_eq!(tls_outbounds.len(), 6);
        for outbound in tls_outbounds {
            assert_eq!(
                outbound["tls"]["min_version"], MINIMUM_REMOTE_TLS_VERSION,
                "{} lost the product TLS floor",
                outbound["tag"]
            );
        }
    }
}

#[test]
fn anytls_and_tuic_project_exact_placeholders_and_slots_in_both_modes() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[
          {{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}},"tls":{{"enabled":true,"server_name":"front.example.com","alpn":["h2"],"utls":{{"enabled":true,"fingerprint":"chrome"}}}}}},
          {{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":10443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com","alpn":["h3"]}},"congestion_control":"new_reno","udp_relay_mode":"quic"}}
        ],"route":{{"final":"tuic"}}}}"#
    ))
    .expect("typed AnyTLS/TUIC profile");

    let mut mode_outbounds = Vec::new();
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("AnyTLS/TUIC runtime projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        let outbounds = config["outbounds"].as_array().expect("outbounds");
        assert_eq!(outbounds.len(), 2);
        assert_eq!(outbounds[0]["type"], "anytls");
        assert_eq!(outbounds[0]["password"], "");
        assert_eq!(outbounds[0]["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(
            outbounds[0]["tls"]["min_version"],
            MINIMUM_REMOTE_TLS_VERSION
        );
        assert!(outbounds[0].get("credential_ref").is_none());
        assert_eq!(outbounds[1]["type"], "tuic");
        assert_eq!(outbounds[1]["uuid"], "");
        assert_eq!(outbounds[1]["password"], "");
        assert_eq!(outbounds[1]["congestion_control"], "new_reno");
        assert_eq!(outbounds[1]["udp_relay_mode"], "quic");
        assert_eq!(outbounds[1]["zero_rtt_handshake"], false);
        assert_eq!(
            outbounds[1]["tls"]["min_version"],
            MINIMUM_REMOTE_TLS_VERSION
        );
        assert!(outbounds[1].get("uuid_credential_ref").is_none());
        assert!(outbounds[1].get("password_credential_ref").is_none());

        assert_eq!(projected.credential_slots().len(), 3);
        let slots = projected.credential_slots();
        assert_eq!(slots[0].reference().id(), ANYTLS_ID);
        assert_eq!(slots[0].json_pointer(), "/outbounds/0/password");
        assert_eq!(slots[1].reference().id(), TUIC_UUID_ID);
        assert_eq!(slots[1].json_pointer(), "/outbounds/1/uuid");
        assert_eq!(slots[2].reference().id(), TUIC_PASSWORD_ID);
        assert_eq!(slots[2].json_pointer(), "/outbounds/1/password");
        assert_eq!(
            serde_json::to_value(&slots[0]).unwrap()["target"],
            "anytls_password"
        );
        assert_eq!(
            serde_json::to_value(&slots[1]).unwrap()["target"],
            "tuic_uuid"
        );
        assert_eq!(
            serde_json::to_value(&slots[2]).unwrap()["target"],
            "tuic_password"
        );
        mode_outbounds.push(outbounds.clone());
    }
    assert_eq!(mode_outbounds[0], mode_outbounds[1]);
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

#[test]
fn remote_projection_contains_only_empty_placeholders_and_closed_slots() {
    let profile = shadowsocks_profile(SS_ID);
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("Shadowsocks tunnel template");
    let template: serde_json::Value =
        serde_json::from_str(projected.as_json()).expect("template JSON");
    assert_eq!(template["outbounds"][0]["password"], "");
    assert!(template.pointer("/outbounds/0/credential_ref").is_none());
    assert_eq!(projected.credential_slots().len(), 1);
    let slot = &projected.credential_slots()[0];
    assert_eq!(slot.reference().id(), SS_ID);
    assert_eq!(slot.json_pointer(), "/outbounds/0/password");

    let wire = serde_json::to_value(slot).expect("slot wire");
    assert_eq!(wire["target"], "shadowsocks_password");
    assert_eq!(
        serde_json::from_value::<CredentialSlot>(wire).expect("round trip"),
        *slot
    );
    assert!(!format!("{projected:?}").contains(projected.as_json()));
}

#[test]
fn credential_reference_changes_runtime_identity_without_changing_template_bytes() {
    let first = shadowsocks_profile(SS_ID)
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("first template");
    let second = shadowsocks_profile(SS_ID_2)
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("second template");
    assert_eq!(first.as_json(), second.as_json());
    assert_eq!(first.configuration_digest(), second.configuration_digest());
    assert_ne!(first.credential_slots(), second.credential_slots());
    assert_ne!(first.digest(), second.digest());
}

#[test]
fn slot_deserialization_rejects_pointer_kind_and_unknown_field_tampering() {
    let projected = shadowsocks_profile(SS_ID)
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("template");
    let slot = &projected.credential_slots()[0];
    let mut pointer = serde_json::to_value(slot).expect("slot");
    pointer["json_pointer"] = serde_json::Value::String("/outbounds/0/uuid".into());
    assert!(serde_json::from_value::<CredentialSlot>(pointer).is_err());

    let mut kind = serde_json::to_value(slot).expect("slot");
    kind["target"] = serde_json::Value::String("vmess_uuid".into());
    assert!(serde_json::from_value::<CredentialSlot>(kind).is_err());

    let mut unknown = serde_json::to_value(slot).expect("slot");
    unknown["secret"] = serde_json::Value::String("must-not-be-accepted".into());
    assert!(serde_json::from_value::<CredentialSlot>(unknown).is_err());
}

#[test]
fn tunnel_identity_binds_os_network_options_beyond_config_json() {
    let profile = ValidatedSingBoxProfile::direct();
    let baseline_settings = EngineSettings::default();
    let baseline = profile
        .project(PROFILE_ID, ProjectionMode::Tunnel, &baseline_settings)
        .expect("baseline tunnel");

    let mtu_settings = EngineSettings {
        tunnel_mtu: 1_400,
        ..baseline_settings.clone()
    };
    let mtu_changed = profile
        .project(PROFILE_ID, ProjectionMode::Tunnel, &mtu_settings)
        .expect("MTU tunnel");
    assert_ne!(baseline.as_json(), mtu_changed.as_json());
    assert_ne!(
        baseline.configuration_digest(),
        mtu_changed.configuration_digest()
    );
    assert_ne!(baseline.digest(), mtu_changed.digest());

    let bypass_settings = EngineSettings {
        bypass_private_networks: false,
        ..baseline_settings
    };
    let bypass_changed = profile
        .project(PROFILE_ID, ProjectionMode::Tunnel, &bypass_settings)
        .expect("captured private networks tunnel");
    assert_eq!(baseline.as_json(), bypass_changed.as_json());
    assert_eq!(
        baseline.configuration_digest(),
        bypass_changed.configuration_digest()
    );
    assert_ne!(baseline.digest(), bypass_changed.digest());
}

#[test]
fn release_packet_direct_host_route_is_closed_source_owned_and_identity_bound() {
    assert_eq!(
        ValidatedSingBoxProfile::parse(
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"direct_ipv4_hosts":["35.194.216.98"]}"#,
        )
        .expect_err("an imported profile cannot request a host route"),
        ConfigError::UnsupportedTopLevelKey("direct_ipv4_hosts".to_owned())
    );

    let ordinary = ValidatedSingBoxProfile::direct()
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("ordinary tunnel");
    assert!(ordinary.direct_ipv4_hosts().is_empty());

    let included =
        ValidatedSingBoxProfile::release_packet_evidence(ReleasePacketEvidenceCase::IncludedRoutes)
            .project(
                PROFILE_ID,
                ProjectionMode::Tunnel,
                &EngineSettings::default(),
            )
            .expect("included-routes projection");
    let excluded =
        ValidatedSingBoxProfile::release_packet_evidence(ReleasePacketEvidenceCase::ExcludedRoutes)
            .project(
                PROFILE_ID,
                ProjectionMode::Tunnel,
                &EngineSettings::default(),
            )
            .expect("excluded-routes projection");

    assert!(included.direct_ipv4_hosts().is_empty());
    assert_eq!(
        excluded.direct_ipv4_hosts().as_slice(),
        &[RELEASE_PACKET_TRANSPORT_IPV4]
    );
    assert_eq!(included.as_json(), excluded.as_json());
    assert_eq!(
        included.configuration_digest(),
        excluded.configuration_digest()
    );
    assert_ne!(included.digest(), excluded.digest());

    for case in ReleasePacketEvidenceCase::ALL {
        let projected = ValidatedSingBoxProfile::release_packet_evidence(case)
            .project(
                PROFILE_ID,
                ProjectionMode::Tunnel,
                &EngineSettings::default(),
            )
            .expect("fixed Packet projection");
        assert_eq!(
            projected.direct_ipv4_hosts().is_empty(),
            case != ReleasePacketEvidenceCase::ExcludedRoutes
        );
    }

    assert_eq!(
        ValidatedSingBoxProfile::release_packet_evidence(ReleasePacketEvidenceCase::ExcludedRoutes)
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect_err("Packet evidence cannot project into System Proxy"),
        ConfigError::InvalidReleasePacketEvidenceMode
    );
}

#[test]
fn direct_ipv4_host_route_wire_value_rejects_duplicates_and_noncanonical_inputs() {
    let empty: DirectIpv4HostRoutes = serde_json::from_str("[]").expect("empty route set");
    assert!(empty.is_empty());
    let exact: DirectIpv4HostRoutes =
        serde_json::from_str(r#"["35.194.216.98"]"#).expect("exact route set");
    assert_eq!(exact.as_slice(), &[RELEASE_PACKET_TRANSPORT_IPV4]);
    assert_eq!(
        serde_json::to_string(&exact).expect("canonical routes"),
        r#"["35.194.216.98"]"#
    );

    for invalid in [
        r#"["35.194.216.98","35.194.216.98"]"#,
        r#"["035.194.216.98"]"#,
        r#"["35.194.216.99"]"#,
        r#"["35.194.216.98","1.1.1.1"]"#,
    ] {
        assert!(
            serde_json::from_str::<DirectIpv4HostRoutes>(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn hysteria2_port_hopping_projects_to_pinned_sing_box_fields() {
    let profile = ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,"server_ports":["443","5000:5002"],"hop_interval_seconds":30,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}}}}]}}"#
    ))
    .expect("Hysteria2 hopping profile");

    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("Hysteria2 hopping projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("runtime JSON");
        let hysteria2 = config["outbounds"]
            .as_array()
            .expect("runtime outbounds")
            .iter()
            .find(|outbound| outbound["type"] == "hysteria2")
            .expect("runtime Hysteria2");
        assert_eq!(
            hysteria2["server_ports"],
            serde_json::json!(["443:443", "5000:5002"])
        );
        assert_eq!(hysteria2["hop_interval"], "30s");
        assert_eq!(hysteria2["password"], "");
    }
}

#[test]
fn rust_tunnel_address_plan_matches_the_cross_language_contract() {
    let contract: TunnelAddressPlanContract = serde_json::from_str(include_str!(
        "../../../../contracts/tunnel-address-plan-v1.json"
    ))
    .expect("canonical tunnel address plan");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.ipv4_address, TUNNEL_ADDRESS_PLAN.ipv4_address);
    assert_eq!(
        contract.ipv4_prefix_length,
        TUNNEL_ADDRESS_PLAN.ipv4_prefix_length
    );
    assert_eq!(contract.ipv4_dns_peer, TUNNEL_ADDRESS_PLAN.ipv4_dns_peer);
    assert_eq!(contract.ipv6_address, TUNNEL_ADDRESS_PLAN.ipv6_address);
    assert_eq!(
        contract.ipv6_prefix_length,
        TUNNEL_ADDRESS_PLAN.ipv6_prefix_length
    );
    assert_eq!(contract.ipv6_dns_peer, TUNNEL_ADDRESS_PLAN.ipv6_dns_peer);
}

#[test]
fn configuration_identity_schema_matches_the_engine_owner_contract() {
    let contract: EngineOwnerSchemaContract = serde_json::from_str(include_str!(
        "../../../../contracts/engine-owner-v6/schema-policy.json"
    ))
    .expect("engine owner schema contract");
    assert_eq!(
        contract.configuration_identity_schema_version,
        CONFIGURATION_IDENTITY_SCHEMA_VERSION
    );
    assert_eq!(contract.engine_owner_schema_version, 6);

    let projected = ValidatedSingBoxProfile::direct()
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("direct projection");
    let identity = crate::validation::canonicalize(serde_json::json!({
        "configuration_sha256": projected.configuration_digest(),
        "credential_audience": projected.credential_audience(),
        "credential_slots": projected.credential_slots(),
        "mode": "system_proxy",
        "network_options": null,
        "schema_version": CONFIGURATION_IDENTITY_SCHEMA_VERSION,
    }));
    let expected = crate::sha256_hex(
        serde_json::to_string(&identity)
            .expect("configuration identity JSON")
            .as_bytes(),
    );
    assert_eq!(projected.digest(), expected);
}

fn shadowsocks_profile(credential_id: &str) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"ss.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{credential_id}","kind":"shadowsocks_password"}}}}],"route":{{"final":"proxy"}}}}"#
    ))
    .expect("typed Shadowsocks profile")
}

fn remote_protocol_matrix_profile() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{
          "outbounds": [
            {{"type":"socks5","tag":"socks5","server":"socks5.example.com","server_port":1080}},
            {{"type":"shadowsocks","tag":"ss","server":"ss.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
            {{"type":"vmess","tag":"vmess","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"security":"auto","tls":{{"enabled":true,"server_name":"vmess.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}}}},"transport":{{"type":"ws","path":"/ws","headers":{{"Host":"vmess.example.com"}}}}}},
            {{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"flow":"xtls-rprx-vision","tls":{{"enabled":true,"server_name":"www.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}}}}},
            {{"type":"trojan","tag":"trojan","server":"trojan.example.com","server_port":443,"credential_ref":{{"id":"{TROJAN_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"trojan.example.com"}},"transport":{{"type":"grpc","service_name":"tunnel"}}}},
            {{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}},"up_mbps":100,"down_mbps":200,"obfs":{{"type":"salamander","credential_ref":{{"id":"{HYSTERIA_OBFS_ID}","kind":"hysteria2_obfs_password"}}}}}},
            {{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}},"tls":{{"enabled":true,"server_name":"anytls.example.com"}}}},
            {{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com"}},"congestion_control":"bbr","udp_relay_mode":"native"}}
          ],
          "route": {{"final":"ss"}}
        }}"#
    ))
    .expect("typed remote protocol matrix")
}
