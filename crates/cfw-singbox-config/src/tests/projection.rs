use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    AuthenticatedDnsServer, ConfigError, CredentialSlot, DEFAULT_CLASH_API_PORT, EngineSettings,
    MIN_CLASH_API_PORT, ProjectionMode, TUNNEL_ADDRESS_PLAN, ValidatedSingBoxProfile,
};

const SS_ID: &str = "11111111-1111-4111-8111-111111111111";
const SS_ID_2: &str = "77777777-7777-4777-8777-777777777777";
const VMESS_ID: &str = "22222222-2222-4222-8222-222222222222";
const VLESS_ID: &str = "33333333-3333-4333-8333-333333333333";
const TROJAN_ID: &str = "44444444-4444-4444-8444-444444444444";
const HYSTERIA_ID: &str = "55555555-5555-4555-8555-555555555555";
const HYSTERIA_OBFS_ID: &str = "66666666-6666-4666-8666-666666666666";

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

#[test]
fn projections_have_exactly_one_application_owned_inbound() {
    let profile = ValidatedSingBoxProfile::direct();
    let proxy = profile
        .project(ProjectionMode::SystemProxy, &EngineSettings::default())
        .expect("proxy config");
    let tunnel = profile
        .project(ProjectionMode::Tunnel, &EngineSettings::default())
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
        let projected = profile.project(mode, &settings).expect("projection");
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
        .project(ProjectionMode::Tunnel, &EngineSettings::default())
        .expect("baseline tunnel");
    let moved_settings = EngineSettings {
        controller_port: 19_090,
        ..EngineSettings::default()
    };
    let moved = profile
        .project(ProjectionMode::Tunnel, &moved_settings)
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
                    .project(mode, &settings)
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
            assert!(profile.project(mode, &settings).is_err());
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
        assert!(profile.project(mode, &settings).is_err());
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
        assert!(profile.project(mode, &duplicate_authenticated).is_err());
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
        assert!(profile.project(mode, &invalid_tls_name).is_err());
    }
}

#[test]
fn ordinary_dns_is_authenticated_and_detoured_in_both_modes_while_bootstrap_is_endpoint_only() {
    let profile = shadowsocks_profile(SS_ID);
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(mode, &EngineSettings::default())
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
fn domain_named_proxy_endpoint_uses_the_bounded_bootstrap_pair_in_both_modes() {
    let profile = shadowsocks_profile(SS_ID);
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(mode, &EngineSettings::default())
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
            .project(mode, &EngineSettings::default())
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
            .project(mode, &EngineSettings::default())
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
            .project(mode, &EngineSettings::default())
            .expect("remote protocol matrix projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        let outbounds = config["outbounds"].as_array().expect("outbound matrix");
        assert_eq!(outbounds.len(), 5);
        for outbound in outbounds {
            assert_eq!(outbound["domain_resolver"], expected);
        }
    }
}

#[test]
fn tunnel_identity_binds_configured_numeric_bootstrap_dns() {
    let profile = ValidatedSingBoxProfile::direct();
    let baseline = profile
        .project(ProjectionMode::Tunnel, &EngineSettings::default())
        .expect("baseline tunnel");
    let changed = profile
        .project(
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
        .project(ProjectionMode::Tunnel, &EngineSettings::default())
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
        .project(ProjectionMode::SystemProxy, &EngineSettings::default())
        .expect("first template");
    let second = shadowsocks_profile(SS_ID_2)
        .project(ProjectionMode::SystemProxy, &EngineSettings::default())
        .expect("second template");
    assert_eq!(first.as_json(), second.as_json());
    assert_eq!(first.configuration_digest(), second.configuration_digest());
    assert_ne!(first.credential_slots(), second.credential_slots());
    assert_ne!(first.digest(), second.digest());
}

#[test]
fn slot_deserialization_rejects_pointer_kind_and_unknown_field_tampering() {
    let projected = shadowsocks_profile(SS_ID)
        .project(ProjectionMode::SystemProxy, &EngineSettings::default())
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
        .project(ProjectionMode::Tunnel, &baseline_settings)
        .expect("baseline tunnel");

    let mtu_settings = EngineSettings {
        tunnel_mtu: 1_400,
        ..baseline_settings.clone()
    };
    let mtu_changed = profile
        .project(ProjectionMode::Tunnel, &mtu_settings)
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
        .project(ProjectionMode::Tunnel, &bypass_settings)
        .expect("captured private networks tunnel");
    assert_eq!(baseline.as_json(), bypass_changed.as_json());
    assert_eq!(
        baseline.configuration_digest(),
        bypass_changed.configuration_digest()
    );
    assert_ne!(baseline.digest(), bypass_changed.digest());
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
            {{"type":"shadowsocks","tag":"ss","server":"ss.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
            {{"type":"vmess","tag":"vmess","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"security":"auto","tls":{{"enabled":true,"server_name":"vmess.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}}}},"transport":{{"type":"ws","path":"/ws","headers":{{"Host":"vmess.example.com"}}}}}},
            {{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"flow":"xtls-rprx-vision","tls":{{"enabled":true,"server_name":"www.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}}}}},
            {{"type":"trojan","tag":"trojan","server":"trojan.example.com","server_port":443,"credential_ref":{{"id":"{TROJAN_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"trojan.example.com"}},"transport":{{"type":"grpc","service_name":"tunnel"}}}},
            {{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}},"up_mbps":100,"down_mbps":200,"obfs":{{"type":"salamander","credential_ref":{{"id":"{HYSTERIA_OBFS_ID}","kind":"hysteria2_obfs_password"}}}}}}
          ],
          "route": {{"final":"ss"}}
        }}"#
    ))
    .expect("typed remote protocol matrix")
}
