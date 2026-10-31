use super::*;
use cfw_engine_api::TunnelNetworkOptions;
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
fn input(mode: ProjectionMode, lan: bool, credentials: bool) -> EngineStartRequest {
    let source = if credentials {
        r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#
    } else {
        r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#
    };
    let settings = EngineSettings {
        lan_proxy: lan.then(|| LanProxySettings {
            listen: Ipv4Addr::UNSPECIFIED,
            port: 8081,
            allowed_source_cidrs: vec!["192.168.42.0/24".into()],
        }),
        ..EngineSettings::default()
    };
    let projection = ValidatedSingBoxProfile::parse(source)
        .unwrap()
        .project(PROFILE, mode, &settings)
        .unwrap();
    EngineStartRequest {
        context: EngineCommandContext {
            installation_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            config_epoch: 3,
            generation: 7,
        },
        mode,
        credential_audience: projection.credential_audience().clone(),
        config_json: projection.as_json().into(),
        config_content_digest: projection.configuration_digest().into(),
        config_digest: projection.digest().into(),
        credential_slots: projection.credential_slots().to_vec(),
        tunnel_options: mode.has_tunnel().then_some(TunnelNetworkOptions {
            ipv6_enabled: settings.enable_ipv6,
            bypass_private_networks: settings.bypass_private_networks,
            direct_ipv4_hosts: projection.direct_ipv4_hosts(),
            mtu: settings.tunnel_mtu,
            system_proxy_port: (mode == ProjectionMode::TunnelSystemProxy)
                .then_some(settings.mixed_port),
        }),
    }
}
fn rehash(request: &mut EngineStartRequest) {
    request.config_content_digest = sha256_hex(request.config_json.as_bytes());
    request.config_digest = configuration_identity_digest(
        &request.config_content_digest,
        &request.credential_audience,
        &request.credential_slots,
        request.mode,
        &request.tunnel_options,
    )
    .unwrap();
}
fn edit(request: &mut EngineStartRequest, action: impl FnOnce(&mut Value)) {
    let mut document: Value = serde_json::from_str(&request.config_json).unwrap();
    action(&mut document);
    request.config_json =
        serde_json::to_string(&canonicalize_configuration_value(document)).unwrap();
    rehash(request);
}

#[test]
fn proxy_resource_scope_rejects_system_interfaces_and_extra_services() {
    for mode in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy] {
        for change in 0..5 {
            let mut value = input(mode, false, false);
            edit(&mut value, |root| match change {
                0 => {
                    root["endpoints"] =
                        serde_json::json!([{"type":"wireguard","tag":"foreign","system":true}])
                }
                1 => root["endpoints"] = serde_json::json!([{"type":"tailscale","tag":"foreign"}]),
                2 => root["services"] = serde_json::json!([{"type":"resolved","tag":"foreign"}]),
                3 => {
                    root["experimental"]["v2ray_api"] =
                        serde_json::json!({"listen":"0.0.0.0:10085"})
                }
                4 => {
                    root["outbounds"] = serde_json::json!([{"type":"wireguard","tag":"foreign","system_interface":true}])
                }
                _ => unreachable!(),
            });
            assert!(
                CheckedStartConfiguration::new(value).is_err(),
                "{mode:?} change {change}"
            );
        }
    }
}

#[test]
fn proxy_resource_scope_preserves_projected_userspace_wireguard() {
    let profile = ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"wireguard","tag":"wg","server":"vpn.example.com","server_port":51820,"local_addresses":["10.10.0.2/32"],"mtu":1420,"persistent_keepalive_seconds":25,"peer_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","private_key_credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"wireguard_private_key"}}]}"#).unwrap();
    for mode in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy] {
        let projection = profile
            .project(PROFILE, mode, &EngineSettings::default())
            .unwrap();
        let mut request = input(mode, false, false);
        request.config_json = projection.as_json().into();
        request.credential_audience = projection.credential_audience().clone();
        request.credential_slots = projection.credential_slots().to_vec();
        rehash(&mut request);
        let checked = CheckedStartConfiguration::new(request).unwrap();
        let references = checked.credential_references();
        let prepared = checked
            .prepare_proxy(
                references
                    .iter()
                    .map(|reference| (reference, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")),
            )
            .unwrap();
        assert_eq!(prepared.mode(), mode);
    }
}

#[test]
fn shared_request_keeps_exact_bytes_identity_and_separate_lan_endpoint() {
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        for lan in [false, true] {
            let request = input(mode, lan, false);
            let expected: Value = serde_json::from_str(&request.config_json).unwrap();
            let identity = request.config_digest.clone();
            let content = request.config_content_digest.clone();
            let checked = CheckedStartConfiguration::new(request).unwrap();
            let resolved = checked.resolve([]).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&resolved.bytes).unwrap(),
                expected
            );
            assert_eq!(resolved.digest(), identity);
            if mode.has_tunnel() {
                assert!(checked.prepare_proxy([]).is_err());
            } else {
                let prepared = checked.prepare_proxy([]).unwrap();
                assert_eq!(prepared.digest(), identity);
                assert_eq!(prepared.configuration_digest(), content);
                assert_eq!(prepared.listeners.len(), if lan { 3 } else { 2 });
                assert_eq!(
                    prepared.system_proxy_endpoint(),
                    (mode == ProjectionMode::SystemProxy)
                        .then(|| "127.0.0.1:7890".parse().unwrap())
                );
            }
        }
    }
}

#[test]
fn context_modes_and_both_digest_domains_are_checked_before_resolution() {
    let base = input(ProjectionMode::SystemProxy, false, false);
    for change in 0..7 {
        let mut value = base.clone();
        match change {
            0 => value.context.installation_id = uuid::Uuid::nil().to_string(),
            1 => value.context.config_epoch = 0,
            2 => value.context.generation = 0,
            3 => value.config_content_digest = "0".repeat(64),
            4 => value.config_digest = "0".repeat(64),
            5 => value.mode = ProjectionMode::LocalProxy,
            6 => value.tunnel_options = input(ProjectionMode::Tunnel, false, false).tunnel_options,
            _ => unreachable!(),
        }
        assert!(CheckedStartConfiguration::new(value).is_err());
    }
}

#[test]
fn self_consistent_hashes_cannot_authorize_foreign_listeners_or_lan_policy() {
    for change in 0..7 {
        let mut value = input(ProjectionMode::SystemProxy, true, false);
        edit(&mut value, |root| match change {
            0 => root["inbounds"][0]["type"] = "tun".into(),
            1 => root["inbounds"][0]["set_system_proxy"] = true.into(),
            2 => root["experimental"]["clash_api"]["external_controller"] = "0.0.0.0:9090".into(),
            3 => root["experimental"]["clash_api"]["secret"] = "".into(),
            4 => root["route"]["rules"][0]["rules"][1]["invert"] = false.into(),
            5 => root["inbounds"][1]["listen_port"] = 7890.into(),
            6 => root["inbounds"][0]["tag"] = "unowned-listener".into(),
            _ => unreachable!(),
        });
        assert!(CheckedStartConfiguration::new(value).is_err());
    }
}

#[test]
fn duplicate_keys_and_noncanonical_templates_never_become_checked_input() {
    let mut value = input(ProjectionMode::LocalProxy, false, false);
    value.config_json.insert_str(1, "\"inbounds\":[],");
    rehash(&mut value);
    assert!(CheckedStartConfiguration::new(value).is_err());
    let mut value = input(ProjectionMode::LocalProxy, false, false);
    value.config_json.push(' ');
    rehash(&mut value);
    assert!(CheckedStartConfiguration::new(value).is_err());
}

#[test]
fn shared_credential_slots_require_exact_placeholders_audience_and_material() {
    let original = input(ProjectionMode::SystemProxy, true, true);
    let reference = original.credential_slots[0].reference().clone();
    let pointer = original.credential_slots[0].json_pointer().to_owned();
    let checked = CheckedStartConfiguration::new(original.clone()).unwrap();
    assert!(checked.resolve([]).is_err());
    assert!(
        checked
            .resolve([
                (&reference, "fixture-secret"),
                (&reference, "fixture-secret")
            ])
            .is_err()
    );
    let material = checked.resolve([(&reference, "fixture-secret")]).unwrap();
    let actual: Value = serde_json::from_slice(&material.bytes).unwrap();
    assert_eq!(actual.pointer(&pointer).unwrap(), "fixture-secret");
    assert_eq!(material.digest(), original.config_digest);
    let mut duplicate = original.clone();
    duplicate
        .credential_slots
        .push(duplicate.credential_slots[0].clone());
    rehash(&mut duplicate);
    assert!(CheckedStartConfiguration::new(duplicate).is_err());
    let mut populated = original.clone();
    edit(&mut populated, |root| {
        *root.pointer_mut(&pointer).unwrap() = "already-populated".into()
    });
    assert!(CheckedStartConfiguration::new(populated).is_err());
    let mut audience = original;
    audience.credential_audience =
        CredentialAudience::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "a".repeat(64)).unwrap();
    assert!(CheckedStartConfiguration::new(audience).is_err());
}

fn projected_request(
    source: &str,
    mode: ProjectionMode,
    settings: &EngineSettings,
    stack: cfw_singbox_config::TunnelStack,
) -> EngineStartRequest {
    let projection = ValidatedSingBoxProfile::parse(source)
        .unwrap()
        .project_with_tunnel_stack(PROFILE, mode, settings, stack)
        .unwrap();
    EngineStartRequest {
        context: EngineCommandContext {
            installation_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            config_epoch: 3,
            generation: 7,
        },
        mode,
        credential_audience: projection.credential_audience().clone(),
        config_json: projection.as_json().into(),
        config_content_digest: projection.configuration_digest().into(),
        config_digest: projection.digest().into(),
        credential_slots: projection.credential_slots().to_vec(),
        tunnel_options: mode.has_tunnel().then_some(TunnelNetworkOptions {
            ipv6_enabled: settings.enable_ipv6,
            bypass_private_networks: settings.bypass_private_networks,
            direct_ipv4_hosts: projection.direct_ipv4_hosts(),
            mtu: settings.tunnel_mtu,
            system_proxy_port: (mode == ProjectionMode::TunnelSystemProxy)
                .then_some(settings.mixed_port),
        }),
    }
}

const MAINLAND_SOURCE: &str = r#"{"outbounds":[{"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080}]}"#;

#[test]
fn proxy_admission_keeps_the_projected_routing_cache() {
    // Mainland China direct projects rule sets and their private routing
    // cache. The Windows boundary previously rejected this GA projection.
    let settings = EngineSettings {
        mainland_china_direct: true,
        ..EngineSettings::default()
    };
    for mode in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy] {
        let request = projected_request(
            MAINLAND_SOURCE,
            mode,
            &settings,
            cfw_singbox_config::TunnelStack::Gvisor,
        );
        let document: Value = serde_json::from_str(&request.config_json).unwrap();
        assert_eq!(
            document["experimental"]["cache_file"],
            serde_json::json!({"cache_id":PROFILE,"enabled":true,"path":"routing-cache.db"}),
            "{mode:?} fixture no longer exercises the projected cache"
        );
        let checked = CheckedStartConfiguration::new(request).unwrap();
        let prepared = checked.prepare_proxy([]).unwrap();
        assert_eq!(prepared.mode(), mode);
    }
}

#[test]
fn proxy_routing_cache_cannot_leave_the_projected_shape() {
    let settings = EngineSettings {
        mainland_china_direct: true,
        ..EngineSettings::default()
    };
    for change in 0..6 {
        let mut value = projected_request(
            MAINLAND_SOURCE,
            ProjectionMode::SystemProxy,
            &settings,
            cfw_singbox_config::TunnelStack::Gvisor,
        );
        edit(&mut value, |root| {
            let cache = &mut root["experimental"]["cache_file"];
            match change {
                0 => cache["path"] = r"C:\ProgramData\foreign.db".into(),
                1 => cache["path"] = "../routing-cache.db".into(),
                2 => cache["cache_id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
                3 => cache["store_fakeip"] = true.into(),
                4 => cache["enabled"] = false.into(),
                5 => cache["store_rdrc"] = true.into(),
                _ => unreachable!(),
            }
        });
        assert!(
            CheckedStartConfiguration::new(value).is_err(),
            "routing cache change {change}"
        );
    }
}

fn tunnel_request(settings: &EngineSettings) -> EngineStartRequest {
    projected_request(
        MAINLAND_SOURCE,
        ProjectionMode::Tunnel,
        settings,
        cfw_singbox_config::TunnelStack::Gvisor,
    )
}

#[test]
fn tunnel_data_plane_admits_only_the_exact_packet_fed_projection() {
    let fake_ip = serde_json::json!({"outbounds":[{"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080}],
        "dns":{"servers":[{"type":"udp","server":"1.1.1.1","server_port":53}],"fake_ip":{"exclude":["+.lan"]}}})
    .to_string();
    for (case, mtu, ipv6, lan, mainland, leak, source) in [
        (0, 1280, false, false, false, false, MAINLAND_SOURCE),
        (1, 1500, true, true, false, true, MAINLAND_SOURCE),
        (2, 9000, true, false, true, false, MAINLAND_SOURCE),
        (3, 1500, true, true, true, true, fake_ip.as_str()),
    ] {
        let settings = EngineSettings {
            tunnel_mtu: mtu,
            enable_ipv6: ipv6,
            mainland_china_direct: mainland,
            dns_leak_protection: leak,
            lan_proxy: lan.then(|| LanProxySettings {
                listen: Ipv4Addr::UNSPECIFIED,
                port: 8081,
                allowed_source_cidrs: vec!["192.168.42.0/24".into()],
            }),
            ..EngineSettings::default()
        };
        let request = projected_request(
            source,
            ProjectionMode::Tunnel,
            &settings,
            cfw_singbox_config::TunnelStack::Gvisor,
        );
        let identity = request.config_digest.clone();
        let document: Value = serde_json::from_str(&request.config_json).unwrap();
        if case == 3 {
            assert_eq!(document["experimental"]["cache_file"]["store_fakeip"], true);
        }
        // DNS leak protection follows the LAN access rule and the port 53
        // hijack, so the LAN listener's first-rule admission is unchanged.
        assert_eq!(
            document["route"]["rules"][usize::from(lan) + 1]
                == serde_json::json!({"port":853,"action":"reject"}),
            leak,
            "case {case}"
        );
        let prepared = CheckedStartConfiguration::new(request)
            .unwrap()
            .prepare_tunnel_data_plane([])
            .unwrap();
        assert_eq!(prepared.mode(), ProjectionMode::Tunnel, "case {case}");
        assert_eq!(prepared.tunnel_mtu(), Some(mtu), "case {case}");
        assert_eq!(prepared.digest(), identity, "case {case}");
        assert_eq!(prepared.system_proxy_endpoint(), None, "case {case}");
        let mut expected = vec![SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            settings.controller_port,
        ))];
        if lan {
            expected.push(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8081)));
        }
        assert_eq!(prepared.listeners, expected, "case {case}");
    }
}

#[test]
fn tunnel_data_plane_requires_outbound_binding_to_the_physical_interface() {
    let settings = EngineSettings::default();
    let document: Value = serde_json::from_str(&tunnel_request(&settings).config_json).unwrap();
    assert_eq!(document["route"]["auto_detect_interface"], true);
    for change in 0..3 {
        let mut value = tunnel_request(&settings);
        edit(&mut value, |root| match change {
            0 => {
                root["route"]
                    .as_object_mut()
                    .unwrap()
                    .remove("auto_detect_interface");
            }
            1 => root["route"]["auto_detect_interface"] = false.into(),
            2 => root["route"]["auto_detect_interface"] = "true".into(),
            _ => unreachable!(),
        });
        assert!(
            CheckedStartConfiguration::new(value)
                .unwrap()
                .prepare_tunnel_data_plane([])
                .is_err(),
            "change {change}"
        );
    }
}

#[test]
fn tunnel_data_plane_rejects_other_modes_and_the_system_stack() {
    let settings = EngineSettings::default();
    for (mode, stack) in [
        (
            ProjectionMode::LocalProxy,
            cfw_singbox_config::TunnelStack::Gvisor,
        ),
        (
            ProjectionMode::SystemProxy,
            cfw_singbox_config::TunnelStack::Gvisor,
        ),
        (
            ProjectionMode::TunnelSystemProxy,
            cfw_singbox_config::TunnelStack::Gvisor,
        ),
        (
            ProjectionMode::Tunnel,
            cfw_singbox_config::TunnelStack::System,
        ),
    ] {
        let checked = CheckedStartConfiguration::new(projected_request(
            MAINLAND_SOURCE,
            mode,
            &settings,
            stack,
        ))
        .unwrap();
        assert!(
            checked.prepare_tunnel_data_plane([]).is_err(),
            "{mode:?} {stack:?} became a packet-fed Tunnel data plane"
        );
    }
}

#[test]
fn tunnel_data_plane_cannot_request_unowned_interfaces_or_drift_from_its_options() {
    let settings = EngineSettings {
        lan_proxy: Some(LanProxySettings {
            listen: Ipv4Addr::UNSPECIFIED,
            port: 8081,
            allowed_source_cidrs: vec!["192.168.42.0/24".into()],
        }),
        ..EngineSettings::default()
    };
    for change in 0..12 {
        let mut value = tunnel_request(&settings);
        if change == 11 {
            // A self-consistent identity cannot move the options away from the
            // interface the template actually configures.
            value.tunnel_options.as_mut().unwrap().mtu = 9000;
            rehash(&mut value);
        } else {
            edit(&mut value, |root| {
                let tun = &mut root["inbounds"][0];
                assert_eq!(tun["tag"], "cfw-tunnel");
                match change {
                    0 => tun["auto_route"] = true.into(),
                    1 => tun["stack"] = "system".into(),
                    2 => tun["mtu"] = 9000.into(),
                    3 => tun["strict_route"] = true.into(),
                    4 => tun["auto_redirect"] = true.into(),
                    5 => tun["address"] = serde_json::json!(["10.0.0.1/30"]),
                    6 => tun["listen"] = "127.0.0.1".into(),
                    7 => tun["tag"] = "foreign-tunnel".into(),
                    8 => {
                        let second = tun.clone();
                        root["inbounds"].as_array_mut().unwrap().push(second);
                    }
                    9 => root["inbounds"].as_array_mut().unwrap().push(serde_json::json!(
                        {"type":"mixed","tag":"cfw-system-proxy","listen":"127.0.0.1","listen_port":7890}
                    )),
                    10 => root["route"]["rules"][0]["rules"][1]["invert"] = false.into(),
                    _ => unreachable!(),
                }
            });
        }
        let accepted = CheckedStartConfiguration::new(value)
            .and_then(|checked| checked.prepare_tunnel_data_plane([]));
        assert!(accepted.is_err(), "Tunnel change {change}");
    }
}
