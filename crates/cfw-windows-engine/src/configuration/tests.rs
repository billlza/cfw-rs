use super::*;
use cfw_singbox_config::{CredentialKind, EngineSettings, ValidatedSingBoxProfile};

const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const REFERENCE: &str = "11111111-1111-4111-8111-111111111111";

fn projection() -> ProjectedConfig {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{REFERENCE}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"proxy.example.com"}}}}]}}"#
    ))
    .unwrap()
    .project(PROFILE, ProjectionMode::LocalProxy, &EngineSettings::default())
    .unwrap()
}

#[test]
fn material_is_injected_without_changing_public_identity_or_debug_output() {
    let projected = projection();
    let reference = CredentialRef::new(REFERENCE, CredentialKind::TrojanPassword).unwrap();
    let config =
        PreparedConfig::local_proxy(&projected, [(&reference, "test-secret-123")]).unwrap();
    let parsed: Value = serde_json::from_slice(&config.resolved.bytes).unwrap();
    assert_eq!(
        parsed
            .pointer(projected.credential_slots()[0].json_pointer())
            .unwrap(),
        "test-secret-123"
    );
    assert_eq!(config.digest(), projected.digest());
    assert_eq!(config.listeners.len(), 2);
    assert!(!format!("{config:?}").contains("test-secret-123"));
    assert!(!projected.as_json().contains("test-secret-123"));
}

#[test]
fn missing_duplicate_wrong_kind_and_extra_material_fail() {
    let projected = projection();
    let reference = CredentialRef::new(REFERENCE, CredentialKind::TrojanPassword).unwrap();
    let wrong = CredentialRef::new(REFERENCE, CredentialKind::Socks5Password).unwrap();
    assert!(PreparedConfig::local_proxy(&projected, []).is_err());
    assert!(
        PreparedConfig::local_proxy(&projected, [(&reference, "a"), (&reference, "a")]).is_err()
    );
    assert!(PreparedConfig::local_proxy(&projected, [(&wrong, "a")]).is_err());
    assert!(PreparedConfig::local_proxy(&projected, [(&reference, "a"), (&wrong, "a")]).is_err());
    assert!(PreparedConfig::local_proxy(&projected, [(&reference, "")]).is_err());
}

#[test]
fn other_modes_cannot_activate_platform_effects_through_this_component() {
    let profile =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .unwrap();
    for mode in [
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let projected = profile
            .project(PROFILE, mode, &EngineSettings::default())
            .unwrap();
        let checked = ResolvedProjection::new(&projected, []).unwrap();
        assert_eq!(checked.digest(), projected.digest());
        assert!(PreparedConfig::local_proxy(&projected, []).is_err());
    }
}

#[test]
fn system_proxy_data_plane_preserves_mode_and_has_a_local_endpoint() {
    let profile =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .unwrap();
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let projected = profile
            .project(PROFILE, mode, &EngineSettings::default())
            .unwrap();
        if mode == ProjectionMode::SystemProxy {
            let prepared = PreparedConfig::system_proxy_data_plane(&projected, []).unwrap();
            assert_eq!(prepared.digest(), projected.digest());
            let endpoint = prepared.system_proxy_endpoint().unwrap();
            assert!(endpoint.ip().is_loopback());
            assert_eq!(endpoint.port(), EngineSettings::default().mixed_port);
            assert!(prepared.listeners.contains(&endpoint));
        } else {
            assert!(PreparedConfig::system_proxy_data_plane(&projected, []).is_err());
        }
    }
}

#[test]
fn packet_interface_is_owned_only_by_the_admitted_tunnel_data_plane() {
    let profile =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .unwrap();
    let settings = EngineSettings {
        lan_proxy: Some(cfw_singbox_config::LanProxySettings {
            listen: "0.0.0.0".parse().unwrap(),
            port: 8081,
            allowed_source_cidrs: vec!["192.168.42.0/24".into()],
        }),
        ..EngineSettings::default()
    };
    let project = |mode| {
        profile
            .project_with_tunnel_stack(
                PROFILE,
                mode,
                &settings,
                cfw_singbox_config::TunnelStack::Gvisor,
            )
            .unwrap()
    };
    let tunnel = project(ProjectionMode::Tunnel);
    let local = project(ProjectionMode::LocalProxy);
    let combined = project(ProjectionMode::TunnelSystemProxy);
    let controller = std::net::SocketAddr::new(
        tunnel.clash_api().address().into(),
        tunnel.clash_api().port(),
    );
    let prepare = |projection: &ProjectedConfig, template: &str, mode, mtu| {
        PreparedConfig::from_parts(
            ResolvedProjection::new(projection, []).unwrap(),
            template,
            projection.configuration_digest(),
            mode,
            controller,
            mtu,
        )
    };
    let admitted = prepare(
        &tunnel,
        tunnel.as_json(),
        ProjectionMode::Tunnel,
        Some(1500),
    )
    .expect("the exact packet-fed Tunnel template");
    assert_eq!(
        admitted.listeners,
        [controller, "0.0.0.0:8081".parse().unwrap()]
    );
    assert_eq!(admitted.tunnel_mtu(), Some(1500));
    assert_eq!(admitted.system_proxy_endpoint(), None);
    // A combined run: the packet interface, with the listener this
    // user's proxy settings will name beside it.
    let both = prepare(
        &combined,
        combined.as_json(),
        ProjectionMode::TunnelSystemProxy,
        Some(1500),
    )
    .expect("the exact combined template");
    let proxy: std::net::SocketAddr = (std::net::Ipv4Addr::LOCALHOST, settings.mixed_port).into();
    assert_eq!(both.mode(), ProjectionMode::TunnelSystemProxy);
    assert_eq!(both.tunnel_mtu(), Some(1500));
    assert_eq!(both.system_proxy_endpoint(), Some(proxy));
    assert_eq!(
        both.listeners,
        [controller, proxy, "0.0.0.0:8081".parse().unwrap()]
    );
    let mut detached: Value = serde_json::from_str(tunnel.as_json()).unwrap();
    detached["inbounds"]
        .as_array_mut()
        .unwrap()
        .retain(|inbound| inbound["type"] != "tun");
    let detached = detached.to_string();
    // The combined listeners with no packet interface beside them.
    let mut listeners_only: Value = serde_json::from_str(combined.as_json()).unwrap();
    listeners_only["inbounds"]
        .as_array_mut()
        .unwrap()
        .retain(|inbound| inbound["type"] != "tun");
    assert_eq!(listeners_only["inbounds"].as_array().unwrap().len(), 2);
    let listeners_only = listeners_only.to_string();
    let mut doubled: Value = serde_json::from_str(tunnel.as_json()).unwrap();
    let interface = doubled["inbounds"][0].clone();
    assert_eq!(interface["type"], "tun");
    doubled["inbounds"].as_array_mut().unwrap().push(interface);
    let doubled = doubled.to_string();
    for (projection, template, mode, mtu) in [
        (&tunnel, tunnel.as_json(), ProjectionMode::LocalProxy, None),
        (&tunnel, tunnel.as_json(), ProjectionMode::Tunnel, None),
        (
            &tunnel,
            detached.as_str(),
            ProjectionMode::Tunnel,
            Some(1500),
        ),
        (
            &tunnel,
            doubled.as_str(),
            ProjectionMode::Tunnel,
            Some(1500),
        ),
        (&local, local.as_json(), ProjectionMode::Tunnel, Some(1500)),
        (
            &local,
            local.as_json(),
            ProjectionMode::LocalProxy,
            Some(1500),
        ),
        (
            &combined,
            combined.as_json(),
            ProjectionMode::Tunnel,
            Some(1500),
        ),
        (
            &combined,
            combined.as_json(),
            ProjectionMode::TunnelSystemProxy,
            None,
        ),
        (
            &combined,
            combined.as_json(),
            ProjectionMode::SystemProxy,
            None,
        ),
        (
            &tunnel,
            tunnel.as_json(),
            ProjectionMode::TunnelSystemProxy,
            Some(1500),
        ),
        (
            &combined,
            listeners_only.as_str(),
            ProjectionMode::TunnelSystemProxy,
            Some(1500),
        ),
    ] {
        assert!(
            prepare(projection, template, mode, mtu).is_err(),
            "{mode:?} with MTU {mtu:?} admitted a template it does not own"
        );
    }
}

#[test]
fn encoding_budget_counts_escaped_bytes() {
    assert!(serialize_bounded(&"\\\\\\", 6).is_err());
    assert_eq!(&*serialize_bounded(&"ok", 4).unwrap(), b"\"ok\"");
}

#[test]
fn lan_sharing_remains_separate_from_local_system_proxy_ownership() {
    let profile =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .unwrap();
    for listen in ["0.0.0.0", "192.168.42.1"] {
        let settings = EngineSettings {
            lan_proxy: Some(cfw_singbox_config::LanProxySettings {
                listen: listen.parse().unwrap(),
                port: 8081,
                allowed_source_cidrs: vec!["192.168.42.0/24".into()],
            }),
            ..EngineSettings::default()
        };
        for mode in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy] {
            let projected = profile.project(PROFILE, mode, &settings).unwrap();
            let prepared = match mode {
                ProjectionMode::LocalProxy => PreparedConfig::local_proxy(&projected, []),
                ProjectionMode::SystemProxy => {
                    PreparedConfig::system_proxy_data_plane(&projected, [])
                }
                _ => unreachable!(),
            }
            .expect("valid shared LAN projection must remain admissible on Windows");
            assert_eq!(prepared.listeners.len(), 3);
            assert!(
                prepared
                    .listeners
                    .contains(&std::net::SocketAddr::new(listen.parse().unwrap(), 8081))
            );
            assert_eq!(
                prepared.system_proxy_endpoint(),
                (mode == ProjectionMode::SystemProxy)
                    .then(|| std::net::SocketAddr::from(([127, 0, 0, 1], settings.mixed_port)))
            );
            assert_eq!(
                prepared.configuration_digest(),
                projected.configuration_digest()
            );
            assert_eq!(prepared.digest(), projected.digest());
        }
    }
}
