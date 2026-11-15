//! The data plane of a combined run: the packet interface of a Tunnel
//! run, with the loopback listener this user's proxy settings will name.
use super::*;

fn combined_request(settings: &EngineSettings) -> EngineStartRequest {
    projected_request(
        MAINLAND_SOURCE,
        ProjectionMode::TunnelSystemProxy,
        settings,
        cfw_singbox_config::TunnelStack::Gvisor,
    )
}

#[test]
fn a_combined_run_is_admitted_with_the_listener_its_proxy_settings_will_name() {
    for lan in [false, true] {
        let settings = EngineSettings {
            lan_proxy: lan.then(|| LanProxySettings {
                listen: Ipv4Addr::UNSPECIFIED,
                port: 8081,
                allowed_source_cidrs: vec!["192.168.42.0/24".into()],
            }),
            ..EngineSettings::default()
        };
        let prepared = CheckedStartConfiguration::new(combined_request(&settings))
            .unwrap()
            .prepare_tunnel_data_plane([])
            .unwrap();
        assert_eq!(prepared.mode(), ProjectionMode::TunnelSystemProxy);
        assert_eq!(prepared.tunnel_mtu(), Some(settings.tunnel_mtu));
        assert_eq!(
            prepared.system_proxy_endpoint(),
            Some((Ipv4Addr::LOCALHOST, settings.mixed_port).into())
        );
        // It has a packet interface, so the listener-only admission refuses it.
        assert!(
            CheckedStartConfiguration::new(combined_request(&settings))
                .unwrap()
                .prepare_proxy([])
                .is_err()
        );
    }
}

#[test]
fn a_combined_run_cannot_move_its_proxy_listener_away_from_its_options() {
    let settings = EngineSettings::default();
    for change in 0..8 {
        let mut value = combined_request(&settings);
        match change {
            // Self-consistent identities whose options and template differ.
            0 => {
                value.tunnel_options.as_mut().unwrap().system_proxy_port =
                    Some(settings.mixed_port + 1);
                rehash(&mut value);
            }
            1 => {
                value.tunnel_options.as_mut().unwrap().system_proxy_port = None;
                rehash(&mut value);
            }
            _ => edit(&mut value, |root| {
                let inbounds = root["inbounds"].as_array_mut().unwrap();
                let at = inbounds
                    .iter()
                    .position(|inbound| inbound["tag"] == "cfw-system-proxy")
                    .unwrap();
                match change {
                    2 => inbounds[at]["listen_port"] = (settings.mixed_port + 1).into(),
                    3 => inbounds[at]["listen"] = "0.0.0.0".into(),
                    4 => {
                        inbounds.remove(at);
                    }
                    5 => {
                        let mut second = inbounds[at].clone();
                        second["listen_port"] = (settings.mixed_port + 1).into();
                        inbounds.push(second);
                    }
                    6 => inbounds[at]["type"] = "http".into(),
                    7 => inbounds[at]["tag"] = "foreign-proxy".into(),
                    _ => unreachable!(),
                }
            }),
        }
        let accepted = CheckedStartConfiguration::new(value)
            .and_then(|checked| checked.prepare_tunnel_data_plane([]));
        assert!(accepted.is_err(), "combined change {change}");
    }
}

#[test]
fn a_combined_run_with_lan_sharing_still_needs_its_own_proxy_listener() {
    let settings = EngineSettings {
        lan_proxy: Some(LanProxySettings {
            listen: Ipv4Addr::UNSPECIFIED,
            port: 8081,
            allowed_source_cidrs: vec!["192.168.42.0/24".into()],
        }),
        ..EngineSettings::default()
    };
    let mut value = combined_request(&settings);
    edit(&mut value, |root| {
        let inbounds = root["inbounds"].as_array_mut().unwrap();
        inbounds.retain(|inbound| inbound["tag"] != "cfw-system-proxy");
        // The packet interface and the LAN listener remain.
        assert_eq!(inbounds.len(), 2);
    });
    let Err(refusal) = CheckedStartConfiguration::new(value)
        .and_then(|checked| checked.prepare_tunnel_data_plane([]))
    else {
        panic!("a combined run without its proxy listener was admitted");
    };
    // The request's own template check refuses it, before any credential is
    // resolved into the configuration. The prepared data plane would refuse
    // it too, but only afterwards.
    assert_eq!(refusal.to_string(), invalid().to_string());
}
