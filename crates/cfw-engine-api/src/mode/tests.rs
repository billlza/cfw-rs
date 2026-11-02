use cfw_singbox_config::TunnelStack;

use super::*;

const MODES: [EngineMode; 5] = [
    EngineMode::Off,
    EngineMode::LocalProxy,
    EngineMode::SystemProxy,
    EngineMode::Tunnel,
    EngineMode::TunnelSystemProxy,
];

#[test]
fn the_two_switches_select_exactly_one_running_mode() {
    for (system_proxy, tunnel, mode) in [
        (false, false, EngineMode::LocalProxy),
        (true, false, EngineMode::SystemProxy),
        (false, true, EngineMode::Tunnel),
        (true, true, EngineMode::TunnelSystemProxy),
    ] {
        let selected = EngineMode::from_switches(system_proxy, tunnel);
        assert_eq!(selected, mode);
        assert_eq!(selected.system_proxy_enabled(), system_proxy);
        assert_eq!(selected.tunnel_enabled(), tunnel);
    }
    assert_eq!(EngineMode::default(), EngineMode::Off);
    assert!(!EngineMode::Off.system_proxy_enabled());
    assert!(!EngineMode::Off.tunnel_enabled());
}

#[test]
fn each_platform_names_its_own_owners_stack_and_consent() {
    let mac = EngineRuntimePlatform::MacOs;
    assert_eq!(mac.tunnel_stack(), TunnelStack::System);
    assert_eq!(mac.proxy_owner(), EngineOwner::ProxyAgent);
    assert_eq!(mac.tunnel_owner(), EngineOwner::PacketTunnelSystemExtension);
    assert!(mac.tunnel_authorization_awaits_consent());

    let windows = EngineRuntimePlatform::Windows;
    assert_eq!(windows.tunnel_stack(), TunnelStack::Gvisor);
    assert_eq!(windows.proxy_owner(), EngineOwner::WindowsUserAgent);
    assert_eq!(windows.tunnel_owner(), EngineOwner::WindowsTunnelService);
    assert!(!windows.tunnel_authorization_awaits_consent());
}

#[test]
fn proxy_owners_run_only_proxy_modes_and_tunnel_owners_only_tunnel_modes() {
    let supported = |owner: EngineOwner| {
        MODES
            .into_iter()
            .filter(|mode| owner.supports_mode(*mode))
            .collect::<Vec<_>>()
    };
    for owner in [EngineOwner::ProxyAgent, EngineOwner::WindowsUserAgent] {
        assert_eq!(
            supported(owner),
            [EngineMode::LocalProxy, EngineMode::SystemProxy]
        );
    }
    for owner in [
        EngineOwner::PacketTunnelSystemExtension,
        EngineOwner::WindowsTunnelService,
    ] {
        assert_eq!(
            supported(owner),
            [EngineMode::Tunnel, EngineMode::TunnelSystemProxy]
        );
    }
}

#[test]
fn modes_and_owners_keep_their_wire_names() {
    for (mode, name) in MODES.into_iter().zip([
        "off",
        "local_proxy",
        "system_proxy",
        "tunnel",
        "tunnel_system_proxy",
    ]) {
        assert_eq!(serde_json::to_value(mode).expect("mode"), name);
    }
    for (owner, name) in [
        (EngineOwner::ProxyAgent, "proxy_agent"),
        (
            EngineOwner::PacketTunnelSystemExtension,
            "packet_tunnel_system_extension",
        ),
        (EngineOwner::WindowsUserAgent, "windows_user_agent"),
        (EngineOwner::WindowsTunnelService, "windows_tunnel_service"),
    ] {
        assert_eq!(serde_json::to_value(owner).expect("owner"), name);
    }
}
