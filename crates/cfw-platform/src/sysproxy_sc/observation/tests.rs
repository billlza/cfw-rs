use super::*;
use crate::sysproxy_sc::MAX_SERVICES;
use crate::sysproxy_sc::test_support::{
    FakeProxies, FakeService, FakeStore, Protocol, Proxies, Step, number, pac_enable_key, text,
    wpad_enable_key,
};

fn protocol(enabled: bool, server: Option<&str>, port: Option<u16>) -> ProxyProtocolState {
    ProxyProtocolState {
        enabled,
        server: server.map(ToOwned::to_owned),
        port,
    }
}

fn observation(protocol: ProxyProtocolState) -> ProxyObservation {
    ProxyObservation {
        service_id: "service-id".into(),
        display_name: "Wi-Fi".into(),
        web: protocol.clone(),
        secure_web: protocol.clone(),
        socks: protocol,
        pac_enabled: false,
        wpad_enabled: false,
    }
}

fn observe(service: FakeService) -> Result<ServiceProxies> {
    let store = FakeStore::with_services(vec![service]);
    let session = store.open().expect("session");
    let services = current_services(&session).expect("services");
    observe_service(&services[0])
}

fn read_web(proxies: Proxies) -> Result<ProxyProtocolState, String> {
    let dictionary = proxies.build();
    let [enable, host, port] = Protocol::Web.keys();
    read_protocol(
        as_config_dict(&dictionary),
        enable,
        host,
        port,
        "HTTP proxy",
    )
    .map_err(|error| error.to_string())
}

#[test]
fn a_foreign_endpoint_is_not_the_retired_installations_proxy() {
    // Clash for Windows on 127.0.0.1:7890 while the retired installation
    // recorded 7902. Same host, same loopback, different product.
    let foreign = protocol(true, Some("127.0.0.1"), Some(7890));
    assert!(!protocol_matches_product(&foreign, 7902));
    assert!(protocol_matches_product(&foreign, 7890));
}

#[test]
fn a_partially_torn_down_legacy_proxy_is_still_owned_per_protocol() {
    // Only SOCKS remains on the retired endpoint. The all-three conjunction
    // would call this "not ours" and fail open on exactly the residue the
    // absence proof exists to catch; per-protocol matching still sees it.
    let cleared = protocol(false, None, None);
    let remaining = protocol(true, Some("127.0.0.1"), Some(7902));
    let partial = ProxyObservation {
        service_id: "service-id".into(),
        display_name: "Wi-Fi".into(),
        web: cleared.clone(),
        secure_web: cleared,
        socks: remaining.clone(),
        pac_enabled: false,
        wpad_enabled: false,
    };

    assert!(!observation_matches_product(&partial, 7902));
    assert!(
        [&partial.web, &partial.secure_web, &partial.socks]
            .into_iter()
            .any(|state| protocol_matches_product(state, 7902))
    );
    assert!(protocol_matches_product(&remaining, 7902));
}

#[test]
fn ownership_requires_all_three_exact_live_loopback_protocols() {
    let exact = observation(protocol(true, Some("127.0.0.1"), Some(7890)));
    assert!(observation_matches_product(&exact, 7890));

    let mut malicious_historical_value = exact.clone();
    malicious_historical_value.web.server = Some("attacker.invalid".into());
    assert!(!observation_matches_product(
        &malicious_historical_value,
        7890
    ));

    let mut partial = exact.clone();
    partial.socks.enabled = false;
    assert!(!observation_matches_product(&partial, 7890));

    let mut secure_web_elsewhere = exact.clone();
    secure_web_elsewhere.secure_web.port = Some(7891);
    assert!(!observation_matches_product(&secure_web_elsewhere, 7890));

    let mut pac = exact.clone();
    pac.pac_enabled = true;
    assert!(!observation_matches_product(&pac, 7890));

    let mut wpad = exact;
    wpad.wpad_enabled = true;
    assert!(!observation_matches_product(&wpad, 7890));
}

#[test]
fn postcondition_requires_owned_values_to_be_cleared() {
    assert!(observation_is_cleared(&observation(protocol(
        false, None, None
    ))));
    assert!(!observation_is_cleared(&observation(protocol(
        false,
        Some("127.0.0.1"),
        Some(7890)
    ))));
    assert!(!observation_is_cleared(&observation(protocol(
        false,
        None,
        Some(7890)
    ))));
    assert!(!observation_is_cleared(&observation(protocol(
        true, None, None
    ))));

    let cleared = observation(protocol(false, None, None));
    let mut socks_left = cleared.clone();
    socks_left.socks.enabled = true;
    assert!(!observation_is_cleared(&socks_left));
    let mut secure_web_left = cleared.clone();
    secure_web_left.secure_web.server = Some("127.0.0.1".into());
    assert!(!observation_is_cleared(&secure_web_left));
    let mut pac = cleared.clone();
    pac.pac_enabled = true;
    assert!(!observation_is_cleared(&pac));
    let mut wpad = cleared;
    wpad.wpad_enabled = true;
    assert!(!observation_is_cleared(&wpad));
}

#[test]
fn a_protocol_reads_its_flag_server_and_port() {
    assert_eq!(
        read_web(Proxies::default().protocol(Protocol::Web, 1, "127.0.0.1", 7890)),
        Ok(protocol(true, Some("127.0.0.1"), Some(7890)))
    );
    assert_eq!(
        read_web(Proxies::default()),
        Ok(protocol(false, None, None))
    );
    // System Settings leaves an empty server behind when a field is cleared.
    assert_eq!(
        read_web(Proxies::default().protocol(Protocol::Web, 0, "", 0)),
        Ok(protocol(false, None, Some(0)))
    );
}

#[test]
fn a_protocol_refuses_a_port_outside_the_u16_range_or_a_malformed_value() {
    for port in [65_536, -1] {
        assert_eq!(
            read_web(Proxies::default().protocol(Protocol::Web, 1, "127.0.0.1", port)),
            Err("HTTP proxy port is outside the u16 range".into())
        );
    }
    let [enable, host, port] = Protocol::Web.keys();
    assert_eq!(
        read_web(Proxies::default().with(enable, number(3))),
        Err("HTTP proxy enable flag has invalid value 3; expected 0 or 1".into())
    );
    assert_eq!(
        read_web(Proxies::default().with(host, number(1))),
        Err("HTTP proxy server has an unexpected CoreFoundation type".into())
    );
    assert_eq!(
        read_web(Proxies::default().with(port, text("7890"))),
        Err("HTTP proxy port has an unexpected CoreFoundation type".into())
    );
}

#[test]
fn a_service_is_observed_with_every_protocol_and_the_automatic_modes() {
    let proxies = Proxies::every_protocol("127.0.0.1", 7890)
        .protocol(Protocol::SecureWeb, 0, "proxy.example", 8443)
        .protocol(Protocol::Socks, 1, "127.0.0.1", 7891)
        .with(pac_enable_key(), number(1))
        .with(wpad_enable_key(), number(1));
    let observed =
        observe(FakeService::configured("service-a", "Wi-Fi", proxies)).expect("observed");
    assert_eq!(
        observed,
        ServiceProxies::Observed(ProxyObservation {
            service_id: "service-a".into(),
            display_name: "Wi-Fi".into(),
            web: protocol(true, Some("127.0.0.1"), Some(7890)),
            secure_web: protocol(false, Some("proxy.example"), Some(8443)),
            socks: protocol(true, Some("127.0.0.1"), Some(7891)),
            pac_enabled: true,
            wpad_enabled: true,
        })
    );
}

#[test]
fn a_service_without_a_proxies_protocol_carries_no_proxy() {
    let service = FakeService::new("service-a", "Thunderbolt Bridge", FakeProxies::NoProtocol);
    assert_eq!(
        observe(service.clone()).expect("observed"),
        ServiceProxies::NoProtocol {
            display_name: "Thunderbolt Bridge".into()
        }
    );

    let store = FakeStore::with_services(vec![service]);
    let session = store.open().expect("session");
    let services = current_services(&session).expect("services");
    let error = read_observation(&services[0]).expect_err("a protocol is required");
    assert_eq!(
        error.to_string(),
        "network service Thunderbolt Bridge has no Proxies protocol"
    );
}

#[test]
fn a_proxies_protocol_without_a_configuration_is_an_error() {
    let error = observe(FakeService::new(
        "service-a",
        "Wi-Fi",
        FakeProxies::Unconfigured,
    ))
    .expect_err("a configuration is required");
    assert_eq!(
        error.to_string(),
        "network service Wi-Fi has no proxy configuration"
    );
}

#[test]
fn every_setting_of_a_service_is_checked_in_order() {
    let [web_enable, ..] = Protocol::Web.keys();
    let [secure_web_enable, ..] = Protocol::SecureWeb.keys();
    let [socks_enable, ..] = Protocol::Socks.keys();
    for (key, label) in [
        (web_enable, "HTTP proxy"),
        (secure_web_enable, "HTTPS proxy"),
        (socks_enable, "SOCKS proxy"),
        (pac_enable_key(), "PAC proxy configuration"),
        (wpad_enable_key(), "proxy auto-discovery"),
    ] {
        let proxies = Proxies::every_protocol("127.0.0.1", 7890).with(key, number(2));
        let error = observe(FakeService::configured("service-a", "Wi-Fi", proxies))
            .expect_err("an invalid flag");
        assert_eq!(
            error.to_string(),
            format!("{label} enable flag has invalid value 2; expected 0 or 1")
        );
    }

    let error = observe(FakeService {
        identifier: Some(" service-a".into()),
        ..FakeService::new("unused", "Wi-Fi", FakeProxies::NoProtocol)
    })
    .expect_err("an invalid identifier");
    assert_eq!(
        error.to_string(),
        "SC network service identifier is invalid"
    );
}

#[test]
fn diagnostics_report_every_service_in_set_order_and_tolerate_missing_proxies() {
    let store = FakeStore::with_services(vec![
        FakeService::configured(
            "service-a",
            "Wi-Fi",
            Proxies::every_protocol("127.0.0.1", 7890).with(pac_enable_key(), number(1)),
        ),
        FakeService::new("service-b", "Thunderbolt Bridge", FakeProxies::NoProtocol),
        FakeService {
            display_name: None,
            ..FakeService::new("service-c", "unused", FakeProxies::Unconfigured)
        },
    ]);
    let observations = observe_network_services(|| store.open()).expect("diagnostics");

    let loopback = NetworkProxyProtocolObservation {
        enabled: true,
        server: Some("127.0.0.1".into()),
        port: Some(7890),
    };
    let nothing = |service_id: &str, display_name: &str, order| NetworkServiceObservation {
        service_id: service_id.into(),
        display_name: display_name.into(),
        order,
        web: NetworkProxyProtocolObservation::default(),
        secure_web: NetworkProxyProtocolObservation::default(),
        socks: NetworkProxyProtocolObservation::default(),
        pac_enabled: false,
        wpad_enabled: false,
    };
    assert_eq!(
        observations,
        [
            NetworkServiceObservation {
                web: loopback.clone(),
                secure_web: loopback.clone(),
                socks: loopback,
                pac_enabled: true,
                ..nothing("service-a", "Wi-Fi", 0)
            },
            nothing("service-b", "Thunderbolt Bridge", 1),
            nothing("service-c", "service-c", 2),
        ]
    );
    // Diagnostics only read.
    assert_eq!(
        store.events(),
        [
            crate::sysproxy_sc::test_support::Event::Opened,
            crate::sysproxy_sc::test_support::Event::Listed
        ]
    );
}

#[test]
fn diagnostics_fail_on_a_malformed_service_or_an_unavailable_store() {
    let [_, _, port] = Protocol::Socks.keys();
    let store = FakeStore::with_services(vec![FakeService::configured(
        "service-a",
        "Wi-Fi",
        Proxies::every_protocol("127.0.0.1", 7890).with(port, number(70_000)),
    )]);
    let error = observe_network_services(|| store.open()).expect_err("a malformed port");
    assert_eq!(
        error.to_string(),
        "SOCKS proxy port is outside the u16 range"
    );

    let store = FakeStore::with_services(vec![FakeService {
        identifier: None,
        ..FakeService::new("unused", "Wi-Fi", FakeProxies::NoProtocol)
    }]);
    let error = observe_network_services(|| store.open()).expect_err("an unidentified service");
    assert_eq!(
        error.to_string(),
        "SC network service has no stable identifier"
    );

    let store = FakeStore::with_services(
        (0..=MAX_SERVICES)
            .map(|index| {
                FakeService::new(
                    &format!("service-{index}"),
                    "Wi-Fi",
                    FakeProxies::NoProtocol,
                )
            })
            .collect(),
    );
    let error = observe_network_services(|| store.open()).expect_err("an oversized set");
    assert_eq!(
        error.to_string(),
        "current network service count exceeds the cutover safety bound"
    );

    let store = FakeStore::default();
    store.fail(Step::Open);
    let error = observe_network_services(|| store.open()).expect_err("no session");
    assert_eq!(error.to_string(), "fake SystemConfiguration refused Open");
}
