use super::*;

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

    let mut pac = exact;
    pac.pac_enabled = true;
    assert!(!observation_matches_product(&pac, 7890));
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
}
