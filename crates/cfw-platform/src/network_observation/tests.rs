use super::*;

#[test]
fn observation_reports_any_enabled_proxy_mode() {
    let base = NetworkServiceObservation {
        service_id: "service-uuid".into(),
        display_name: "Wi-Fi".into(),
        order: 0,
        web: NetworkProxyProtocolObservation::default(),
        secure_web: NetworkProxyProtocolObservation::default(),
        socks: NetworkProxyProtocolObservation::default(),
        pac_enabled: false,
        wpad_enabled: false,
    };
    assert!(!base.any_proxy_enabled());

    for mutate in [
        (|observation: &mut NetworkServiceObservation| observation.web.enabled = true)
            as fn(&mut NetworkServiceObservation),
        |observation| observation.secure_web.enabled = true,
        |observation| observation.socks.enabled = true,
        |observation| observation.pac_enabled = true,
        |observation| observation.wpad_enabled = true,
    ] {
        let mut observation = base.clone();
        mutate(&mut observation);
        assert!(observation.any_proxy_enabled());
    }
}

#[test]
fn observation_payload_has_a_closed_shape() {
    let error = serde_json::from_value::<NetworkServiceObservation>(serde_json::json!({
        "service_id": "service-uuid",
        "display_name": "Wi-Fi",
        "order": 0,
        "web": { "enabled": false, "server": null, "port": null },
        "secure_web": { "enabled": false, "server": null, "port": null },
        "socks": { "enabled": false, "server": null, "port": null },
        "pac_enabled": false,
        "wpad_enabled": false,
        "pac_url": "http://attacker.example/proxy.pac",
    }))
    .expect_err("unexpected diagnostics fields must be rejected");
    assert!(error.to_string().contains("pac_url"));
}

#[test]
fn routing_observation_runs_each_fixed_read_only_tool() {
    let routing = MacOsPlatformService
        .observe_network_routing()
        .expect("routing observation");
    assert!(
        routing
            .interfaces
            .lines()
            .any(|line| line.starts_with("lo0: ")),
        "{}",
        routing.interfaces
    );
    assert!(
        routing.ipv4_routes.contains("Internet:"),
        "{}",
        routing.ipv4_routes
    );
    assert!(
        routing.ipv6_routes.contains("Internet6:"),
        "{}",
        routing.ipv6_routes
    );
    assert!(
        routing.dns.starts_with("\nDNS configuration")
            || routing.dns.starts_with("DNS configuration"),
        "{}",
        routing.dns
    );
}

#[test]
fn an_observation_command_must_succeed_silently_with_text() {
    assert_eq!(
        run_network_observation("/bin/sh", &["-c", "printf 'lo0: up\\n'; printf ' \\n' >&2"])
            .expect("output"),
        "lo0: up\n"
    );
    for (script, message) in [
        (
            "printf 'refused' >&2; exit 3",
            "network observation command /bin/sh failed with status exit status: 3: refused",
        ),
        (
            "printf 'lo0'; printf 'deprecated' >&2",
            "network observation command /bin/sh succeeded with unexpected stderr: deprecated",
        ),
        (
            "printf '\\377'",
            "network observation command /bin/sh returned non-UTF-8 output",
        ),
        (
            "printf '\\377' >&2",
            "network observation command /bin/sh returned non-UTF-8 stderr",
        ),
    ] {
        let error = run_network_observation("/bin/sh", &["-c", script]).expect_err(message);
        assert_eq!(error.to_string(), message);
    }
    let error =
        run_network_observation("/nonexistent/cfw-network-tool", &[]).expect_err("a missing tool");
    assert_eq!(
        error.to_string(),
        "network observation command /nonexistent/cfw-network-tool failed"
    );
}
