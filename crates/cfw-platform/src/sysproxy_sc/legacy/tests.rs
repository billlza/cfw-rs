use super::*;
use crate::sysproxy_sc::test_support::{
    Event, FakeProxies, FakeService, FakeStore, Protocol, Proxies, Step,
    exclude_simple_hostnames_key, number, pac_enable_key, wpad_enable_key,
};

const PORT: u16 = 7890;

fn product(identifier: &str, display_name: &str) -> FakeService {
    FakeService::configured(
        identifier,
        display_name,
        Proxies::every_protocol("127.0.0.1", i32::from(PORT)),
    )
}

fn cleared(identifier: &str, display_name: &str) -> FakeService {
    FakeService::configured(identifier, display_name, Proxies::cleared())
}

fn plan(services: &[(&str, &str)]) -> LegacyProxyCutoverPlan {
    LegacyProxyCutoverPlan {
        services: services
            .iter()
            .map(|(service_id, display_name)| LegacyProxyServiceIdentity {
                service_id: (*service_id).into(),
                display_name: (*display_name).into(),
            })
            .collect(),
        expected_port: PORT,
    }
}

fn two_product_services() -> FakeStore {
    FakeStore::with_services(vec![
        product("service-a", "Wi-Fi"),
        FakeService::new("service-b", "Thunderbolt Bridge", FakeProxies::NoProtocol),
        product("service-c", "Ethernet"),
    ])
}

/// The settings the cutover leaves: every protocol off without a server or
/// port, and everything else as it was.
fn cleared_settings() -> std::collections::BTreeMap<String, String> {
    FakeService::configured("unused", "unused", Proxies::cleared())
        .settings()
        .into_iter()
        .chain([
            (pac_enable_key().to_string(), "0".to_owned()),
            (wpad_enable_key().to_string(), "0".to_owned()),
        ])
        .collect()
}

#[test]
fn capture_records_every_service_with_the_exact_product_proxy() {
    let store = FakeStore::with_services(vec![
        product("service-a", "Wi-Fi"),
        FakeService::new("service-b", "Thunderbolt Bridge", FakeProxies::NoProtocol),
        FakeService::configured(
            "service-c",
            "Ethernet",
            Proxies::every_protocol("127.0.0.1", 7891),
        ),
        product("service-d", "USB LAN"),
    ]);
    let captured = capture_legacy_applied_proxy(|| store.open(), PORT).expect("capture");
    assert_eq!(
        captured,
        plan(&[("service-a", "Wi-Fi"), ("service-d", "USB LAN")])
    );
    // Capture only reads.
    assert_eq!(store.events(), [Event::Opened, Event::Listed]);
}

#[test]
fn capture_without_an_owned_service_changes_nothing() {
    let store = FakeStore::with_services(vec![
        cleared("service-a", "Wi-Fi"),
        FakeService::configured(
            "service-b",
            "Ethernet",
            Proxies::every_protocol("127.0.0.1", i32::from(PORT)).with(pac_enable_key(), number(1)),
        ),
    ]);
    let error =
        capture_legacy_applied_proxy(|| store.open(), PORT).expect_err("nothing to capture");
    assert_eq!(
        error.to_string(),
        "no current network service has the exact legacy HTTP/HTTPS/SOCKS value 127.0.0.1:7890 with PAC/WPAD disabled; no proxy field was changed"
    );
    assert_eq!(store.events(), [Event::Opened, Event::Listed]);
}

#[test]
fn an_unconfigured_service_fails_the_capture_whatever_its_name() {
    // A name that contains the "no Proxies protocol" wording must not turn a
    // missing configuration into a skipped service.
    for name in ["Wi-Fi", "VPN has no Proxies protocol"] {
        let store = FakeStore::with_services(vec![
            product("service-a", "Ethernet"),
            FakeService::new("service-b", name, FakeProxies::Unconfigured),
        ]);
        let error = capture_legacy_applied_proxy(|| store.open(), PORT)
            .expect_err("an unconfigured service");
        assert_eq!(
            error.to_string(),
            format!("network service {name} has no proxy configuration")
        );
    }
}

#[test]
fn capture_fails_when_the_store_cannot_be_read() {
    for step in [Step::Open, Step::List] {
        let store = two_product_services();
        store.fail(step);
        let error =
            capture_legacy_applied_proxy(|| store.open(), PORT).expect_err("an unreadable store");
        assert_eq!(
            error.to_string(),
            format!("fake SystemConfiguration refused {step:?}")
        );
    }
}

#[test]
fn a_plan_must_name_distinct_valid_services_and_a_port() {
    validate_plan(&plan(&[("service-a", "Wi-Fi")])).expect("a valid plan");

    let mut no_port = plan(&[("service-a", "Wi-Fi")]);
    no_port.expected_port = 0;
    let too_many = LegacyProxyCutoverPlan {
        services: (0..=MAX_SERVICES)
            .map(|index| LegacyProxyServiceIdentity {
                service_id: format!("service-{index}"),
                display_name: "Wi-Fi".into(),
            })
            .collect(),
        expected_port: PORT,
    };
    for (invalid, message) in [
        (no_port, "legacy proxy cutover plan is invalid"),
        (plan(&[]), "legacy proxy cutover plan is invalid"),
        (too_many, "legacy proxy cutover plan is invalid"),
        (
            plan(&[("service-a ", "Wi-Fi")]),
            "SC network service identifier is invalid",
        ),
        (
            plan(&[("service-a", "Wi\u{0}Fi")]),
            "SC network service display name is invalid",
        ),
        (
            plan(&[("service-a", "Wi-Fi"), ("service-a", "Ethernet")]),
            "legacy proxy cutover plan has duplicate service identifiers",
        ),
    ] {
        let error = validate_plan(&invalid).expect_err(message);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn an_invalid_plan_opens_no_session() {
    let store = two_product_services();
    let invalid = plan(&[]);
    assert!(verify_legacy_applied_proxy(|| store.open(), &invalid).is_err());
    assert!(disable_legacy_proxy(|| store.open(), &invalid).is_err());
    assert!(verify_legacy_proxy_disabled(|| store.open(), &invalid).is_err());
    assert!(recover_legacy_proxy(|| store.open(), &invalid).is_err());
    assert_eq!(store.events(), []);
}

#[test]
fn legacy_absence_refuses_to_prove_anything_without_a_recorded_endpoint() {
    // Absence is only provable against a known endpoint. An empty or zero
    // port list must never be a vacuous pass; both return before any
    // SCPreferences session is opened.
    let store = two_product_services();
    for ports in [vec![], vec![0u16], vec![0u16, 7902]] {
        let error = verify_no_legacy_owned_proxy(|| store.open(), &ports, false)
            .expect_err("an unknown retired endpoint cannot prove absence");
        assert!(
            error.to_string().contains("owned proxy port is unknown"),
            "{error}"
        );
    }
    assert_eq!(store.events(), []);
}

#[test]
fn a_still_applied_plan_verifies_and_a_changed_service_does_not() {
    let store = two_product_services();
    let planned = plan(&[("service-a", "Wi-Fi"), ("service-c", "Ethernet")]);
    verify_legacy_applied_proxy(|| store.open(), &planned).expect("still applied");

    store.replace(
        2,
        FakeService::configured(
            "service-c",
            "Ethernet",
            Proxies::every_protocol("127.0.0.1", i32::from(PORT)).protocol(
                Protocol::SecureWeb,
                1,
                "127.0.0.1",
                7891,
            ),
        ),
    );
    let error =
        verify_legacy_applied_proxy(|| store.open(), &planned).expect_err("a changed service");
    assert_eq!(
        error.to_string(),
        "network service Ethernet no longer equals the exact legacy loopback proxy; no proxy field was changed"
    );

    let error = verify_legacy_applied_proxy(|| store.open(), &plan(&[("service-z", "Wi-Fi")]))
        .expect_err("a vanished service");
    assert_eq!(
        error.to_string(),
        "SC network service identity disappeared: service-z"
    );
}

#[test]
fn disable_clears_only_the_product_triples_under_one_lock_and_one_commit() {
    let store = two_product_services();
    let planned = plan(&[("service-a", "Wi-Fi"), ("service-c", "Ethernet")]);
    disable_legacy_proxy(|| store.open(), &planned).expect("disabled");

    assert_eq!(
        store.events(),
        [
            Event::Opened,
            Event::Locked,
            Event::Listed,
            Event::Staged("service-a".into()),
            Event::Staged("service-c".into()),
            Event::Committed,
        ]
    );
    for index in [0, 2] {
        let settings = store.service(index).settings();
        assert_eq!(settings, cleared_settings());
        // The setting the cutover does not own survives it.
        assert_eq!(
            settings.get(&exclude_simple_hostnames_key().to_string()),
            Some(&"1".to_owned())
        );
    }
    verify_legacy_proxy_disabled(|| store.open(), &planned).expect("cleared");
}

#[test]
fn disable_revalidates_every_service_before_staging_any() {
    let store = two_product_services();
    let planned = plan(&[("service-a", "Wi-Fi"), ("service-c", "Ethernet")]);
    store.replace(
        2,
        FakeService::configured(
            "service-c",
            "Ethernet",
            Proxies::every_protocol("127.0.0.1", i32::from(PORT))
                .with(wpad_enable_key(), number(1)),
        ),
    );
    let error = disable_legacy_proxy(|| store.open(), &planned).expect_err("a changed service");
    assert_eq!(
        error.to_string(),
        "network service Ethernet changed after preparation; no proxy field was changed"
    );
    assert_eq!(
        store.events(),
        [Event::Opened, Event::Locked, Event::Listed]
    );
    assert_eq!(
        store.service(0).settings(),
        product("service-a", "Wi-Fi").settings()
    );
}

#[test]
fn a_refused_stage_commits_nothing() {
    let store = two_product_services();
    let mut refusing = product("service-c", "Ethernet");
    refusing.refuses_staging = true;
    store.replace(2, refusing);
    let planned = plan(&[("service-a", "Wi-Fi"), ("service-c", "Ethernet")]);

    let error = disable_legacy_proxy(|| store.open(), &planned).expect_err("a refused stage");
    assert_eq!(
        error.to_string(),
        "SCNetworkProtocolSetConfiguration failed for Ethernet"
    );
    assert_eq!(
        store.events(),
        [
            Event::Opened,
            Event::Locked,
            Event::Listed,
            Event::Staged("service-a".into()),
        ]
    );
    // The first service was staged in the session only.
    assert_eq!(
        store.service(0).settings(),
        product("service-a", "Wi-Fi").settings()
    );
}

#[test]
fn disable_stops_at_a_failed_lock_or_commit() {
    let planned = plan(&[("service-a", "Wi-Fi")]);

    let store = two_product_services();
    store.fail(Step::Lock);
    let error = disable_legacy_proxy(|| store.open(), &planned).expect_err("no lock");
    assert_eq!(error.to_string(), "fake SystemConfiguration refused Lock");
    assert_eq!(store.events(), [Event::Opened, Event::Locked]);

    let store = two_product_services();
    store.fail(Step::Commit);
    let error = disable_legacy_proxy(|| store.open(), &planned).expect_err("no commit");
    assert_eq!(error.to_string(), "fake SystemConfiguration refused Commit");
    assert_eq!(
        store.service(0).settings(),
        product("service-a", "Wi-Fi").settings()
    );
}

#[test]
fn staging_requires_a_configured_proxies_protocol() {
    for (proxies, message) in [
        (
            FakeProxies::NoProtocol,
            "network service Wi-Fi has no Proxies protocol",
        ),
        (
            FakeProxies::Unconfigured,
            "network service Wi-Fi has no proxy configuration",
        ),
    ] {
        let store = FakeStore::with_services(vec![FakeService::new("service-a", "Wi-Fi", proxies)]);
        let session = store.open().expect("session");
        let services = current_services(&session).expect("services");
        let error = stage_clear_product_proxy(&services[0], "Wi-Fi").expect_err(message);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn a_service_with_a_product_value_left_is_not_disabled() {
    let store = FakeStore::with_services(vec![FakeService::configured(
        "service-a",
        "Wi-Fi",
        Proxies::cleared().protocol(Protocol::Socks, 0, "127.0.0.1", i32::from(PORT)),
    )]);
    let error = verify_legacy_proxy_disabled(|| store.open(), &plan(&[("service-a", "Wi-Fi")]))
        .expect_err("a value is left");
    assert_eq!(
        error.to_string(),
        "network service Wi-Fi still contains a legacy product proxy value"
    );
}

#[test]
fn recovery_of_an_applied_plan_disables_and_verifies() {
    let store = two_product_services();
    let planned = plan(&[("service-a", "Wi-Fi"), ("service-c", "Ethernet")]);
    recover_legacy_proxy(|| store.open(), &planned).expect("recovered");
    assert_eq!(
        store.events(),
        [
            Event::Opened,
            Event::Listed,
            Event::Opened,
            Event::Locked,
            Event::Listed,
            Event::Staged("service-a".into()),
            Event::Staged("service-c".into()),
            Event::Committed,
            Event::Opened,
            Event::Listed,
        ]
    );
    assert_eq!(store.service(0).settings(), cleared_settings());
    assert_eq!(store.service(2).settings(), cleared_settings());
}

#[test]
fn recovery_of_a_cleared_plan_only_verifies() {
    let store = FakeStore::with_services(vec![
        cleared("service-a", "Wi-Fi"),
        cleared("service-c", "Ethernet"),
    ]);
    let planned = plan(&[("service-a", "Wi-Fi"), ("service-c", "Ethernet")]);
    recover_legacy_proxy(|| store.open(), &planned).expect("already cleared");
    assert_eq!(
        store.events(),
        [Event::Opened, Event::Listed, Event::Opened, Event::Listed]
    );
}

#[test]
fn recovery_refuses_a_mixed_or_foreign_state() {
    let planned = plan(&[("service-a", "Wi-Fi"), ("service-c", "Ethernet")]);

    let store = FakeStore::with_services(vec![
        product("service-a", "Wi-Fi"),
        cleared("service-c", "Ethernet"),
    ]);
    let error = recover_legacy_proxy(|| store.open(), &planned).expect_err("a mixed state");
    assert_eq!(
        error.to_string(),
        "legacy proxy services are in a non-atomic mixed recovery state"
    );
    assert_eq!(store.events(), [Event::Opened, Event::Listed]);

    let store = FakeStore::with_services(vec![
        product("service-a", "Wi-Fi"),
        FakeService::configured(
            "service-c",
            "Ethernet",
            Proxies::every_protocol("127.0.0.1", 7891),
        ),
    ]);
    let error = recover_legacy_proxy(|| store.open(), &planned).expect_err("a foreign state");
    assert_eq!(
        error.to_string(),
        "network service Ethernet is neither exact-product-applied nor cleared"
    );
    assert_eq!(store.events(), [Event::Opened, Event::Listed]);
}

#[test]
fn absence_holds_when_no_service_carries_an_owned_endpoint() {
    let store = FakeStore::with_services(vec![
        cleared("service-a", "Wi-Fi"),
        FakeService::new("service-b", "Thunderbolt Bridge", FakeProxies::NoProtocol),
        FakeService::new("service-c", "VPN", FakeProxies::Unconfigured),
        // Another product's proxy on a port the retired installation never
        // owned is not evidence about it.
        FakeService::configured(
            "service-d",
            "Ethernet",
            Proxies::every_protocol("127.0.0.1", 7891).with(pac_enable_key(), number(1)),
        ),
    ]);
    verify_no_legacy_owned_proxy(|| store.open(), &[PORT, 7902], false).expect("absent");
    assert_eq!(store.events(), [Event::Opened, Event::Listed]);
}

#[test]
fn absence_fails_on_any_one_protocol_left_on_an_owned_endpoint() {
    for (protocol, label, setting_name) in [
        (Protocol::Web, "HTTP proxy", "Web Proxy (HTTP)"),
        (
            Protocol::SecureWeb,
            "HTTPS proxy",
            "Secure Web Proxy (HTTPS)",
        ),
        (Protocol::Socks, "SOCKS proxy", "SOCKS Proxy"),
    ] {
        let store = FakeStore::with_services(vec![FakeService::configured(
            "service-a",
            "Wi-Fi",
            Proxies::cleared().protocol(protocol, 1, "127.0.0.1", 7902),
        )]);
        let error = verify_no_legacy_owned_proxy(|| store.open(), &[PORT, 7902], false)
            .expect_err("a protocol is left");
        assert_eq!(
            error.to_string(),
            format!(
                "network service Wi-Fi still has {label} enabled on the retired 127.0.0.1:7902 endpoint; turn off \"{setting_name}\" in System Settings > Network > Details > Proxies before confirming legacy cleanup"
            )
        );
    }
}

#[test]
fn an_enabled_pac_blocks_absence_only_while_the_retired_pac_file_remains() {
    let store = FakeStore::with_services(vec![FakeService::configured(
        "service-a",
        "Wi-Fi",
        Proxies::cleared().with(pac_enable_key(), number(1)),
    )]);
    verify_no_legacy_owned_proxy(|| store.open(), &[PORT], false).expect("not attributable");
    let error =
        verify_no_legacy_owned_proxy(|| store.open(), &[PORT], true).expect_err("attributable");
    assert_eq!(
        error.to_string(),
        "network service Wi-Fi still has PAC proxy configuration enabled while the retired installation's proxy.pac remains; turn off \"Automatic Proxy Configuration\" in System Settings > Network > Details > Proxies before confirming legacy cleanup"
    );
}

#[test]
fn absence_fails_on_a_malformed_or_unreadable_service() {
    let store = FakeStore::with_services(vec![FakeService::configured(
        "service-a",
        "Wi-Fi",
        Proxies::cleared().with(pac_enable_key(), number(5)),
    )]);
    let error =
        verify_no_legacy_owned_proxy(|| store.open(), &[PORT], true).expect_err("malformed");
    assert_eq!(
        error.to_string(),
        "PAC proxy configuration enable flag has invalid value 5; expected 0 or 1"
    );

    let [enable, ..] = Protocol::Web.keys();
    let store = FakeStore::with_services(vec![FakeService::configured(
        "service-a",
        "Wi-Fi",
        Proxies::cleared().with(enable, number(9)),
    )]);
    let error =
        verify_no_legacy_owned_proxy(|| store.open(), &[PORT], false).expect_err("malformed");
    assert_eq!(
        error.to_string(),
        "HTTP proxy enable flag has invalid value 9; expected 0 or 1"
    );

    let store = FakeStore::with_services(vec![FakeService {
        display_name: Some("Wi-Fi\t".into()),
        ..cleared("service-a", "unused")
    }]);
    let error =
        verify_no_legacy_owned_proxy(|| store.open(), &[PORT], false).expect_err("invalid name");
    assert_eq!(
        error.to_string(),
        "SC network service display name is invalid"
    );

    let store = two_product_services();
    store.fail(Step::Open);
    let error =
        verify_no_legacy_owned_proxy(|| store.open(), &[PORT], false).expect_err("no session");
    assert_eq!(error.to_string(), "fake SystemConfiguration refused Open");
}
