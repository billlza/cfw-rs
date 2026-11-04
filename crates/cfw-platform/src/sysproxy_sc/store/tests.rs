use super::*;
use crate::sysproxy_sc::test_support::{FakeProxies, FakeService, FakeStore, Step};

fn identity(service_id: &str, display_name: &str) -> LegacyProxyServiceIdentity {
    LegacyProxyServiceIdentity {
        service_id: service_id.into(),
        display_name: display_name.into(),
    }
}

#[test]
fn identity_text_must_be_bounded_trimmed_printable_text() {
    let longest = "x".repeat(MAX_IDENTITY_BYTES);
    for valid in ["Wi-Fi", "USB 10/100/1000 LAN", longest.as_str()] {
        validate_identity_text("service display name", valid).expect(valid);
    }
    let too_long = "x".repeat(MAX_IDENTITY_BYTES + 1);
    for invalid in ["", " Wi-Fi", "Wi-Fi\n", "Wi\u{7}Fi", too_long.as_str()] {
        let error = validate_identity_text("service display name", invalid)
            .expect_err("invalid identity text");
        assert_eq!(
            error.to_string(),
            "SC network service display name is invalid"
        );
    }
}

#[test]
fn a_service_is_named_by_its_identifier_when_it_has_no_name() {
    let store = FakeStore::with_services(vec![
        FakeService {
            display_name: None,
            ..FakeService::new("service-a", "unused", FakeProxies::NoProtocol)
        },
        FakeService {
            identifier: None,
            ..FakeService::new("unused", "Wi-Fi", FakeProxies::NoProtocol)
        },
        FakeService::new("service-c", "Wi-Fi\n", FakeProxies::NoProtocol),
    ]);
    let session = store.open().expect("session");
    let services = current_services(&session).expect("services");

    let id = service_id(&services[0]).expect("identifier");
    assert_eq!(id, "service-a");
    assert_eq!(service_name(&services[0], &id).expect("name"), "service-a");

    let error = service_id(&services[1]).expect_err("a service without an identifier");
    assert_eq!(
        error.to_string(),
        "SC network service has no stable identifier"
    );

    let error = service_name(&services[2], "service-c").expect_err("an invalid name");
    assert_eq!(
        error.to_string(),
        "SC network service display name is invalid"
    );
}

#[test]
fn the_current_set_is_refused_beyond_its_safety_bound() {
    let services = |count: usize| {
        (0..count)
            .map(|index| {
                FakeService::new(
                    &format!("service-{index}"),
                    "Wi-Fi",
                    FakeProxies::NoProtocol,
                )
            })
            .collect::<Vec<_>>()
    };
    let store = FakeStore::with_services(services(MAX_SERVICES));
    let session = store.open().expect("session");
    assert_eq!(
        current_services(&session).expect("bounded set").len(),
        MAX_SERVICES
    );

    let store = FakeStore::with_services(services(MAX_SERVICES + 1));
    let session = store.open().expect("session");
    let error = current_services(&session).err().expect("an oversized set");
    assert_eq!(
        error.to_string(),
        "current network service count exceeds the cutover safety bound"
    );

    let store = FakeStore::default();
    store.fail(Step::List);
    let session = store.open().expect("session");
    let error = current_services(&session).err().expect("a failed listing");
    assert_eq!(error.to_string(), "fake SystemConfiguration refused List");
}

#[test]
fn a_planned_service_is_found_only_under_its_identifier_and_name() {
    let store = FakeStore::with_services(vec![
        FakeService {
            identifier: None,
            ..FakeService::new("unused", "Wi-Fi", FakeProxies::NoProtocol)
        },
        FakeService::new("service-a", "Ethernet", FakeProxies::NoProtocol),
        FakeService::new("service-b", "Wi-Fi", FakeProxies::NoProtocol),
    ]);
    let session = store.open().expect("session");
    let services = current_services(&session).expect("services");

    let found = find_service(&services, &identity("service-b", "Wi-Fi")).expect("found");
    assert_eq!(found.identifier().as_deref(), Some("service-b"));

    let error = find_service(&services, &identity("service-z", "Wi-Fi"))
        .err()
        .expect("a missing service");
    assert_eq!(
        error.to_string(),
        "SC network service identity disappeared: service-z"
    );

    let error = find_service(&services, &identity("service-a", "Wi-Fi"))
        .err()
        .expect("a renamed service");
    assert_eq!(
        error.to_string(),
        "SC network service service-a changed display identity during cutover"
    );
}
