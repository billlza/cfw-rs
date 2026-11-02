use super::*;

#[test]
fn plan_contains_only_live_service_identity_and_product_port() {
    let plan = LegacyProxyCutoverPlan {
        services: vec![LegacyProxyServiceIdentity {
            service_id: "service-uuid".into(),
            display_name: "Wi-Fi".into(),
        }],
        expected_port: 7890,
    };

    assert_eq!(plan.service_ids().collect::<Vec<_>>(), ["service-uuid"]);
    assert_eq!(plan.expected_port(), 7890);
    // There is deliberately no field capable of carrying attacker-chosen
    // historical hosts, ports, bypass domains, PAC URLs, or WPAD state.
    assert_eq!(std::mem::size_of_val(&plan.expected_port), 2);
}

fn identity(service_id: &str, display_name: &str) -> LegacyProxyServiceIdentity {
    LegacyProxyServiceIdentity {
        service_id: service_id.into(),
        display_name: display_name.into(),
    }
}

#[test]
fn a_recovered_plan_keeps_its_services_in_order() {
    let plan = LegacyProxyCutoverPlan::for_recovery(
        vec![
            identity("service-a", "Wi-Fi"),
            identity("service-b", "Ethernet"),
        ],
        7890,
    )
    .expect("a valid plan");
    assert_eq!(plan.expected_port(), 7890);
    assert_eq!(
        plan.services()
            .iter()
            .map(|service| (service.service_id(), service.display_name()))
            .collect::<Vec<_>>(),
        [("service-a", "Wi-Fi"), ("service-b", "Ethernet")]
    );
}

#[test]
fn a_recovered_plan_is_validated_before_any_use() {
    for (services, port, message) in [
        (
            vec![identity("service-a", "Wi-Fi")],
            0,
            "legacy proxy cutover plan is invalid",
        ),
        (vec![], 7890, "legacy proxy cutover plan is invalid"),
        (
            vec![
                identity("service-a", "Wi-Fi"),
                identity("service-a", "Ethernet"),
            ],
            7890,
            "legacy proxy cutover plan has duplicate service identifiers",
        ),
        (
            vec![identity("service-a", " Wi-Fi")],
            7890,
            "SC network service display name is invalid",
        ),
    ] {
        let error = LegacyProxyCutoverPlan::for_recovery(services, port).expect_err(message);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn a_recorded_plan_round_trips_and_refuses_unknown_fields() {
    let service = identity("service-a", "Wi-Fi");
    let encoded = serde_json::to_value(&service).expect("encode");
    assert_eq!(
        encoded,
        serde_json::json!({ "service_id": "service-a", "display_name": "Wi-Fi" })
    );
    assert_eq!(
        serde_json::from_value::<LegacyProxyServiceIdentity>(encoded).expect("decode"),
        service
    );
    let error = serde_json::from_value::<LegacyProxyServiceIdentity>(serde_json::json!({
        "service_id": "service-a",
        "display_name": "Wi-Fi",
        "proxy_host": "attacker.invalid",
    }))
    .expect_err("an unknown field");
    assert!(error.to_string().contains("proxy_host"), "{error}");
}

#[test]
fn preparation_requires_an_applied_port_before_reading_preferences() {
    let error = MacOsPlatformService
        .prepare_legacy_proxy_cutover(0)
        .expect_err("no port");
    assert_eq!(
        error.to_string(),
        "legacy proxy ownership requires a non-zero applied port"
    );
}

#[test]
fn absence_requires_a_recorded_endpoint_before_reading_preferences() {
    let error = MacOsPlatformService
        .verify_no_legacy_owned_proxy(&[], false)
        .expect_err("no endpoint");
    assert!(
        error.to_string().contains("owned proxy port is unknown"),
        "{error}"
    );
}
