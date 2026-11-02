//! Credential slots, configuration identity and the cross-language contracts.

use super::*;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TunnelAddressPlanContract {
    schema_version: u8,
    ipv4_address: String,
    ipv4_prefix_length: u8,
    ipv4_dns_peer: String,
    ipv6_address: String,
    ipv6_prefix_length: u8,
    ipv6_dns_peer: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EngineOwnerSchemaContract {
    configuration_identity_schema_version: u16,
    engine_owner_schema_version: u16,
}

#[test]
fn remote_projection_contains_only_empty_placeholders_and_closed_slots() {
    let profile = shadowsocks_profile(SS_ID);
    let projected = profile
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("Shadowsocks tunnel template");
    let template: serde_json::Value =
        serde_json::from_str(projected.as_json()).expect("template JSON");
    assert_eq!(template["outbounds"][0]["password"], "");
    assert!(template.pointer("/outbounds/0/credential_ref").is_none());
    assert_eq!(projected.credential_slots().len(), 1);
    let slot = &projected.credential_slots()[0];
    assert_eq!(slot.reference().id(), SS_ID);
    assert_eq!(slot.json_pointer(), "/outbounds/0/password");

    let wire = serde_json::to_value(slot).expect("slot wire");
    assert_eq!(wire["target"], "shadowsocks_password");
    assert_eq!(
        serde_json::from_value::<CredentialSlot>(wire).expect("round trip"),
        *slot
    );
    assert!(!format!("{projected:?}").contains(projected.as_json()));
}

#[test]
fn credential_reference_changes_runtime_identity_without_changing_template_bytes() {
    let first = shadowsocks_profile(SS_ID)
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("first template");
    let second = shadowsocks_profile(SS_ID_2)
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("second template");
    assert_eq!(first.as_json(), second.as_json());
    assert_eq!(first.configuration_digest(), second.configuration_digest());
    assert_ne!(first.credential_slots(), second.credential_slots());
    assert_ne!(first.digest(), second.digest());
}

#[test]
fn slot_deserialization_rejects_pointer_kind_and_unknown_field_tampering() {
    let projected = shadowsocks_profile(SS_ID)
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("template");
    let slot = &projected.credential_slots()[0];
    let mut pointer = serde_json::to_value(slot).expect("slot");
    pointer["json_pointer"] = serde_json::Value::String("/outbounds/0/uuid".into());
    assert!(serde_json::from_value::<CredentialSlot>(pointer).is_err());

    let mut kind = serde_json::to_value(slot).expect("slot");
    kind["target"] = serde_json::Value::String("vmess_uuid".into());
    assert!(serde_json::from_value::<CredentialSlot>(kind).is_err());

    let mut unknown = serde_json::to_value(slot).expect("slot");
    unknown["secret"] = serde_json::Value::String("must-not-be-accepted".into());
    assert!(serde_json::from_value::<CredentialSlot>(unknown).is_err());
}

#[test]
fn tunnel_identity_binds_os_network_options_beyond_config_json() {
    let profile = ValidatedSingBoxProfile::direct();
    let baseline_settings = EngineSettings::default();
    let baseline = profile
        .project(PROFILE_ID, ProjectionMode::Tunnel, &baseline_settings)
        .expect("baseline tunnel");

    let mtu_settings = EngineSettings {
        tunnel_mtu: 1_400,
        ..baseline_settings.clone()
    };
    let mtu_changed = profile
        .project(PROFILE_ID, ProjectionMode::Tunnel, &mtu_settings)
        .expect("MTU tunnel");
    assert_ne!(baseline.as_json(), mtu_changed.as_json());
    assert_ne!(
        baseline.configuration_digest(),
        mtu_changed.configuration_digest()
    );
    assert_ne!(baseline.digest(), mtu_changed.digest());

    let bypass_settings = EngineSettings {
        bypass_private_networks: false,
        ..baseline_settings
    };
    let bypass_changed = profile
        .project(PROFILE_ID, ProjectionMode::Tunnel, &bypass_settings)
        .expect("captured private networks tunnel");
    assert_eq!(baseline.as_json(), bypass_changed.as_json());
    assert_eq!(
        baseline.configuration_digest(),
        bypass_changed.configuration_digest()
    );
    assert_ne!(baseline.digest(), bypass_changed.digest());
}

#[test]
fn release_packet_direct_host_route_is_closed_source_owned_and_identity_bound() {
    assert_eq!(
        ValidatedSingBoxProfile::parse(
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"direct_ipv4_hosts":["35.194.216.98"]}"#,
        )
        .expect_err("an imported profile cannot request a host route"),
        ConfigError::UnsupportedTopLevelKey("direct_ipv4_hosts".to_owned())
    );

    let ordinary = ValidatedSingBoxProfile::direct()
        .project(
            PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("ordinary tunnel");
    assert!(ordinary.direct_ipv4_hosts().is_empty());

    let included =
        ValidatedSingBoxProfile::release_packet_evidence(ReleasePacketEvidenceCase::IncludedRoutes)
            .project(
                PROFILE_ID,
                ProjectionMode::Tunnel,
                &EngineSettings::default(),
            )
            .expect("included-routes projection");
    let excluded =
        ValidatedSingBoxProfile::release_packet_evidence(ReleasePacketEvidenceCase::ExcludedRoutes)
            .project(
                PROFILE_ID,
                ProjectionMode::Tunnel,
                &EngineSettings::default(),
            )
            .expect("excluded-routes projection");

    assert!(included.direct_ipv4_hosts().is_empty());
    assert_eq!(
        excluded.direct_ipv4_hosts().as_slice(),
        &[RELEASE_PACKET_TRANSPORT_IPV4]
    );
    assert_eq!(included.as_json(), excluded.as_json());
    assert_eq!(
        included.configuration_digest(),
        excluded.configuration_digest()
    );
    assert_ne!(included.digest(), excluded.digest());

    for case in ReleasePacketEvidenceCase::ALL {
        let projected = ValidatedSingBoxProfile::release_packet_evidence(case)
            .project(
                PROFILE_ID,
                ProjectionMode::Tunnel,
                &EngineSettings::default(),
            )
            .expect("fixed Packet projection");
        assert_eq!(
            projected.direct_ipv4_hosts().is_empty(),
            case != ReleasePacketEvidenceCase::ExcludedRoutes
        );
    }

    assert_eq!(
        ValidatedSingBoxProfile::release_packet_evidence(ReleasePacketEvidenceCase::ExcludedRoutes)
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect_err("Packet evidence cannot project into System Proxy"),
        ConfigError::InvalidReleasePacketEvidenceMode
    );
}

#[test]
fn direct_ipv4_host_route_wire_value_rejects_duplicates_and_noncanonical_inputs() {
    let empty: DirectIpv4HostRoutes = serde_json::from_str("[]").expect("empty route set");
    assert!(empty.is_empty());
    let exact: DirectIpv4HostRoutes =
        serde_json::from_str(r#"["35.194.216.98"]"#).expect("exact route set");
    assert_eq!(exact.as_slice(), &[RELEASE_PACKET_TRANSPORT_IPV4]);
    assert_eq!(
        serde_json::to_string(&exact).expect("canonical routes"),
        r#"["35.194.216.98"]"#
    );

    for invalid in [
        r#"["35.194.216.98","35.194.216.98"]"#,
        r#"["035.194.216.98"]"#,
        r#"["35.194.216.99"]"#,
        r#"["35.194.216.98","1.1.1.1"]"#,
    ] {
        assert!(
            serde_json::from_str::<DirectIpv4HostRoutes>(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn rust_tunnel_address_plan_matches_the_cross_language_contract() {
    let contract: TunnelAddressPlanContract = serde_json::from_str(include_str!(
        "../../../../../contracts/tunnel-address-plan-v1.json"
    ))
    .expect("canonical tunnel address plan");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.ipv4_address, TUNNEL_ADDRESS_PLAN.ipv4_address);
    assert_eq!(
        contract.ipv4_prefix_length,
        TUNNEL_ADDRESS_PLAN.ipv4_prefix_length
    );
    assert_eq!(contract.ipv4_dns_peer, TUNNEL_ADDRESS_PLAN.ipv4_dns_peer);
    assert_eq!(contract.ipv6_address, TUNNEL_ADDRESS_PLAN.ipv6_address);
    assert_eq!(
        contract.ipv6_prefix_length,
        TUNNEL_ADDRESS_PLAN.ipv6_prefix_length
    );
    assert_eq!(contract.ipv6_dns_peer, TUNNEL_ADDRESS_PLAN.ipv6_dns_peer);
}

#[test]
fn configuration_identity_schema_matches_the_engine_owner_contract() {
    let contract: EngineOwnerSchemaContract = serde_json::from_str(include_str!(
        "../../../../../contracts/engine-owner-v7/schema-policy.json"
    ))
    .expect("engine owner schema contract");
    assert_eq!(
        contract.configuration_identity_schema_version,
        CONFIGURATION_IDENTITY_SCHEMA_VERSION
    );
    assert_eq!(contract.engine_owner_schema_version, 7);

    let projected = ValidatedSingBoxProfile::direct()
        .project(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("direct projection");
    let identity = crate::validation::canonicalize(serde_json::json!({
        "configuration_sha256": projected.configuration_digest(),
        "credential_audience": projected.credential_audience(),
        "credential_slots": projected.credential_slots(),
        "mode": "system_proxy",
        "network_options": null,
        "schema_version": CONFIGURATION_IDENTITY_SCHEMA_VERSION,
    }));
    let expected = crate::sha256_hex(
        serde_json::to_string(&identity)
            .expect("configuration identity JSON")
            .as_bytes(),
    );
    assert_eq!(projected.digest(), expected);
}
