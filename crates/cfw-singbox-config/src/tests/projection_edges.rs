//! Projection settings at their edges, and the profile accessors the shell
//! reads.

use serde_json::{Value, json};

use crate::{
    AuthenticatedDnsServer, ConfigError, EngineLogLevel, EngineSettings, ProjectionMode,
    ValidatedSingBoxProfile,
};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SHADOWSOCKS_ID: &str = "11111111-1111-4111-8111-111111111111";
const TROJAN_ID: &str = "33333333-3333-4333-8333-333333333333";

fn trojan() -> Value {
    json!({"type":"trojan","tag":"trojan","server":"trojan.example.com","server_port":443,
        "credential_ref":{"id":TROJAN_ID,"kind":"trojan_password"},
        "tls":{"enabled":true,"server_name":"trojan.example.com"}})
}

fn parse(outbounds: Value) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(
        &json!({"outbounds": outbounds, "route": {"final": "trojan"}}).to_string(),
    )
    .expect("profile")
}

fn project(
    profile: &ValidatedSingBoxProfile,
    mode: ProjectionMode,
    settings: &EngineSettings,
) -> Result<Value, ConfigError> {
    let projected = profile.project(PROFILE_ID, mode, settings)?;
    Ok(serde_json::from_str(projected.as_json()).expect("runtime JSON"))
}

#[test]
fn silent_logging_disables_the_runtime_log() {
    let settings = EngineSettings {
        log_level: EngineLogLevel::Silent,
        ..EngineSettings::default()
    };
    let config = project(
        &parse(json!([trojan()])),
        ProjectionMode::SystemProxy,
        &settings,
    )
    .expect("projection");
    assert_eq!(config["log"], json!({"disabled": true}));
}

#[test]
fn tunnel_mtu_stays_within_1280_and_9000() {
    let profile = parse(json!([trojan()]));
    let with_mtu = |tunnel_mtu| EngineSettings {
        tunnel_mtu,
        ..EngineSettings::default()
    };
    for mtu in [1_280, 9_000] {
        let config =
            project(&profile, ProjectionMode::Tunnel, &with_mtu(mtu)).expect("bounded MTU");
        assert_eq!(config["inbounds"][0]["mtu"], mtu);
    }
    for mtu in [1_279, 9_001] {
        assert!(matches!(
            project(&profile, ProjectionMode::Tunnel, &with_mtu(mtu)),
            Err(ConfigError::InvalidTunnelMtu(actual)) if actual == mtu
        ));
    }
}

#[test]
fn authenticated_dns_pools_admit_only_reachable_ipv6_endpoints() {
    let profile = parse(json!([trojan()]));
    let pool = |address: &str| {
        [
            AuthenticatedDnsServer {
                address: address.parse().expect("IP address"),
                server_name: "dns.example.com".into(),
            },
            AuthenticatedDnsServer {
                address: "1.1.1.1".parse().unwrap(),
                server_name: "one.one.one.one".into(),
            },
        ]
    };
    let settings = |enable_ipv6, address: &str| EngineSettings {
        enable_ipv6,
        authenticated_dns_servers: pool(address),
        ..EngineSettings::default()
    };
    let rejected = |settings: &EngineSettings| match project(
        &profile,
        ProjectionMode::SystemProxy,
        settings,
    ) {
        Err(ConfigError::InvalidAuthenticatedDnsServers(reason)) => reason,
        other => panic!("unexpected projection result {other:?}"),
    };
    project(
        &profile,
        ProjectionMode::SystemProxy,
        &settings(true, "2606:4700:4700::1111"),
    )
    .expect("a public IPv6 resolver");
    assert!(
        rejected(&settings(false, "2606:4700:4700::1111"))
            .contains("is unavailable while IPv6 is disabled")
    );
    for address in ["::", "::1", "fe80::1", "ff02::1", "2001:db8::53"] {
        assert!(
            rejected(&settings(true, address)).contains("has an unusable address"),
            "{address}"
        );
    }
}

#[test]
fn http_transports_project_every_request_method() {
    for method in ["GET", "PUT", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
        let mut outbound = trojan();
        outbound["transport"] = json!({"type":"http","method":method,"path":"/tunnel"});
        let config = project(
            &parse(json!([outbound])),
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("projection");
        let projected = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["tag"] == "trojan")
            .expect("projected trojan");
        assert_eq!(projected["transport"]["method"], method);
    }
}

#[test]
fn proxy_probe_debug_redacts_its_template() {
    let probe = parse(json!([trojan()]))
        .project_proxy_probe(
            PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("probe");
    let rendered = format!("{probe:?}");
    assert!(
        rendered.contains("[REDACTED CONFIG TEMPLATE]"),
        "{rendered}"
    );
    assert!(!rendered.contains("trojan.example.com"), "{rendered}");
}

#[test]
fn credential_references_follow_the_outbound_order() {
    let shadowsocks = json!({"type":"shadowsocks","tag":"ss","server":"ss.example.com","server_port":443,
        "method":"aes-256-gcm","credential_ref":{"id":SHADOWSOCKS_ID,"kind":"shadowsocks_password"}});
    let profile = parse(json!([trojan(), shadowsocks]));
    let ids = profile
        .credential_references_in_outbound_order()
        .iter()
        .map(|reference| reference.id().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(ids, [TROJAN_ID, SHADOWSOCKS_ID]);
}

#[test]
fn vmess_alter_ids_encode_as_their_protocol_numbers() {
    use crate::profile::VmessAlterId;
    assert_eq!(u8::from(VmessAlterId::Aead), 0);
    assert_eq!(u8::from(VmessAlterId::Legacy), 1);
    assert_eq!(VmessAlterId::try_from(0), Ok(VmessAlterId::Aead));
    assert!(VmessAlterId::try_from(2).is_err());
}
