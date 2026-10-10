use serde_json::{Value, json};

use crate::{
    CredentialKind, CredentialSecret, EngineSettings, ProjectionMode, ValidatedSingBoxProfile,
};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const USERNAME_ID: &str = "11111111-1111-4111-8111-111111111111";
const PASSWORD_ID: &str = "22222222-2222-4222-8222-222222222222";

fn socks5_outbound() -> Value {
    json!({"type":"socks5","tag":"proxy","server":"proxy.example.com","server_port":1080})
}

fn authentication() -> Value {
    json!({
        "username_credential_ref":{"id":USERNAME_ID,"kind":"socks5_username"},
        "password_credential_ref":{"id":PASSWORD_ID,"kind":"socks5_password"}
    })
}

fn parse(outbound: Value) -> Result<ValidatedSingBoxProfile, crate::ConfigError> {
    ValidatedSingBoxProfile::parse(&json!({"outbounds":[outbound]}).to_string())
}

#[test]
fn socks5_anonymous_projection_uses_v5_and_no_credential_placeholders() {
    for server in ["proxy.example.com", "9.9.9.9", "2606:4700:4700::1111"] {
        let mut outbound = socks5_outbound();
        outbound["server"] = json!(server);
        let profile = parse(outbound).expect("SOCKS5 endpoint");
        assert!(profile.routes_through_remote());
        assert!(profile.credential_references().is_empty());
        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            let projection = profile
                .project(PROFILE_ID, mode, &EngineSettings::default())
                .expect("SOCKS5 projection");
            let wire: Value = serde_json::from_str(projection.as_json()).expect("runtime JSON");
            let node = &wire["outbounds"][0];
            assert_eq!(node["type"], "socks");
            assert_eq!(node["version"], "5");
            assert_eq!(node["server"], server);
            assert_eq!(node["server_port"], 1080);
            assert!(node.get("username").is_none());
            assert!(node.get("password").is_none());
            assert!(node.get("network").is_none());
            assert!(projection.credential_slots().is_empty());
        }
    }
}

#[test]
fn socks5_endpoints_preserve_the_existing_destination_boundary() {
    for server in [
        "127.0.0.1",
        "::1",
        "192.0.2.10",
        "2001:db8::1",
        "169.254.1.1",
    ] {
        let mut outbound = socks5_outbound();
        outbound["server"] = json!(server);
        assert!(
            parse(outbound).is_err(),
            "SOCKS5 must not bypass endpoint admission"
        );
    }
    let mut outbound = socks5_outbound();
    outbound["server_port"] = json!(0);
    assert!(parse(outbound).is_err());
}

#[test]
fn socks5_authenticated_projection_has_two_typed_vault_slots() {
    let mut outbound = socks5_outbound();
    outbound["authentication"] = authentication();
    let profile = parse(outbound).expect("authenticated SOCKS5 profile");
    assert_eq!(profile.credential_references().len(), 2);
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projection = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("authenticated projection");
        let wire: Value = serde_json::from_str(projection.as_json()).expect("runtime JSON");
        assert_eq!(wire["outbounds"][0]["username"], "");
        assert_eq!(wire["outbounds"][0]["password"], "");
        let slots = serde_json::to_value(projection.credential_slots()).expect("slot JSON");
        assert_eq!(slots[0]["target"], "socks5_username");
        assert_eq!(slots[0]["json_pointer"], "/outbounds/0/username");
        assert_eq!(slots[0]["reference"]["id"], USERNAME_ID);
        assert_eq!(slots[1]["target"], "socks5_password");
        assert_eq!(slots[1]["json_pointer"], "/outbounds/0/password");
        assert_eq!(slots[1]["reference"]["id"], PASSWORD_ID);
    }
}

#[test]
fn socks5_network_restrictions_are_preserved() {
    for network in ["tcp", "udp"] {
        let mut outbound = socks5_outbound();
        outbound["network"] = json!(network);
        let profile = parse(outbound).expect("SOCKS5 network restriction");
        let projection = profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("network projection");
        let wire: Value = serde_json::from_str(projection.as_json()).expect("runtime JSON");
        assert_eq!(wire["outbounds"][0]["network"], network);
    }
    for network in ["", "tcp,udp", "quic"] {
        let mut outbound = socks5_outbound();
        outbound["network"] = json!(network);
        assert!(
            parse(outbound).is_err(),
            "unsupported network must not widen silently"
        );
    }
}

#[test]
fn socks5_authentication_rejects_partial_wrong_kind_and_shared_reference_pairs() {
    for field in ["username_credential_ref", "password_credential_ref"] {
        let mut outbound = socks5_outbound();
        outbound["authentication"] = authentication();
        outbound["authentication"]
            .as_object_mut()
            .expect("authentication")
            .remove(field);
        assert!(
            parse(outbound).is_err(),
            "partial authentication must not become anonymous"
        );

        let mut outbound = socks5_outbound();
        outbound["authentication"] = authentication();
        outbound["authentication"][field]["kind"] = json!("trojan_password");
        assert!(parse(outbound).is_err(), "wrong credential kind");
    }
    let mut outbound = socks5_outbound();
    outbound["authentication"] = authentication();
    outbound["authentication"]["password_credential_ref"]["id"] = json!(USERNAME_ID);
    assert!(
        parse(outbound).is_err(),
        "username and password must have separate typed identities"
    );
}

#[test]
fn socks5_stored_profiles_reject_inline_credentials_and_transport_extensions() {
    for (field, value) in [
        ("username", json!("synthetic-user")),
        ("password", json!("synthetic-secret")),
        ("version", json!("4")),
        ("tls", json!({"enabled":true})),
        ("udp_over_tcp", json!(true)),
    ] {
        let mut outbound = socks5_outbound();
        outbound[field] = value;
        let error = parse(outbound).expect_err("unsupported SOCKS5 field");
        assert!(!error.to_string().contains("synthetic-secret"));
        assert!(!error.to_string().contains("synthetic-user"));
    }
}

#[test]
fn socks5_credentials_enforce_rfc1929_utf8_byte_bounds() {
    for kind in ["socks5_username", "socks5_password"] {
        let kind: CredentialKind =
            serde_json::from_value(json!(kind)).expect("SOCKS5 credential kind");
        for value in ["x".to_owned(), "x".repeat(255), "界".repeat(85)] {
            CredentialSecret::new(&value)
                .expect("valid text")
                .validate_for_kind(kind)
                .expect("1..=255 bytes");
        }
        for value in ["x".repeat(256), "界".repeat(86)] {
            assert!(
                CredentialSecret::new(&value)
                    .expect("bounded general secret")
                    .validate_for_kind(kind)
                    .is_err()
            );
        }
        assert!(CredentialSecret::new("").is_err());
        assert!(CredentialSecret::new("bad\nsecret").is_err());
    }
}
