//! Credential references: canonical ids, closed kinds and redacted secrets.

use super::*;

#[test]
fn credentials_are_rejected_until_keychain_projection_exists() {
    for key in ["password", "private_key", "token", "uuid", "auth_key"] {
        let input = format!(r#"{{"outbounds":[{{"type":"direct","{key}":"sensitive"}}]}}"#);
        let error = ValidatedSingBoxProfile::parse(&input)
            .expect_err("credentials must never be persisted in profile JSON");
        assert!(matches!(
            error,
            ConfigError::CredentialRequiresKeychain { key: rejected, .. } if rejected == key
        ));
    }
}

#[test]
fn typed_remote_outbounds_persist_only_canonical_credential_references() {
    let input = format!(
        r#"{{
          "outbounds": [
            {{"type":"shadowsocks","tag":"ss","server":"ss.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
            {{"type":"vmess","tag":"vmess","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"security":"auto","tls":{{"enabled":true,"server_name":"vmess.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}}}},"transport":{{"type":"ws","path":"/ws","headers":{{"Host":"vmess.example.com"}}}}}},
            {{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"flow":"xtls-rprx-vision","tls":{{"enabled":true,"server_name":"www.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}}}}},
            {{"type":"trojan","tag":"trojan","server":"trojan.example.com","server_port":443,"credential_ref":{{"id":"{TROJAN_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"trojan.example.com"}},"transport":{{"type":"grpc","service_name":"tunnel"}}}},
            {{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}},"up_mbps":100,"down_mbps":200,"obfs":{{"type":"salamander","credential_ref":{{"id":"{HYSTERIA_OBFS_ID}","kind":"hysteria2_obfs_password"}}}}}},
            {{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}},"tls":{{"enabled":true,"server_name":"anytls.example.com"}}}},
            {{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com","alpn":["h3"]}},"congestion_control":"bbr","udp_relay_mode":"quic"}}
          ],
          "route": {{"final":"ss"}}
        }}"#
    );
    let profile = ValidatedSingBoxProfile::parse(&input).expect("typed remote profile");
    let value: Value = serde_json::from_str(profile.as_json()).expect("canonical profile JSON");
    assert_eq!(value["route"]["final"], "ss");
    assert_eq!(value["outbounds"][0]["credential_ref"]["id"], SS_ID);
    assert!(!contains_key(&value, "password"));
    assert!(!contains_key(&value, "uuid"));
}

#[test]
fn cross_layer_typed_profile_fixture_uses_the_native_safe_field_shape() {
    let profile = ValidatedSingBoxProfile::parse(include_str!(
        "../../../../../contracts/typed-profile-v1.json"
    ))
    .expect("shared typed profile fixture");
    let canonical: serde_json::Value =
        serde_json::from_str(profile.as_json()).expect("canonical fixture");
    assert_eq!(canonical["outbounds"][0]["transport"]["type"], "ws");
    assert_eq!(
        canonical["outbounds"][0]["transport"]["headers"]["Host"],
        "vmess.example.com"
    );
    assert_eq!(canonical["outbounds"][0]["tls"]["utls"]["enabled"], true);
    assert_eq!(canonical["outbounds"][1]["tls"]["reality"]["enabled"], true);
}

#[test]
fn typed_profiles_reject_unknown_fields_and_wrong_credential_kinds() {
    let unknown = format!(
        r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}},"plugin":"unsafe"}}]}}"#
    );
    assert!(ValidatedSingBoxProfile::parse(&unknown).is_err());

    let wrong_kind = format!(
        r#"{{"outbounds":[{{"type":"vmess","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"trojan_password"}}}}]}}"#
    );
    assert!(matches!(
        ValidatedSingBoxProfile::parse(&wrong_kind),
        Err(ConfigError::CredentialKindMismatch { .. })
    ));

    let noncanonical_id = r#"{"outbounds":[{"type":"vmess","tag":"proxy","server":"example.com","server_port":443,"credential_ref":{"id":"22222222222242228222222222222222","kind":"vmess_uuid"}}]}"#;
    assert!(ValidatedSingBoxProfile::parse(noncanonical_id).is_err());
}

#[test]
fn one_credential_id_cannot_cross_protocol_kinds() {
    let input = format!(
        r#"{{"outbounds":[
          {{"type":"shadowsocks","tag":"ss","server":"one.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
          {{"type":"trojan","tag":"trojan","server":"two.example.com","server_port":443,"credential_ref":{{"id":"{SS_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"two.example.com"}}}}
        ]}}"#
    );
    assert!(matches!(
        ValidatedSingBoxProfile::parse(&input),
        Err(ConfigError::ConflictingCredentialReference { id }) if id == SS_ID
    ));
}

#[test]
fn borrowed_secret_debug_is_redacted_and_not_serializable() {
    let secret = CredentialSecret::new("never-log-this-secret").expect("bounded secret");
    assert_eq!(format!("{secret:?}"), "CredentialSecret([REDACTED])");
    assert_eq!(secret.expose_to_vault(), "never-log-this-secret");
}

#[test]
fn uuid_credentials_require_canonical_hyphenated_values() {
    let canonical =
        CredentialSecret::new("11111111-1111-4111-8111-111111111111").expect("bounded UUID secret");
    for kind in [
        CredentialKind::VmessUuid,
        CredentialKind::VlessUuid,
        CredentialKind::TuicUuid,
    ] {
        canonical
            .validate_for_kind(kind)
            .expect("canonical UUID credential");
    }

    for value in [
        "not-a-uuid",
        "11111111111141118111111111111111",
        "11111111-1111-4111-8111-11111111111A",
    ] {
        let invalid = CredentialSecret::new(value).expect("bounded invalid UUID secret");
        for kind in [
            CredentialKind::VmessUuid,
            CredentialKind::VlessUuid,
            CredentialKind::TuicUuid,
        ] {
            assert!(
                invalid.validate_for_kind(kind).is_err(),
                "{kind:?}: {value}"
            );
        }
    }
}

fn contains_key(value: &Value, expected: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(expected)
                || object.values().any(|value| contains_key(value, expected))
        }
        Value::Array(values) => values.iter().any(|value| contains_key(value, expected)),
        _ => false,
    }
}
