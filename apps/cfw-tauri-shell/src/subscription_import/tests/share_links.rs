//! Other share links: legacy formats, the transport matrix, AnyTLS and TUIC,
//! and the TLS semantics links must not leave unrepresented.

use super::*;

#[test]
fn legacy_uri_formats_reject_unrepresented_or_ambiguous_semantics() {
    for (label, uri, expected) in [
        (
            "Shadowsocks unknown parameter",
            "ss://YWVzLTI1Ni1nY206VG9wU2VjcmV0VmFsdWUh@ss.example.com:8388?uot=1#S",
            "unsupported parameters",
        ),
        (
            "VLESS duplicate SNI",
            "vless://11111111-1111-4111-8111-111111111111@v.example:443?security=tls&sni=one.example&sni=two.example#V",
            "repeats query parameter",
        ),
        (
            "VLESS packet encoding",
            "vless://11111111-1111-4111-8111-111111111111@v.example:443?packetEncoding=TopSecretValue123#V",
            "packet encoding is unsupported",
        ),
        (
            "VLESS encryption",
            "vless://11111111-1111-4111-8111-111111111111@v.example:443?encryption=mlkem768x25519plus#V",
            "encryption is unsupported",
        ),
        (
            "Trojan HTTP header",
            "trojan://TopSecretValue%21@t.example:443?type=tcp&headerType=http#T",
            "header type is unsupported",
        ),
        (
            "Trojan TCP path",
            "trojan://TopSecretValue%21@t.example:443?type=tcp&path=%2Fws#T",
            "unsupported options",
        ),
        (
            "QUIC transport options",
            "vless://11111111-1111-4111-8111-111111111111@v.example:443?type=quic&path=%2Fhidden#V",
            "QUIC subscription transport declares unsupported options",
        ),
    ] {
        let error = import_subscription_document(uri).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
        assert!(!error.contains("TopSecretValue123"), "{label}: {error}");
    }
}

#[test]
fn imports_closed_http_httpupgrade_and_quic_transport_matrix() {
    let vmess_quic = json!({
        "v": "2",
        "ps": "VMess QUIC",
        "add": "vmess.example.com",
        "port": "443",
        "id": SYNTHETIC_VM_UUID,
        "aid": "0",
        "net": "quic",
        "type": "none",
        "tls": "tls",
        "sni": "vmess.example.com"
    });
    let document = format!(
        "vless://11111111-1111-4111-8111-111111111111@v.example:443?type=http&method=GET&path=%2Fh2&host=one.example%2Ctwo.example&headerType=none#HTTP\n\
         trojan://TopSecretValue%21@t.example:443?type=httpupgrade&path=%2Fup&host=edge.example#Upgrade\n\
         vmess://{}",
        STANDARD.encode(vmess_quic.to_string())
    );
    let imported = import_subscription_document(&document).expect("V2Ray transport matrix");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical transport profile");
    let outbounds = profile["outbounds"]
        .as_array()
        .expect("transport outbounds");
    assert_eq!(outbounds[0]["transport"]["type"], "http");
    assert_eq!(outbounds[0]["transport"]["method"], "GET");
    assert_eq!(
        outbounds[0]["transport"]["host"],
        json!(["one.example", "two.example"])
    );
    assert_eq!(outbounds[1]["transport"]["type"], "http_upgrade");
    assert_eq!(outbounds[1]["transport"]["host"], "edge.example");
    assert_eq!(outbounds[2]["transport"]["type"], "quic");

    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = imported
            .profile
            .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
            .expect("transport matrix projection");
        let runtime: Value =
            serde_json::from_str(projected.as_json()).expect("runtime transport projection");
        assert_eq!(runtime["outbounds"][0]["transport"]["type"], "http");
        assert_eq!(runtime["outbounds"][0]["transport"]["method"], "GET");
        assert_eq!(runtime["outbounds"][1]["transport"]["type"], "httpupgrade");
        assert_eq!(runtime["outbounds"][2]["transport"]["type"], "quic");
    }
}

#[test]
fn imports_anytls_and_tuic_links_with_closed_options_and_vault_credentials() {
    let imported = import_subscription_document(
        "anytls://any%3Atls-secret@anytls.example.com:443?security=tls&sni=front.example.com&alpn=h2,http%2F1.1&fp=chrome&insecure=0#AnyTLS\ntuic://11111111-1111-4111-8111-111111111111:tuic%3Asecret@tuic.example.com:10443?security=tls&sni=tuic.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=quic&zero_rtt_handshake=false&udp_over_stream=0#TUIC",
    )
    .expect("AnyTLS and TUIC URIs");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    let outbounds = profile["outbounds"].as_array().expect("outbounds");
    assert_eq!(outbounds.len(), 2);
    assert_eq!(outbounds[0]["type"], "anytls");
    assert_eq!(outbounds[0]["tls"]["server_name"], "front.example.com");
    assert_eq!(outbounds[0]["tls"]["alpn"], json!(["h2", "http/1.1"]));
    assert_eq!(outbounds[0]["tls"]["utls"]["fingerprint"], "chrome");
    assert_eq!(outbounds[1]["type"], "tuic");
    assert_eq!(outbounds[1]["congestion_control"], "bbr");
    assert_eq!(outbounds[1]["udp_relay_mode"], "quic");
    assert_eq!(outbounds[1]["tls"]["alpn"], json!(["h3"]));

    assert_eq!(imported.credentials.len(), 3);
    assert_eq!(
        imported.credentials[0].reference.kind(),
        CredentialKind::AnyTlsPassword
    );
    assert_eq!(imported.credentials[0].secret, "any:tls-secret");
    assert_eq!(
        imported.credentials[1].reference.kind(),
        CredentialKind::TuicUuid
    );
    assert_eq!(
        imported.credentials[1].secret,
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(
        imported.credentials[2].reference.kind(),
        CredentialKind::TuicPassword
    );
    assert_eq!(imported.credentials[2].secret, "tuic:secret");
    for secret in [
        "any:tls-secret",
        "11111111-1111-4111-8111-111111111111",
        "tuic:secret",
    ] {
        assert!(!imported.profile.as_json().contains(secret));
    }

    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = imported
            .profile
            .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
            .expect("runtime projection");
        assert_eq!(projected.credential_slots().len(), 3);
        assert_eq!(
            projected.credential_slots()[0].json_pointer(),
            "/outbounds/0/password"
        );
        assert_eq!(
            projected.credential_slots()[1].json_pointer(),
            "/outbounds/1/uuid"
        );
        assert_eq!(
            projected.credential_slots()[2].json_pointer(),
            "/outbounds/1/password"
        );
    }
}

#[test]
fn tls_protocol_uri_imports_fail_closed_on_unrepresented_semantics() {
    for (label, uri, expected) in [
        (
            "Hysteria2 unknown parameter",
            "hy2://TopSecretValue%21@hy2.example.com:443?TopSecretValue123=1",
            "unsupported parameters",
        ),
        (
            "Hysteria2 uTLS",
            "hy2://TopSecretValue%21@hy2.example.com:443?fp=chrome",
            "does not support uTLS",
        ),
        (
            "Hysteria2 Reality",
            "hy2://TopSecretValue%21@hy2.example.com:443?security=reality",
            "security mode is unsupported",
        ),
        (
            "Hysteria2 insecure TLS",
            "hy2://TopSecretValue%21@hy2.example.com:443?insecure=true",
            "disabling TLS certificate verification",
        ),
        (
            "Hysteria2 empty pin",
            "hy2://TopSecretValue%21@hy2.example.com:443?pinSHA256=",
            "Hysteria2 pinSHA256 must be a SHA256 hex value",
        ),
        (
            "Hysteria2 pin without a value",
            "hy2://TopSecretValue%21@hy2.example.com:443?pinSHA256",
            "Hysteria2 pinSHA256 must be a SHA256 hex value",
        ),
        (
            "Hysteria2 short pin",
            "hy2://TopSecretValue%21@hy2.example.com:443?pinSHA256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1",
            "Hysteria2 pinSHA256 must be a SHA256 hex value",
        ),
        (
            "Hysteria2 base64 pin",
            "hy2://TopSecretValue%21@hy2.example.com:443?pinSHA256=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8%3D",
            "Hysteria2 pinSHA256 must be a SHA256 hex value",
        ),
        (
            "Hysteria2 repeated pin",
            "hy2://TopSecretValue%21@hy2.example.com:443?pinSHA256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f&pinSHA256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "repeats query parameter",
        ),
        (
            "Hysteria2 pin key in another case",
            "hy2://TopSecretValue%21@hy2.example.com:443?pinsha256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "unsupported parameters",
        ),
        (
            "Hysteria2 pin with an unknown parameter",
            "hy2://TopSecretValue%21@hy2.example.com:443?pinSHA256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f&TopSecretValue123=1",
            "unsupported parameters",
        ),
        (
            "Hysteria2 insecure with a later false alias",
            "hy2://TopSecretValue%21@hy2.example.com:443?insecure=1&allowInsecure=0",
            "disabling TLS certificate verification",
        ),
        (
            "Trojan insecure with a later false alias",
            "trojan://TopSecretValue%21@trojan.example.com:443?insecure=1&skip-cert-verify=0",
            "disabling TLS certificate verification",
        ),
        (
            "Hysteria2 insecure beside a malformed pin",
            "hy2://TopSecretValue%21@hy2.example.com:443?insecure=1&pinSHA256=zz",
            "Hysteria2 pinSHA256 must be a SHA256 hex value",
        ),
        (
            "Hysteria2 insecure beside an empty pin",
            "hy2://TopSecretValue%21@hy2.example.com:443?allowInsecure=true&pinSHA256=",
            "Hysteria2 pinSHA256 must be a SHA256 hex value",
        ),
        (
            "Hysteria2 uTLS is refused before the pin is read",
            "hy2://TopSecretValue%21@hy2.example.com:443?fp=chrome&pinSHA256=zz",
            "does not support uTLS",
        ),
        (
            "VLESS pin",
            "vless://11111111-1111-4111-8111-111111111111@vless.example.com:443?security=tls&sni=vless.example.com&pinSHA256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "unsupported parameters",
        ),
        (
            "AnyTLS pin",
            "anytls://TopSecretValue%21@anytls.example.com:443?pinSHA256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "unsupported parameters",
        ),
        (
            "TUIC pin",
            "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?pinSHA256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "unsupported parameters",
        ),
        (
            "AnyTLS unknown parameter",
            "anytls://TopSecretValue%21@anytls.example.com:443?TopSecretValue123=1",
            "unsupported parameters",
        ),
        (
            "AnyTLS duplicate parameter",
            "anytls://TopSecretValue%21@anytls.example.com:443?sni=one.example.com&sni=two.example.com",
            "repeats query parameter",
        ),
        (
            "AnyTLS insecure TLS",
            "anytls://TopSecretValue%21@anytls.example.com:443?insecure=true",
            "disabling TLS certificate verification",
        ),
        (
            "TUIC missing password",
            "tuic://11111111-1111-4111-8111-111111111111@tuic.example.com:443",
            "TUIC password is missing",
        ),
        (
            "TUIC 0-RTT",
            "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?zero_rtt_handshake=true",
            "0-RTT handshake is unsupported",
        ),
        (
            "TUIC UDP-over-stream",
            "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?udp_over_stream=1",
            "UDP-over-stream is unsupported",
        ),
        (
            "TUIC uTLS",
            "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?fp=chrome",
            "unsupported parameters",
        ),
        (
            "TUIC congestion control",
            "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?congestion_control=reno",
            "congestion control is unsupported",
        ),
        (
            "TUIC UDP relay",
            "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443?udp_relay_mode=stream",
            "UDP relay mode is unsupported",
        ),
    ] {
        let error = import_subscription_document(uri).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
        assert!(!error.contains("TopSecretValue123"), "{label}: {error}");
        // Pin digits are not secret, but no error echoes a parameter value.
        assert!(!error.contains("0001020304"), "{label}: {error}");
    }
}

#[test]
fn share_links_carry_one_user_info_component_a_decodable_fragment_and_one_alias_each() {
    const VLESS: &str = "vless://11111111-1111-4111-8111-111111111111@v.example:443";
    const TUIC: &str =
        "tuic://11111111-1111-4111-8111-111111111111:TopSecretValue%21@tuic.example.com:443";
    for (uri, expected) in [
        (
            "vless://11111111-1111-4111-8111-111111111111:TopSecretValue123@v.example:443"
                .to_owned(),
            "VLESS URI must encode its UUID as the single user-info component",
        ),
        (
            "trojan://user:TopSecretValue123@t.example:443".to_owned(),
            "Trojan URI password must percent-encode reserved separators",
        ),
        (
            "hy2://user:TopSecretValue123@hy2.example.com:443".to_owned(),
            "Hysteria2 URI must encode its password as the single user-info component",
        ),
        (
            "anytls://user:TopSecretValue123@anytls.example.com:443".to_owned(),
            "AnyTLS URI must encode its password as the single user-info component",
        ),
        (
            format!("{VLESS}#%FF"),
            "VLESS URI fragment has invalid percent-encoding",
        ),
        (
            "trojan://TopSecretValue%21@t.example:443#%FF".to_owned(),
            "Trojan URI fragment has invalid percent-encoding",
        ),
        (
            "hy2://TopSecretValue%21@hy2.example.com:443#%FF".to_owned(),
            "Hysteria2 URI fragment has invalid percent-encoding",
        ),
        (
            "anytls://TopSecretValue%21@anytls.example.com:443#%FF".to_owned(),
            "AnyTLS URI fragment has invalid percent-encoding",
        ),
        (
            format!("{TUIC}#%FF"),
            "TUIC URI fragment has invalid percent-encoding",
        ),
        (
            format!("{VLESS}?packetEncoding=xudp&packet-encoding=xudp"),
            "VLESS URI repeats packet encoding using multiple aliases",
        ),
        (
            format!("{VLESS}?type=grpc&serviceName=api&service_name=api"),
            "VLESS URI repeats gRPC service name using multiple aliases",
        ),
        (
            "trojan://TopSecretValue%21@t.example:443?type=grpc&serviceName=api&service_name=api"
                .to_owned(),
            "Trojan URI repeats gRPC service name using multiple aliases",
        ),
        (
            "hy2://TopSecretValue%21@hy2.example.com:443,8443-8450?hop-interval=30&hop_interval=30"
                .to_owned(),
            "Hysteria2 URI repeats hop interval using multiple aliases",
        ),
        (
            format!("{VLESS}?security=TopSecretValue123"),
            "VLESS security mode is unsupported: <redacted>",
        ),
        (
            "hy2://TopSecretValue%21@hy2.example.com:443?obfs=TopSecretValue123".to_owned(),
            "Hysteria2 obfs mode is unsupported: <redacted>",
        ),
    ] {
        assert_eq!(
            import_subscription_document(&uri).map(|_| ()),
            Err(expected.into()),
            "{uri}"
        );
    }
}
