//! VMess from share links and Clash: alterId normalization, the legacy
//! 46-node fixture, WebSocket TLS, and the metadata VMess links may carry.

use super::*;

#[test]
fn imports_url_shaped_vmess_aead_links() {
    let imported = import_subscription_document(
        "vmess://44efe52b-e143-46b5-a9e7-aadbfd77eb9c@vm.example.com:443?type=ws&security=tls&encryption=aes-128-gcm&host=edge.example.com&path=%2Fws&sni=vm.example.com#VMess-URL",
    )
    .expect("URL-shaped VMess AEAD");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("VMess URL profile");
    let outbound = &profile["outbounds"][0];
    assert_eq!(outbound["type"], "vmess");
    assert_eq!(outbound["tag"], "VMess-URL");
    assert_eq!(outbound["security"], "aes-128-gcm");
    assert_eq!(outbound["transport"]["type"], "ws");
    assert_eq!(outbound["transport"]["path"], "/ws");
    assert_eq!(outbound["transport"]["headers"]["Host"], "edge.example.com");
    assert_eq!(outbound["tls"]["server_name"], "vm.example.com");
    assert_eq!(
        imported.credentials[0].secret,
        "44efe52b-e143-46b5-a9e7-aadbfd77eb9c"
    );
    assert!(outbound.get("alter_id").is_none());
}

#[test]
fn vmess_uri_aid_normalizes_positive_legacy_values_and_rejects_noncanonical_input() {
    for (aid, expected) in [
        (None, 0),
        (Some(json!(0)), 0),
        (Some(json!("0")), 0),
        (Some(json!(1)), 1),
        (Some(json!("1")), 1),
        (Some(json!(2)), 1),
        (Some(json!("2")), 1),
        (Some(json!(64)), 1),
        (Some(json!("64")), 1),
        (Some(json!(256)), 1),
        (Some(json!(u32::MAX)), 1),
        (Some(json!(u32::MAX.to_string())), 1),
        (Some(json!(u64::from(u32::MAX) + 1)), 1),
        (Some(json!((u64::from(u32::MAX) + 1).to_string())), 1),
        (Some(json!(i64::MAX)), 1),
        (Some(json!(i64::MAX.to_string())), 1),
    ] {
        assert_single_vmess_alter_id(&vmess_uri_with_aid(aid), expected);
    }

    for (label, aid) in [
        ("null", Value::Null),
        ("empty", json!("")),
        ("leading zero", json!("01")),
        ("plus", json!("+1")),
        ("negative string", json!("-1")),
        ("negative number", json!(-1)),
        ("over bound number", json!(i64::MAX as u64 + 1)),
        (
            "over bound string",
            json!((i64::MAX as u64 + 1).to_string()),
        ),
        ("overflow string", json!("18446744073709551616")),
        ("float", json!(1.0)),
        ("boolean", json!(true)),
        ("mapping", json!({ "value": 1 })),
        ("sequence", json!([1])),
    ] {
        let error = import_subscription_document(&vmess_uri_with_aid(Some(aid))).expect_err(label);
        assert!(
            error.contains("vmess URI aid") || error.contains("vmess URI payload"),
            "{label}: {error}"
        );
        assert!(!error.contains(SYNTHETIC_VM_UUID), "{label}: {error}");
    }
}

#[test]
fn clash_vmess_alter_id_normalizes_positive_legacy_values_and_rejects_noncanonical_input() {
    for (value, expected) in [
        (None, 0),
        (Some("0"), 0),
        (Some("\"0\""), 0),
        (Some("1"), 1),
        (Some("\"1\""), 1),
        (Some("2"), 1),
        (Some("\"2\""), 1),
        (Some("64"), 1),
        (Some("\"64\""), 1),
        (Some("256"), 1),
        (Some("4294967295"), 1),
        (Some("\"4294967295\""), 1),
        (Some("4294967296"), 1),
        (Some("\"4294967296\""), 1),
        (Some("9223372036854775807"), 1),
        (Some("\"9223372036854775807\""), 1),
    ] {
        assert_single_vmess_alter_id(&clash_vmess_with_alter_id(value), expected);
    }

    for (label, value) in [
        ("null", "null"),
        ("empty", "\"\""),
        ("leading zero", "01"),
        ("plus", "+1"),
        ("negative", "-1"),
        ("over bound", "9223372036854775808"),
        ("quoted over bound", "\"9223372036854775808\""),
        ("overflow", "\"18446744073709551616\""),
        ("float", "1.0"),
        ("boolean", "true"),
        ("mapping", "{ value: 1 }"),
        ("sequence", "[1]"),
    ] {
        let error =
            import_subscription_document(&clash_vmess_with_alter_id(Some(value))).expect_err(label);
        assert!(error.contains("proxies[0].alterId"), "{label}: {error}");
        assert!(!error.contains(SYNTHETIC_VM_UUID), "{label}: {error}");
    }
}

#[test]
fn synthetic_46_node_legacy_fixture_preserves_vmess_and_projects_one_selector() {
    let imported = import_subscription_document(&synthetic_46_node_clash_fixture())
        .expect("46-node synthetic Clash fixture");
    assert_eq!(imported.credentials.len(), 46);
    assert_eq!(
        imported
            .credentials
            .iter()
            .filter(|credential| {
                credential.reference.kind() == CredentialKind::ShadowsocksPassword
            })
            .count(),
        34
    );
    assert_eq!(
        imported
            .credentials
            .iter()
            .filter(|credential| credential.reference.kind() == CredentialKind::VmessUuid)
            .count(),
        12
    );

    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical 46-node profile");
    let profile_outbounds = profile["outbounds"].as_array().expect("profile outbounds");
    assert_eq!(profile_outbounds.len(), 46);
    assert_eq!(
        profile_outbounds
            .iter()
            .filter(|outbound| outbound["type"] == "shadowsocks")
            .count(),
        34
    );
    assert_eq!(
        profile_outbounds
            .iter()
            .filter(|outbound| { outbound["type"] == "vmess" && outbound["alter_id"] == 1 })
            .count(),
        12
    );
    assert!(!imported.profile.as_json().contains("synthetic-ss-secret"));

    let expected_tags = profile_outbounds
        .iter()
        .map(|outbound| outbound["tag"].clone())
        .collect::<Vec<_>>();
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = imported
            .profile
            .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
            .expect("runtime projection for 46-node fixture");
        assert_eq!(projected.credential_slots().len(), 46);
        let runtime: Value =
            serde_json::from_str(projected.as_json()).expect("runtime projection JSON");
        let runtime_outbounds = runtime["outbounds"].as_array().expect("runtime outbounds");
        assert_eq!(runtime_outbounds.len(), 48);
        assert_eq!(
            runtime_outbounds[47],
            json!({"type":"direct","tag":"cfw-direct"})
        );
        assert_eq!(
            runtime_outbounds
                .iter()
                .filter(|outbound| { outbound["type"] == "vmess" && outbound["alter_id"] == 1 })
                .count(),
            12
        );
        assert_eq!(
            runtime_outbounds
                .iter()
                .filter(|outbound| outbound["type"] == "selector")
                .count(),
            1
        );
        let selector = runtime_outbounds
            .iter()
            .find(|outbound| outbound["type"] == "selector")
            .expect("app-owned selector");
        let selector_tag = selector["tag"].as_str().expect("selector tag");
        assert_eq!(selector["outbounds"], Value::Array(expected_tags.clone()));
        assert_eq!(
            selector["outbounds"]
                .as_array()
                .expect("selector options")
                .len(),
            46
        );
        assert_eq!(runtime["route"]["final"], selector_tag);
        let authenticated_dns = runtime["dns"]["servers"]
            .as_array()
            .expect("DNS servers")
            .iter()
            .filter(|server| server["type"] == "https")
            .collect::<Vec<_>>();
        assert!(!authenticated_dns.is_empty());
        assert!(
            authenticated_dns
                .iter()
                .all(|server| server["detour"] == selector_tag)
        );
    }
}

#[test]
fn imports_vmess_with_websocket_tls() {
    let payload = json!({
        "ps": "VMess",
        "add": "vmess.example.com",
        "port": "443",
        "id": "11111111-1111-4111-8111-111111111111",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "path": "/ws",
        "host": "edge.example.com",
        "tls": "tls",
        "sni": "vmess.example.com",
        "alpn": "h2,http/1.1",
        "fp": "chrome"
    });
    let entry = format!("vmess://{}", STANDARD.encode(payload.to_string()));
    let imported = import_subscription_document(&entry).expect("vmess URI");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    assert_eq!(profile["outbounds"][0]["type"], "vmess");
    assert_eq!(profile["outbounds"][0]["transport"]["type"], "ws");
    assert_eq!(
        profile["outbounds"][0]["tls"]["utls"]["fingerprint"],
        "chrome"
    );
    assert_eq!(
        imported.credentials[0].reference.kind(),
        CredentialKind::VmessUuid
    );
}

#[test]
fn vmess_explicit_safe_metadata_is_consumed_and_unknown_fields_fail_closed() {
    let safe = json!({
        "v": "2",
        "ps": "VMess",
        "add": "vmess.example.com",
        "port": "443",
        "id": SYNTHETIC_VM_UUID,
        "aid": "0",
        "net": "tcp",
        "type": "none",
        "insecure": "0",
        "vcn": "",
        "pcs": "",
        "packetEncoding": "xudp"
    });
    let imported =
        import_subscription_document(&format!("vmess://{}", STANDARD.encode(safe.to_string())))
            .expect("safe explicit VMess metadata");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical VMess profile");
    assert_eq!(profile["outbounds"][0]["packet_encoding"], "xudp");
    let projected = imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("VMess packet encoding projection");
    let runtime: Value =
        serde_json::from_str(projected.as_json()).expect("runtime VMess projection");
    assert_eq!(runtime["outbounds"][0]["packet_encoding"], "xudp");

    for (label, key, value) in [
        ("unknown field", "mystery", json!("TopSecretValue!")),
        ("insecure TLS", "insecure", json!(true)),
        ("certificate domain", "vcn", json!("certificate.example")),
        ("certificate pin", "pcs", json!("TopSecretValue!")),
        ("HTTP header", "type", json!("http")),
    ] {
        let mut payload = safe.clone();
        payload
            .as_object_mut()
            .expect("VMess fixture object")
            .insert(key.to_owned(), value);
        let uri = format!("vmess://{}", STANDARD.encode(payload.to_string()));
        let error = import_subscription_document(&uri).expect_err(label);
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }
}

/// A base64 VMess payload with the given fields set over a minimal node.
fn vmess_payload_uri(extra: Value) -> String {
    let mut payload = json!({
        "ps": "V",
        "add": "vmess.example.com",
        "port": 443,
        "id": SYNTHETIC_VM_UUID,
    });
    for (key, value) in extra.as_object().expect("extra fields") {
        payload[key] = value.clone();
    }
    format!("vmess://{}", STANDARD.encode(payload.to_string()))
}

#[test]
fn vmess_payload_versions_booleans_and_tls_modes_accept_only_their_spellings() {
    let imported = import_subscription_document(&vmess_payload_uri(
        json!({ "v": 2, "insecure": 0, "scy": "aes-128-gcm" }),
    ))
    .expect("an integer version, an integer boolean and a cipher");
    assert_eq!(imported_outbounds(&imported)[0]["security"], "aes-128-gcm");
    for (extra, expected) in [
        (
            json!({ "v": "TopSecretValue123" }),
            "vmess URI version is unsupported: <redacted>",
        ),
        (json!({ "v": 3 }), "vmess URI version is unsupported"),
        (
            json!({ "insecure": 1 }),
            "vmess URI requires disabling TLS certificate verification",
        ),
        (
            json!({ "insecure": 2 }),
            "vmess URI field insecure must be a boolean",
        ),
        (
            json!({ "tls": "TopSecretValue123" }),
            "vmess TLS mode is unsupported: <redacted>",
        ),
        (
            json!({ "net": "TopSecretValue123" }),
            "subscription transport is unsupported: <redacted>",
        ),
    ] {
        assert_eq!(
            import_subscription_document(&vmess_payload_uri(extra.clone())).map(|_| ()),
            Err(expected.into()),
            "{extra}"
        );
    }
}

#[test]
fn url_shaped_vmess_links_accept_only_their_declared_options() {
    let link = |query: &str| format!("vmess://{SYNTHETIC_VM_UUID}@vm.example.com:443?{query}#V");
    let imported =
        import_subscription_document(&link("packetEncoding=xudp")).expect("a packet encoding");
    assert_eq!(imported_outbounds(&imported)[0]["packet_encoding"], "xudp");
    for (uri, expected) in [
        (
            format!("vmess://{SYNTHETIC_VM_UUID}:TopSecretValue123@vm.example.com:443"),
            "VMess URI must encode its UUID as the single user-info component",
        ),
        (
            link("encryption="),
            "VMess URI encryption must not be empty",
        ),
        (
            link("encryption=TopSecretValue123"),
            "VMess URL-shaped encryption is unsupported: <redacted>",
        ),
        (
            link("security=TopSecretValue123"),
            "VMess URL-shaped security mode is unsupported: <redacted>",
        ),
        (
            link("packetEncoding=xudp&packet-encoding=xudp"),
            "VMess URI repeats packet encoding using multiple aliases",
        ),
        (
            link("type=grpc&serviceName=api&service_name=api"),
            "VMess URI repeats gRPC service name using multiple aliases",
        ),
        (
            link("type=TopSecretValue123"),
            "subscription transport is unsupported: <redacted>",
        ),
        (
            format!("vmess://{SYNTHETIC_VM_UUID}@vm.example.com:443#%FF"),
            "VMess URI fragment has invalid percent-encoding",
        ),
    ] {
        assert_eq!(
            import_subscription_document(&uri).map(|_| ()),
            Err(expected.into()),
            "{uri}"
        );
    }
}
