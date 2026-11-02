//! Typed sing-box profiles and restricted sing-box node lists: pass-through,
//! validation errors that never echo the document, Tailscale endpoints, and
//! certificate pins.

use super::*;

#[test]
fn passes_through_typed_sing_box_json_without_credentials() {
    let imported =
        import_subscription_document(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .expect("typed profile");
    assert_eq!(
        imported.profile.as_json(),
        r#"{"outbounds":[{"tag":"direct","type":"direct"}]}"#
    );
    assert!(imported.credentials.is_empty());
}

#[test]
fn typed_profiles_report_their_validation_error_instead_of_the_node_list_schema() {
    let vless = |tls: Value, transport: Option<Value>| {
        let mut outbound = json!({
            "type": "vless", "tag": "VLESS", "server": "vless.example.com", "server_port": 443,
            "credential_ref": {"id": SYNTHETIC_VM_UUID, "kind": "vless_uuid"},
            "tls": tls,
        });
        if let Some(transport) = transport {
            outbound["transport"] = transport;
        }
        json!({ "outbounds": [outbound] }).to_string()
    };
    let reality_without_utls = vless(
        json!({
            "enabled": true,
            "server_name": "www.example.com",
            "reality": {
                "enabled": true,
                "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                "short_id": "0123456789abcdef",
            },
        }),
        None,
    );
    let relative_transport_path = vless(
        json!({"enabled": true, "server_name": "vless.example.com"}),
        Some(json!({"type": "ws", "path": "TopSecretValue123"})),
    );

    for (label, document, expected) in [
        (
            "credential reference with Reality and no uTLS",
            reality_without_utls.as_str(),
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS",
        ),
        (
            "credential reference with a relative transport path",
            relative_transport_path.as_str(),
            "unsupported credential-free policy shape at $.outbounds[0].transport.path: V2Ray transport path must be a bounded absolute path",
        ),
        (
            "dangling final route",
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"missing"}}"#,
            "unsupported credential-free policy shape at $.route.final: final must reference a declared outbound tag",
        ),
        (
            "selector default outside its members",
            r#"{"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"Select","outbounds":["direct"],"default":"missing"}]}"#,
            "unsupported credential-free policy shape at $.outbounds[1]: selector requires unique members and a default from its members",
        ),
        (
            "empty DNS resolver pool",
            r#"{"dns":{"servers":[]},"outbounds":[{"type":"direct","tag":"direct"}]}"#,
            "unsupported credential-free policy shape at $.dns: DNS resolver pools require one to eight entries",
        ),
    ] {
        let error = import_subscription_document(document).expect_err(label);
        assert_eq!(error, expected, "{label}");
        let editor_error = ValidatedSingBoxProfile::parse(document)
            .expect_err(label)
            .to_string();
        assert_eq!(error, editor_error, "{label}");
    }
}

#[test]
fn typed_profile_schema_errors_do_not_echo_document_values() {
    let vless = |tls: Value, extra: Option<(&str, Value)>| {
        let mut outbound = json!({
            "type": "vless", "tag": "VLESS", "server": "vless.example.com", "server_port": 443,
            "credential_ref": {"id": SYNTHETIC_VM_UUID, "kind": "vless_uuid"},
            "tls": tls,
        });
        if let Some((key, value)) = extra {
            outbound[key] = value;
        }
        json!({ "outbounds": [outbound] }).to_string()
    };
    let tls = json!({"enabled": true, "server_name": "vless.example.com"});
    let mut unknown_fingerprint = tls.clone();
    unknown_fingerprint["utls"] = json!({"enabled": true, "fingerprint": "TopSecretValue123"});

    for (label, document) in [
        ("unknown uTLS fingerprint", vless(unknown_fingerprint, None)),
        (
            "unknown outbound field",
            vless(tls, Some(("TopSecretValue123", json!(true)))),
        ),
    ] {
        // serde quotes the rejected value; only validation errors are reported.
        let schema_error = ValidatedSingBoxProfile::parse(&document)
            .expect_err(label)
            .to_string();
        assert!(
            schema_error.contains("TopSecretValue123"),
            "{label}: {schema_error}"
        );

        let error = import_subscription_document(&document).expect_err(label);
        assert_eq!(
            error, "sing-box source JSON does not match the supported node-list schema",
            "{label}"
        );
    }
}

#[test]
fn credential_free_http_node_lists_keep_upstream_normalization() {
    let http = |tag: &str, server: &str, tls: Option<Value>| {
        let mut outbound =
            json!({"type": "http", "tag": tag, "server": server, "server_port": 443});
        if let Some(tls) = tls {
            outbound["tls"] = tls;
        }
        outbound
    };
    let outbounds = |document: &str| -> Value {
        let imported = import_subscription_document(document).expect("upstream HTTP node list");
        assert!(imported.credentials.is_empty());
        let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
        profile["outbounds"].clone()
    };

    let duplicate_tags = json!({"outbounds": [
        http("Edge", "a.example.com", None),
        http("Edge", "b.example.com", None),
    ]})
    .to_string();
    let padded_tag = json!({"outbounds": [http(" Padded ", "c.example.com", None)]}).to_string();
    let empty_server_name = json!({"outbounds": [http(
        "Sni",
        "d.example.com",
        Some(json!({"enabled": true, "server_name": ""})),
    )]})
    .to_string();
    let disabled_tls = json!({"outbounds": [http(
        "Plain",
        "e.example.com",
        Some(json!({"enabled": false, "server_name": ""})),
    )]})
    .to_string();
    let inert_reality = json!({"outbounds": [http(
        "Inert",
        "f.example.com",
        Some(json!({
            "enabled": true,
            "server_name": "f.example.com",
            "reality": {"enabled": false, "public_key": ""},
        })),
    )]})
    .to_string();
    let empty = r#"{"outbounds":[]}"#;
    // Both schemas read each list, and the typed one rejects it only after
    // deserializing it; the node-list adapter keeps its own handling.
    for document in [
        duplicate_tags.as_str(),
        &padded_tag,
        &empty_server_name,
        &disabled_tls,
        &inert_reality,
        empty,
    ] {
        assert!(
            matches!(
                ValidatedSingBoxProfile::parse_classified(document),
                Err(ProfileParseError::Invalid(_))
            ),
            "{document}"
        );
        assert!(sing_box::matches_node_list_schema(document), "{document}");
    }

    let renamed = outbounds(&duplicate_tags);
    assert_eq!(renamed[0]["tag"], "Edge");
    assert_eq!(renamed[1]["tag"], "Edge-2");
    assert_eq!(outbounds(&padded_tag)[0]["tag"], "Padded");
    assert_eq!(
        outbounds(&empty_server_name)[0]["tls"]["server_name"],
        "d.example.com"
    );
    assert!(outbounds(&disabled_tls)[0].get("tls").is_none());
    assert!(outbounds(&inert_reality)[0]["tls"].get("reality").is_none());
    assert_eq!(
        import_subscription_document(empty).expect_err("empty node list"),
        "sing-box source JSON contains no outbounds"
    );
}

#[test]
fn imports_restricted_upstream_sing_box_node_list_json() {
    let document = json!({
        "outbounds": [
            {
                "type": "shadowsocks", "tag": "SS", "server": "ss.example.com",
                "server_port": 8388, "method": "aes-256-gcm", "password": "ss-secret"
            },
            {
                "type": "vmess", "tag": "VMess", "server": "vm.example.com",
                "server_port": 443, "uuid": "11111111-1111-4111-8111-111111111111",
                "security": "auto", "packet_encoding": "xudp",
                "tls": { "enabled": true, "server_name": "vm.example.com", "min_version": "1.2" },
                "transport": { "type": "ws", "path": "/ws", "headers": { "Host": "edge.example.com" } }
            },
            {
                "type": "vless", "tag": "VLESS", "server": "v.example.com",
                "server_port": 443, "uuid": "22222222-2222-4222-8222-222222222222",
                "packet_encoding": "packetaddr",
                "tls": { "enabled": true, "server_name": "v.example.com" },
                "transport": { "type": "http", "method": "GET", "path": "/h2", "host": ["one.example", "two.example"] }
            },
            {
                "type": "trojan", "tag": "Trojan", "server": "t.example.com",
                "server_port": 443, "password": "trojan-secret",
                "tls": { "enabled": true, "server_name": "t.example.com" },
                "transport": { "type": "grpc", "service_name": "tunnel" }
            },
            {
                "type": "hysteria2", "tag": "HY2", "server": "hy.example.com",
                "server_port": 443, "password": "hy-secret",
                "tls": { "enabled": true, "server_name": "hy.example.com", "alpn": "h3" },
                "obfs": { "type": "salamander", "password": "mask-secret" }
            },
            {
                "type": "anytls", "tag": "AnyTLS", "server": "a.example.com",
                "server_port": 443, "password": "any-secret",
                "tls": { "enabled": true, "server_name": "a.example.com" }
            },
            {
                "type": "tuic", "tag": "TUIC", "server": "q.example.com",
                "server_port": 443, "uuid": "33333333-3333-4333-8333-333333333333",
                "password": "tuic-secret", "congestion_control": "bbr",
                "udp_relay_mode": "quic", "zero_rtt_handshake": false,
                "tls": { "enabled": true, "server_name": "q.example.com", "alpn": ["h3"] }
            }
        ]
    });
    let imported = import_subscription_document(&document.to_string())
        .expect("restricted upstream sing-box JSON");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical source profile");
    assert_eq!(profile["outbounds"].as_array().expect("outbounds").len(), 7);
    assert_eq!(profile["outbounds"][1]["packet_encoding"], "xudp");
    assert_eq!(profile["outbounds"][2]["transport"]["type"], "http");
    assert_eq!(profile["outbounds"][2]["transport"]["method"], "GET");
    assert_eq!(profile["outbounds"][4]["obfs"]["type"], "salamander");
    assert_eq!(imported.credentials.len(), 9);
    for secret in [
        "ss-secret",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "trojan-secret",
        "hy-secret",
        "mask-secret",
        "any-secret",
        "33333333-3333-4333-8333-333333333333",
        "tuic-secret",
    ] {
        assert!(!imported.profile.as_json().contains(secret));
    }
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        imported
            .profile
            .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
            .expect("upstream sing-box source projection");
    }
}

#[test]
fn imports_sing_box_tailscale_endpoints_with_vault_auth_keys() {
    let document = json!({
        "outbounds": [
            {
                "type": "shadowsocks", "tag": "SS", "server": "ss.example.com",
                "server_port": 8388, "method": "aes-256-gcm", "password": "ss-secret"
            }
        ],
        "endpoints": [
            {
                "type": "tailscale", "tag": "Office", "auth_key": "tskey-auth-kTEST1CNTRL-TopSecretValue",
                "exit_node": "exit-mac", "control_url": "https://headscale.example.com",
                "hostname": "office-mac", "accept_routes": true, "exit_node_allow_lan_access": true
            }
        ]
    });
    let imported =
        import_subscription_document(&document.to_string()).expect("sing-box Tailscale endpoint");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical source profile");
    assert_eq!(profile["outbounds"].as_array().expect("outbounds").len(), 2);
    let endpoint = &profile["outbounds"][1];
    assert_eq!(endpoint["type"], "tailscale");
    assert_eq!(endpoint["tag"], "Office");
    assert_eq!(endpoint["exit_node"], "exit-mac");
    assert_eq!(endpoint["control_server"], "https://headscale.example.com");
    assert!(endpoint.get("control_url").is_none());
    assert_eq!(endpoint["hostname"], "office-mac");
    assert_eq!(endpoint["accept_routes"], true);
    assert_eq!(endpoint["exit_node_allow_lan_access"], true);
    assert_eq!(
        endpoint["auth_key_credential_ref"]["kind"],
        "tailscale_auth_key"
    );
    assert!(endpoint.get("auth_key").is_none());
    assert_eq!(imported.credentials.len(), 2);
    assert_eq!(
        imported.credentials[1].reference.kind(),
        CredentialKind::TailscaleAuthKey
    );
    assert_eq!(
        imported.credentials[1].secret,
        "tskey-auth-kTEST1CNTRL-TopSecretValue"
    );
    assert!(!imported.profile.as_json().contains("TopSecretValue"));
    let projected = imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("Tailscale projection");
    let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime");
    assert_eq!(runtime["endpoints"][0]["type"], "tailscale");
    assert_eq!(runtime["endpoints"][0]["auth_key"], "");
    assert_eq!(
        projected.credential_slots()[1].json_pointer(),
        "/endpoints/0/auth_key"
    );
}

#[test]
fn upstream_sing_box_json_rejects_full_configs_and_unsafe_semantics() {
    for (label, document, expected) in [
        (
            "root DNS",
            r#"{"dns":{},"outbounds":[{"type":"direct","tag":"direct"}]}"#,
            "supported node-list schema",
        ),
        (
            "insecure TLS",
            r#"{"outbounds":[{"type":"trojan","tag":"T","server":"t.example","server_port":443,"password":"TopSecretValue!","tls":{"enabled":true,"server_name":"t.example","insecure":true}}]}"#,
            "disabling TLS certificate verification",
        ),
        (
            "unknown outbound field",
            r#"{"outbounds":[{"type":"shadowsocks","tag":"S","server":"s.example","server_port":8388,"method":"aes-256-gcm","password":"TopSecretValue123","TopSecretValue123":"TopSecretValue123"}]}"#,
            "supported node-list schema",
        ),
        (
            "TUIC 0-RTT",
            r#"{"outbounds":[{"type":"tuic","tag":"Q","server":"q.example","server_port":443,"uuid":"33333333-3333-4333-8333-333333333333","password":"TopSecretValue!","zero_rtt_handshake":true,"tls":{"enabled":true,"server_name":"q.example"}}]}"#,
            "0-RTT is unsupported",
        ),
        (
            "Tailscale exit-node advertisement",
            r#"{"outbounds":[],"endpoints":[{"type":"tailscale","tag":"T","auth_key":"TopSecretValue!","exit_node":"exit-mac","advertise_exit_node":true}]}"#,
            "exit-node advertisement is unsupported",
        ),
        (
            "Tailscale SSH server",
            r#"{"outbounds":[],"endpoints":[{"type":"tailscale","tag":"T","auth_key":"TopSecretValue!","exit_node":"exit-mac","ssh_server":true}]}"#,
            "unsupported Tailscale SSH server",
        ),
        (
            "Tailscale without an auth key",
            r#"{"outbounds":[],"endpoints":[{"type":"tailscale","tag":"T","exit_node":"exit-mac"}]}"#,
            "requires auth_key",
        ),
        (
            "Tailscale without an exit node",
            r#"{"outbounds":[],"endpoints":[{"type":"tailscale","tag":"T","auth_key":"TopSecretValue!"}]}"#,
            "requires exit_node",
        ),
        (
            "WireGuard endpoint",
            r#"{"outbounds":[],"endpoints":[{"type":"wireguard","tag":"W","private_key":"TopSecretValue!"}]}"#,
            "supported node-list schema",
        ),
    ] {
        let error = import_subscription_document(document).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
        assert!(!error.contains("TopSecretValue123"), "{label}: {error}");
    }
}

#[test]
fn sing_box_certificate_pins_pass_through_unchanged() {
    let document = |tls: Value| {
        json!({"outbounds":[{"type":"hysteria2","tag":"pinned","server":"hy2.example.com","server_port":443,
            "password":"TopSecretValue!","tls":tls}]})
        .to_string()
    };
    let ones = "//////////////////////////////////////////8=";
    let imported = import_subscription_document(&document(json!({
        "enabled":true,"server_name":"hy2.example.com","certificate_sha256":[ones, ASCENDING_PIN_BASE64]
    })))
    .expect("two DER pins");
    assert_eq!(
        imported_outbounds(&imported)[0]["tls"]["certificate_sha256"],
        json!([ones, ASCENDING_PIN_BASE64])
    );
    let imported = import_subscription_document(&document(json!({
        "enabled":true,"server_name":"hy2.example.com","certificate_public_key_sha256":[ASCENDING_PIN_BASE64]
    })))
    .expect("an SPKI pin");
    let tls = &imported_outbounds(&imported)[0]["tls"];
    assert_eq!(
        tls["certificate_public_key_sha256"],
        json!([ASCENDING_PIN_BASE64])
    );
    assert!(tls.get("certificate_sha256").is_none());
    let nine = (0..9u8)
        .map(|byte| base64::engine::general_purpose::STANDARD.encode([byte; 32]))
        .collect::<Vec<_>>();
    for (label, tls, expected) in [
        (
            "both pin kinds",
            json!({"enabled":true,"server_name":"hy2.example.com","certificate_sha256":[ones],
                "certificate_public_key_sha256":[ASCENDING_PIN_BASE64]}),
            "certificate pinning requires TLS, one pin kind, and no Reality",
        ),
        (
            "nine pins",
            json!({"enabled":true,"server_name":"hy2.example.com","certificate_sha256":nine}),
            "TLS pins must be one to eight distinct SHA256 values in canonical base64",
        ),
        (
            "non-canonical base64",
            json!({"enabled":true,"server_name":"hy2.example.com",
                "certificate_sha256":["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9="]}),
            "TLS pins must be one to eight distinct SHA256 values in canonical base64",
        ),
    ] {
        let error = import_subscription_document(&document(tls)).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }
}

/// Upstream sing-box verifies a public-key pin whether or not `tls.insecure`
/// is set, so `insecure: true` beside a pin (either kind) imports as the pin,
/// as for Clash and share links, and is never stored. Without a pin it still
/// fails closed.
#[test]
fn sing_box_insecure_beside_a_pin_imports_as_the_pin() {
    let trojan = |tls: &str| {
        format!(
            r#"{{"outbounds":[{{"type":"trojan","tag":"T","server":"t.example","server_port":443,"password":"TopSecretValue!","tls":{tls}}}]}}"#
        )
    };
    for pin_key in ["certificate_sha256", "certificate_public_key_sha256"] {
        let imported = import_subscription_document(&trojan(&format!(
            r#"{{"enabled":true,"server_name":"t.example","insecure":true,"{pin_key}":["{ASCENDING_PIN_BASE64}"]}}"#
        )))
        .unwrap_or_else(|error| panic!("{pin_key}: {error}"));
        let tls = &imported_outbounds(&imported)[0]["tls"];
        assert_eq!(tls[pin_key], json!([ASCENDING_PIN_BASE64]), "{pin_key}");
        assert!(tls.get("insecure").is_none(), "{pin_key}");
        let runtime: Value = serde_json::from_str(&projected_json(&imported)).expect("runtime");
        assert!(
            runtime["outbounds"][0]["tls"].get("insecure").is_none(),
            "{pin_key}"
        );
    }
    for (label, tls) in [
        (
            "no pin",
            r#"{"enabled":true,"server_name":"t.example","insecure":true}"#,
        ),
        (
            "an empty pin list",
            r#"{"enabled":true,"server_name":"t.example","insecure":true,"certificate_sha256":[]}"#,
        ),
    ] {
        let error = import_subscription_document(&trojan(tls)).expect_err(label);
        assert!(
            error.contains("disabling TLS certificate verification"),
            "{label}: {error}"
        );
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }
}
