use std::fmt::Write as _;

use cfw_singbox_config::{EngineSettings, ProjectionMode};

use super::*;

const SYNTHETIC_VM_UUID: &str = "00000000-0000-4000-8000-000000000001";
const SYNTHETIC_PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

#[test]
fn empty_clash_routing_rules_remain_explicit_errors() {
    for scalar in ["", "~", "''", "!!str"] {
        let document = format!(
            "proxies:\n  - {{name: Node, type: socks5, server: node.example.com, port: 1080}}\nrules:\n  - {scalar}\n"
        );
        let error = import_subscription_document(&document).expect_err("empty routing rule");
        assert!(
            error.contains("rules[0] has an unsupported rule shape"),
            "{error}"
        );
    }
}

fn vmess_uri_with_aid(aid: Option<Value>) -> String {
    let mut payload = json!({
        "ps": "Synthetic VMess",
        "add": "vmess.example.com",
        "port": 443,
        "id": SYNTHETIC_VM_UUID,
    });
    if let Some(aid) = aid {
        payload
            .as_object_mut()
            .expect("VMess fixture payload must be an object")
            .insert("aid".into(), aid);
    }
    format!("vmess://{}", STANDARD.encode(payload.to_string()))
}

fn clash_vmess_with_alter_id(value: Option<&str>) -> String {
    let alter_id = value
        .map(|value| format!("    alterId: {value}\n"))
        .unwrap_or_default();
    format!(
        "proxies:\n  - name: Synthetic VMess\n    type: vmess\n    server: vmess.example.com\n    port: 443\n    uuid: {SYNTHETIC_VM_UUID}\n{alter_id}"
    )
}

fn assert_single_vmess_alter_id(document: &str, expected: u8) {
    let imported = import_subscription_document(document).expect("valid VMess fixture");
    assert_eq!(imported.credentials.len(), 1);
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical profile JSON");
    let outbound = &profile["outbounds"][0];
    assert_eq!(outbound["type"], "vmess");
    if expected == 0 {
        assert!(
            outbound.get("alter_id").is_none(),
            "AEAD alter_id must remain the omitted canonical default"
        );
    } else {
        assert_eq!(outbound["alter_id"], expected);
    }

    let projected = imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("runtime VMess projection");
    let runtime: Value =
        serde_json::from_str(projected.as_json()).expect("runtime projection JSON");
    let runtime_vmess = runtime["outbounds"]
        .as_array()
        .expect("runtime outbounds")
        .iter()
        .find(|outbound| outbound["type"] == "vmess")
        .expect("runtime VMess outbound");
    if expected == 0 {
        assert!(
            runtime_vmess.get("alter_id").is_none(),
            "AEAD runtime alter_id must remain omitted"
        );
    } else {
        assert_eq!(runtime_vmess["alter_id"], expected);
    }
}

fn synthetic_46_node_clash_fixture() -> String {
    let mut document = String::from("proxies:\n");
    for index in 0..34_u16 {
        writeln!(
            document,
            "  - name: SS-{index:02}\n    type: ss\n    server: ss-{index:02}.example.com\n    port: {}\n    cipher: aes-256-gcm\n    password: synthetic-ss-secret-{index:02}",
            10_000 + index
        )
        .expect("write synthetic Shadowsocks fixture");
    }
    for index in 0..12_u16 {
        writeln!(
            document,
            "  - name: VMess-{index:02}\n    type: vmess\n    server: vmess-{index:02}.example.com\n    port: 443\n    uuid: 00000000-0000-4000-8000-{index:012x}\n    alterId: 1\n    cipher: auto"
        )
        .expect("write synthetic VMess fixture");
    }
    document
}

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
fn imports_sip008_json_with_vault_credentials_and_root_metadata() {
    let document = json!({
        "version": 1,
        "servers": [
            {
                "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
                "remarks": "Tokyo",
                "server": "tokyo.example.com",
                "server_port": 8388,
                "password": "sip008-secret-one",
                "method": "chacha20-ietf-poly1305"
            },
            {
                "id": "7842c068-c667-41f2-8f7d-04feece3cb67",
                "remarks": "Tokyo",
                "server": "osaka.example.com",
                "server_port": 443,
                "password": "sip008-secret-two",
                "method": "aes-256-gcm",
                "plugin": "",
                "plugin_opts": ""
            }
        ],
        "bytes_used": 1024,
        "bytes_remaining": 2048,
        "provider_notice": { "plan": "synthetic" }
    });
    let imported = import_subscription_document(&document.to_string()).expect("SIP008 JSON");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical SIP008 profile");
    assert_eq!(profile["outbounds"][0]["type"], "shadowsocks");
    assert_eq!(profile["outbounds"][0]["tag"], "Tokyo");
    assert_eq!(profile["outbounds"][1]["tag"], "Tokyo-2");
    assert_eq!(imported.credentials.len(), 2);
    assert_eq!(imported.credentials[0].secret, "sip008-secret-one");
    assert_eq!(imported.credentials[1].secret, "sip008-secret-two");
    assert!(!imported.profile.as_json().contains("sip008-secret"));
}

#[test]
fn sip008_rejects_ambiguous_identity_plugins_and_invalid_usage_metadata() {
    let valid_server = json!({
        "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
        "remarks": "Synthetic",
        "server": "ss.example.com",
        "server_port": 8388,
        "password": "TopSecretValue!",
        "method": "aes-256-gcm"
    });
    for (label, document, expected) in [
        (
            "duplicate server id",
            json!({ "version": 1, "servers": [valid_server.clone(), valid_server.clone()] }),
            "unique non-nil UUIDs",
        ),
        (
            "plugin",
            json!({
                "version": 1,
                "servers": [{
                    "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
                    "remarks": "Synthetic",
                    "server": "ss.example.com",
                    "server_port": 8388,
                    "password": "TopSecretValue!",
                    "method": "aes-256-gcm",
                    "plugin": "v2ray-plugin"
                }]
            }),
            "plugins are unsupported",
        ),
        (
            "remaining without used",
            json!({
                "version": 1,
                "servers": [valid_server.clone()],
                "bytes_remaining": 1
            }),
            "requires bytes_used",
        ),
    ] {
        let error = import_subscription_document(&document.to_string()).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }
}

#[test]
fn document_classification_is_structural_and_bom_tolerant() {
    assert!(looks_like_clash_yaml("proxies:\n  - name: node\n"));
    assert!(looks_like_clash_yaml("mixed-port: 7890\n"));
    assert!(!looks_like_clash_yaml("# proxies:\nnot-a-document\n"));
    assert!(!looks_like_clash_yaml("metadata:\n  proxies: nested\n"));
    assert!(!looks_like_clash_yaml("note: proxies: is only a value\n"));

    let upstream_json = json!({
        "outbounds": [{
            "type": "shadowsocks",
            "tag": "proxies:",
            "server": "ss.example.com",
            "server_port": 8388,
            "method": "aes-256-gcm",
            "password": "json-secret"
        }]
    });
    let imported = import_subscription_document(&upstream_json.to_string())
        .expect("JSON string containing a Clash marker");
    assert_eq!(imported.credentials[0].secret, "json-secret");

    let uri = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#BOM";
    let imported =
        import_subscription_document(&format!("\u{feff}{uri}")).expect("plain URI bundle with BOM");
    assert_eq!(imported.credentials[0].secret, "secret");

    let encoded = STANDARD.encode(format!("\u{feff}{uri}\n"));
    let imported = import_subscription_document(&encoded).expect("base64 bundle with BOM");
    assert_eq!(imported.credentials[0].secret, "secret");

    let error = import_subscription_document(r#"{"note":"proxies:""#)
        .expect_err("malformed JSON must not fall through to YAML");
    assert_eq!(error, "subscription JSON document is malformed");
}

#[test]
fn imports_sip002_shadowsocks_2022_plain_userinfo_and_key_chains() {
    const KEY_256: &str = "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=";
    let uri = "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3";
    let imported = import_subscription_document(uri).expect("official SIP002 2022 URI");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical profile JSON");
    assert_eq!(profile["outbounds"][0]["method"], "2022-blake3-aes-256-gcm");
    assert_eq!(imported.credentials[0].secret, KEY_256);
    assert!(!imported.profile.as_json().contains(KEY_256));

    let multi_user = json!({
        "outbounds": [{
            "type": "shadowsocks",
            "tag": "Multi-user",
            "server": "ss.example.com",
            "server_port": 8388,
            "method": "2022-blake3-aes-256-gcm",
            "password": format!("{KEY_256}:{KEY_256}")
        }]
    });
    let imported = import_subscription_document(&multi_user.to_string())
        .expect("sing-box 2022 multi-user key chain");
    assert_eq!(
        imported.credentials[0].secret,
        format!("{KEY_256}:{KEY_256}")
    );
}

#[test]
fn shadowsocks_2022_rejects_base64_userinfo_and_legacy_full_envelopes() {
    const KEY_256: &str = "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=";
    let encoded_userinfo = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-256-gcm:{KEY_256}"));
    let legacy_full = STANDARD.encode(format!(
        "2022-blake3-aes-256-gcm:{KEY_256}@ss.example.com:8388"
    ));
    for (label, document) in [
        (
            "base64 userinfo",
            format!("ss://{encoded_userinfo}@ss.example.com:8388#Encoded"),
        ),
        ("legacy full envelope", format!("ss://{legacy_full}")),
    ] {
        let error = import_subscription_document(&document).expect_err(label);
        assert!(
            error.contains("percent-encoded plain userinfo"),
            "{label}: {error}"
        );
        assert!(!error.contains(KEY_256), "{label}: {error}");
    }
}

#[test]
fn shadowsocks_2022_key_validation_precedes_vault_staging_for_every_container() {
    const WRONG_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
    let documents = [
        (
            "SIP002 URI",
            format!("ss://2022-blake3-aes-256-gcm:{WRONG_KEY}@ss.example.com:8388#Wrong"),
        ),
        (
            "SIP008 JSON",
            json!({
                "version": 1,
                "servers": [{
                    "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
                    "remarks": "Wrong",
                    "server": "ss.example.com",
                    "server_port": 8388,
                    "method": "2022-blake3-aes-256-gcm",
                    "password": WRONG_KEY
                }]
            })
            .to_string(),
        ),
        (
            "Clash YAML",
            format!(
                "proxies:\n  - name: Wrong\n    type: ss\n    server: ss.example.com\n    port: 8388\n    cipher: 2022-blake3-aes-256-gcm\n    password: {WRONG_KEY}\n"
            ),
        ),
        (
            "sing-box JSON",
            json!({
                "outbounds": [{
                    "type": "shadowsocks",
                    "tag": "Wrong",
                    "server": "ss.example.com",
                    "server_port": 8388,
                    "method": "2022-blake3-aes-256-gcm",
                    "password": WRONG_KEY
                }]
            })
            .to_string(),
        ),
    ];
    for (label, document) in documents {
        let error = import_subscription_document(&document).expect_err(label);
        assert!(error.contains("32-byte keys"), "{label}: {error}");
        assert!(!error.contains(WRONG_KEY), "{label}: {error}");
    }

    let error = import_subscription_document(
        "ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA@ss.example.com:8388",
    )
    .expect_err("unpadded Base64 is noncanonical");
    assert!(error.contains("canonical standard-base64 16-byte keys"));
}

#[test]
fn shadowsocks_uri_decodes_each_plain_component_exactly_once() {
    let imported = import_subscription_document(
        "ss://aes-256-gcm:literal%252Fvalue@ss.example.com:8388#Plain",
    )
    .expect("plain SIP002 credentials");
    assert_eq!(imported.credentials[0].secret, "literal%2Fvalue");

    let envelope = URL_SAFE_NO_PAD.encode("aes-256-gcm:literal%2Fvalue");
    let imported =
        import_subscription_document(&format!("ss://{envelope}@ss.example.com:8388#Base64"))
            .expect("base64 SIP002 credentials");
    assert_eq!(imported.credentials[0].secret, "literal%2Fvalue");
}

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
fn uuid_credentials_are_validated_before_vault_staging() {
    for (label, document) in [
        (
            "URL VMess",
            "vmess://not-a-uuid@vm.example.com:443?security=tls",
        ),
        ("VLESS", "vless://not-a-uuid@v.example.com:443?security=tls"),
        (
            "TUIC",
            "tuic://not-a-uuid:TopSecretValue!@q.example.com:443?sni=q.example.com",
        ),
    ] {
        let error = import_subscription_document(document).expect_err(label);
        assert!(error.contains("UUID"), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }
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
    ] {
        let error = import_subscription_document(document).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
        assert!(!error.contains("TopSecretValue123"), "{label}: {error}");
    }
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
fn imports_base64_uri_bundle_with_shadowsocks_and_trojan() {
    let bundle = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#Tokyo\ntrojan://hunter2@trojan.example.com:443?type=grpc&serviceName=tunnel&sni=trojan.example.com#Work";
    let encoded = STANDARD.encode(bundle.as_bytes());
    let imported = import_subscription_document(&encoded).expect("base64 URI bundle");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    assert_eq!(profile["outbounds"][0]["type"], "shadowsocks");
    assert_eq!(profile["outbounds"][1]["type"], "trojan");
    assert_eq!(imported.credentials.len(), 2);
    assert_eq!(
        imported.credentials[0].reference.kind(),
        CredentialKind::ShadowsocksPassword
    );
    assert_eq!(imported.credentials[0].secret, "secret");
    assert_eq!(
        imported.credentials[1].reference.kind(),
        CredentialKind::TrojanPassword
    );
    assert_eq!(imported.credentials[1].secret, "hunter2");
}

#[test]
fn imports_url_safe_padded_base64_uri_bundle() {
    let bundle = "trojan://hunter2@trojan.example.com:443?sni=trojan.example.com#测试\n";
    let encoded = URL_SAFE.encode(bundle.as_bytes());
    assert!(
        encoded.contains('-') || encoded.contains('_'),
        "fixture must exercise the URL-safe alphabet"
    );
    assert!(encoded.ends_with('='), "fixture must exercise padding");

    let imported = import_subscription_document(&encoded).expect("URL-safe padded bundle");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    assert_eq!(profile["outbounds"][0]["type"], "trojan");
    assert_eq!(profile["outbounds"][0]["tag"], "测试");
    assert_eq!(imported.credentials[0].secret, "hunter2");
}

#[test]
fn uri_bundle_enforces_the_outbound_limit_before_conversion() {
    let entry = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#Repeated";
    let at_limit = std::iter::repeat_n(entry, cfw_singbox_config::MAX_PROXY_NODES)
        .collect::<Vec<_>>()
        .join("\n");
    let imported = import_subscription_document(&at_limit).expect("URI bundle at limit");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    let outbounds = profile["outbounds"].as_array().expect("outbounds array");
    assert_eq!(outbounds.len(), cfw_singbox_config::MAX_PROXY_NODES);
    assert_eq!(outbounds[0]["tag"], "Repeated");
    assert_eq!(
        outbounds[cfw_singbox_config::MAX_PROXY_NODES - 1]["tag"],
        format!("Repeated-{}", cfw_singbox_config::MAX_PROXY_NODES)
    );

    let over_limit = format!("{at_limit}\n{entry}");
    let error = import_subscription_document(&over_limit).expect_err("129th URI must fail");
    assert_eq!(
        error,
        format!(
            "subscription URI bundle has more than {} entries",
            cfw_singbox_config::MAX_PROXY_NODES
        )
    );
}

#[test]
fn migration_credential_references_are_stable_and_namespace_bound() {
    let body = "trojan://hunter2@trojan.example.com:443?sni=trojan.example.com#Work";
    let namespace =
        Uuid::parse_str("aaaaaaaa-aaaa-5aaa-8aaa-aaaaaaaaaaaa").expect("migration namespace");
    let other_namespace =
        Uuid::parse_str("bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb").expect("other migration namespace");
    let first = import_subscription_document_with_credential_namespace(body, namespace)
        .expect("first deterministic import");
    let replay = import_subscription_document_with_credential_namespace(body, namespace)
        .expect("deterministic replay");
    let other = import_subscription_document_with_credential_namespace(body, other_namespace)
        .expect("other candidate import");

    assert_eq!(first.profile, replay.profile);
    assert_eq!(
        first.credentials[0].reference,
        replay.credentials[0].reference
    );
    assert_ne!(
        first.credentials[0].reference,
        other.credentials[0].reference
    );
    assert_ne!(first.profile.digest(), other.profile.digest());
    assert_eq!(
        first.credentials[0]
            .reference
            .id()
            .parse::<Uuid>()
            .expect("credential UUID")
            .get_version_num(),
        5
    );
}

#[test]
fn subscription_updates_reuse_references_in_outbound_order() {
    let body =
        "trojan://first@one.example:443#One\nss://YWVzLTI1Ni1nY206c2Vjb25k@two.example:8388#Two";
    let initial = import_subscription_document(body).expect("initial subscription");
    let references = initial.profile.credential_references_in_outbound_order();
    let replay = import_subscription_document_with_reusable_references(body, references.clone())
        .expect("stable subscription update");
    assert_eq!(replay.profile, initial.profile);
    assert_eq!(
        replay.profile.credential_references_in_outbound_order(),
        references
    );
    assert_eq!(
        replay
            .credentials
            .iter()
            .map(|credential| credential.reference.clone())
            .collect::<Vec<_>>(),
        references
    );

    let changed_layout = import_subscription_document_with_reusable_references(
        "ss://YWVzLTI1Ni1nY206bmV3@new.example:8388#New",
        references.clone(),
    )
    .expect("changed credential layout");
    assert_ne!(
        changed_layout.credentials[0].reference, references[0],
        "a kind mismatch must not repurpose an immutable reference"
    );
}

#[test]
fn subscription_updates_handle_shared_references_without_duplicate_provisioning() {
    let initial = import_subscription_document(
        "trojan://same@one.example:443#One\ntrojan://same@two.example:443#Two",
    )
    .expect("initial subscription");
    let shared = initial.credentials[0].reference.clone();

    let unchanged = import_subscription_document_with_reusable_references(
        "trojan://same@one.example:443#One\ntrojan://same@two.example:443#Two",
        vec![shared.clone(), shared.clone()],
    )
    .expect("shared credential update");
    assert_eq!(unchanged.credentials.len(), 1);
    assert_eq!(unchanged.credentials[0].reference, shared);
    assert_eq!(
        unchanged.profile.credential_references_in_outbound_order(),
        vec![shared.clone(), shared.clone()]
    );

    let split = import_subscription_document_with_reusable_references(
        "trojan://first@one.example:443#One\ntrojan://second@two.example:443#Two",
        vec![shared.clone(), shared.clone()],
    )
    .expect("split credential update");
    assert_eq!(split.credentials.len(), 2);
    assert_eq!(split.credentials[0].reference, shared);
    assert_ne!(
        split.credentials[1].reference, split.credentials[0].reference,
        "different material must receive a distinct immutable reference"
    );
    assert_eq!(split.credentials[0].secret, "first");
    assert_eq!(split.credentials[1].secret, "second");
}

#[test]
fn credential_kind_discriminants_are_append_only() {
    assert_eq!(
        [
            CredentialKind::ShadowsocksPassword,
            CredentialKind::VmessUuid,
            CredentialKind::VlessUuid,
            CredentialKind::TrojanPassword,
            CredentialKind::Hysteria2Password,
            CredentialKind::Hysteria2ObfsPassword,
            CredentialKind::AnyTlsPassword,
            CredentialKind::TuicUuid,
            CredentialKind::TuicPassword,
            CredentialKind::Socks5Username,
            CredentialKind::Socks5Password,
        ]
        .map(credential_kind_discriminant),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    );
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
fn imports_vless_reality_and_hysteria2_links() {
    let imported = import_subscription_document(
        "vless://11111111-1111-4111-8111-111111111111@vless.example.com:443?security=reality&sni=www.example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&fp=chrome&flow=xtls-rprx-vision&encryption=none&packetEncoding=xudp#Reality\nhy2://supersecret@hy2.example.com:8443?sni=hy2.example.com&upmbps=100&downmbps=200&obfs=salamander&obfs-password=mask#HY2",
    )
    .expect("vless and hy2 URIs");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    assert_eq!(profile["outbounds"][0]["type"], "vless");
    assert_eq!(profile["outbounds"][0]["packet_encoding"], "xudp");
    assert_eq!(profile["outbounds"][0]["tls"]["reality"]["enabled"], true);
    assert_eq!(profile["outbounds"][1]["type"], "hysteria2");
    assert_eq!(profile["outbounds"][1]["obfs"]["type"], "salamander");
    assert_eq!(imported.credentials.len(), 3);
    assert_eq!(
        imported.credentials[0].reference.kind(),
        CredentialKind::VlessUuid
    );
    assert_eq!(
        imported.credentials[1].reference.kind(),
        CredentialKind::Hysteria2Password
    );
    assert_eq!(
        imported.credentials[2].reference.kind(),
        CredentialKind::Hysteria2ObfsPassword
    );
    let projected = imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("VLESS packet encoding projection");
    let runtime: Value =
        serde_json::from_str(projected.as_json()).expect("runtime projection JSON");
    assert_eq!(runtime["outbounds"][0]["packet_encoding"], "xudp");
}

#[test]
fn hysteria2_and_anytls_omitted_ports_default_to_443() {
    let imported = import_subscription_document(
        "hysteria2://user%3Apass@hy.example/?sni=hy.example#HY2\nanytls://letmein@any.example/?sni=any.example#AnyTLS",
    )
    .expect("official omitted-port URI forms");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    let outbounds = profile["outbounds"].as_array().expect("outbounds");
    assert_eq!(outbounds[0]["server_port"], 443);
    assert_eq!(outbounds[1]["server_port"], 443);
    assert_eq!(imported.credentials[0].secret, "user:pass");
    assert_eq!(imported.credentials[1].secret, "letmein");
    assert!(!imported.profile.as_json().contains("user:pass"));
    assert!(!imported.profile.as_json().contains("letmein"));

    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        imported
            .profile
            .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
            .expect("omitted-port runtime projection");
    }
}

#[test]
fn hysteria2_port_hopping_projects_from_uri_clash_and_sing_box() {
    let documents = [
        (
            "official URI",
            "hysteria2://hy-secret@hy.example.com:443,5000-5002/?sni=hy.example.com#URI-Hop"
                .to_owned(),
            None,
        ),
        (
            "Clash",
            "proxies:\n  - name: Clash-Hop\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 443,5000-5002\n    hop-interval: 30\n    password: hy-secret\n    sni: hy.example.com\n"
                .to_owned(),
            Some(30),
        ),
        (
            "sing-box",
            json!({
                "outbounds": [{
                    "type": "hysteria2",
                    "tag": "SingBox-Hop",
                    "server": "hy.example.com",
                    "server_ports": ["443", "5000:5002"],
                    "hop_interval": "15s",
                    "password": "hy-secret",
                    "tls": { "enabled": true, "server_name": "hy.example.com" }
                }]
            })
            .to_string(),
            Some(15),
        ),
    ];

    for (label, document, hop_interval) in documents {
        let imported = import_subscription_document(&document).expect(label);
        let profile: Value = serde_json::from_str(imported.profile.as_json())
            .expect("canonical Hysteria2 hopping profile");
        let outbound = &profile["outbounds"][0];
        assert_eq!(outbound["server_port"], 443, "{label}");
        assert_eq!(outbound["server_ports"], json!(["443", "5000:5002"]));
        match hop_interval {
            Some(seconds) => {
                assert_eq!(outbound["hop_interval_seconds"], seconds, "{label}")
            }
            None => assert!(outbound.get("hop_interval_seconds").is_none(), "{label}"),
        }
        assert_eq!(imported.credentials[0].secret, "hy-secret");

        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            let projected = imported
                .profile
                .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
                .expect("Hysteria2 hopping projection");
            let runtime: Value =
                serde_json::from_str(projected.as_json()).expect("Hysteria2 hopping runtime JSON");
            let runtime_hysteria2 = runtime["outbounds"]
                .as_array()
                .expect("runtime outbounds")
                .iter()
                .find(|candidate| candidate["type"] == "hysteria2")
                .expect("runtime Hysteria2 outbound");
            assert_eq!(
                runtime_hysteria2["server_ports"],
                json!(["443:443", "5000:5002"]),
                "{label}"
            );
            if let Some(seconds) = hop_interval {
                assert_eq!(
                    runtime_hysteria2["hop_interval"],
                    format!("{seconds}s"),
                    "{label}"
                );
            }
        }
    }
}

#[test]
fn hysteria2_port_hopping_rejects_ambiguous_or_unprojectable_ranges() {
    for (label, document, expected) in [
        (
            "overlap",
            "hysteria2://hy-secret@hy.example.com:443,440-450/?sni=hy.example.com#Overlap",
            "overlapping",
        ),
        (
            "leading zero",
            "hysteria2://hy-secret@hy.example.com:0443,5000-5002/?sni=hy.example.com#LeadingZero",
            "invalid port",
        ),
        (
            "Mihomo descending hop interval range",
            "proxies:\n  - name: Hop\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 5000-5002\n    hop-interval: 30-15\n    password: TopSecretValue!\n",
            "hop interval maximum must be between hop_interval_seconds and 3600 seconds",
        ),
        (
            "Mihomo hop interval below the runtime minimum",
            "proxies:\n  - name: Hop\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 5000-5002\n    hop-interval: 3\n    password: TopSecretValue!\n",
            "hop interval must be between 5 and 3600 seconds",
        ),
        (
            "URI open hop interval range",
            "hysteria2://TopSecretValue!@hy.example.com:443,5000-5002/?sni=hy.example.com&hop-interval=15-#Hop",
            "canonical 1..=3600 second",
        ),
    ] {
        let error = import_subscription_document(document).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }

    let sing_box = |hop_interval_max: Option<&str>| {
        let mut outbound = json!({
            "type": "hysteria2",
            "tag": "SingBox-Hop",
            "server": "hy.example.com",
            "server_ports": ["443", "5000:5002"],
            "hop_interval": "15s",
            "password": "TopSecretValue!",
            "tls": { "enabled": true, "server_name": "hy.example.com" }
        });
        if let Some(value) = hop_interval_max {
            outbound["hop_interval_max"] = json!(value);
        }
        json!({ "outbounds": [outbound] }).to_string()
    };
    import_subscription_document(&sing_box(None)).expect("fixed sing-box hop interval");
    let error = import_subscription_document(&sing_box(Some("10s")))
        .expect_err("a sing-box hop_interval_max below hop_interval");
    assert!(
        error
            .contains("hop interval maximum must be between hop_interval_seconds and 3600 seconds"),
        "{error}"
    );
}

#[test]
fn hysteria2_hop_interval_ranges_import_from_every_format() {
    let sing_box = json!({
        "outbounds": [{
            "type": "hysteria2",
            "tag": "SingBox-Range",
            "server": "hy.example.com",
            "server_ports": ["5000:5002"],
            "hop_interval": "15s",
            "hop_interval_max": "30s",
            "password": "hy-secret",
            "tls": { "enabled": true, "server_name": "hy.example.com" }
        }]
    })
    .to_string();
    for (label, document, expected) in [
        (
            "Clash",
            "proxies:\n  - name: Range\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 5000-5002\n    hop-interval: 15-30\n    password: hy-secret\n".to_owned(),
            (15, Some(30)),
        ),
        (
            "Clash single-valued range",
            "proxies:\n  - name: Range\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 5000-5002\n    hop-interval: 20-20\n    password: hy-secret\n".to_owned(),
            (20, None),
        ),
        (
            "URI",
            "hysteria2://hy-secret@hy.example.com:443,5000-5002/?sni=hy.example.com&hop-interval=15-30#Range".to_owned(),
            (15, Some(30)),
        ),
        ("sing-box", sing_box, (15, Some(30))),
    ] {
        let imported = import_subscription_document(&document).expect(label);
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical profile");
        let outbound = &profile["outbounds"][0];
        assert_eq!(outbound["hop_interval_seconds"], expected.0, "{label}");
        match expected.1 {
            Some(maximum) => assert_eq!(outbound["hop_interval_max_seconds"], maximum, "{label}"),
            None => assert!(outbound.get("hop_interval_max_seconds").is_none(), "{label}"),
        }
        let projected = imported
            .profile
            .project(SYNTHETIC_PROFILE_ID, ProjectionMode::SystemProxy, &EngineSettings::default())
            .expect("Hysteria2 range projection");
        let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime JSON");
        let hysteria2 = runtime["outbounds"]
            .as_array()
            .expect("runtime outbounds")
            .iter()
            .find(|candidate| candidate["type"] == "hysteria2")
            .expect("runtime Hysteria2");
        assert_eq!(hysteria2["hop_interval"], format!("{}s", expected.0), "{label}");
        match expected.1 {
            Some(maximum) => {
                assert_eq!(hysteria2["hop_interval_max"], format!("{maximum}s"), "{label}")
            }
            None => assert!(hysteria2.get("hop_interval_max").is_none(), "{label}"),
        }
    }
}

#[test]
fn hysteria2_gecko_obfs_and_bbr_profile_import_from_clash_and_sing_box() {
    let clash = |extra: &str| {
        format!(
            "proxies:\n  - name: Gecko\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    password: hy-secret\n{extra}"
        )
    };
    let sing_box = |extra: Value| {
        let mut outbound = json!({
            "type": "hysteria2",
            "tag": "Gecko",
            "server": "hy.example.com",
            "server_port": 443,
            "password": "hy-secret",
            "tls": { "enabled": true, "server_name": "hy.example.com" }
        });
        for (key, value) in extra.as_object().expect("extra fields") {
            outbound[key] = value.clone();
        }
        json!({ "outbounds": [outbound] }).to_string()
    };
    for (label, document) in [
        (
            "Clash",
            clash(
                "    obfs: gecko\n    obfs-password: mask-secret\n    obfs-min-packet-size: 400\n    obfs-max-packet-size: 1400\n    bbr-profile: conservative\n",
            ),
        ),
        (
            "sing-box",
            sing_box(json!({
                "obfs": {"type": "gecko", "password": "mask-secret", "min_packet_size": 400, "max_packet_size": 1400},
                "bbr_profile": "conservative"
            })),
        ),
    ] {
        let imported = import_subscription_document(&document).expect(label);
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical profile");
        let outbound = &profile["outbounds"][0];
        assert_eq!(outbound["obfs"]["type"], "gecko", "{label}");
        assert_eq!(
            outbound["obfs"]["credential_ref"]["kind"], "hysteria2_obfs_password",
            "{label}"
        );
        assert_eq!(outbound["obfs"]["min_packet_size"], 400, "{label}");
        assert_eq!(outbound["obfs"]["max_packet_size"], 1400, "{label}");
        assert_eq!(outbound["bbr_profile"], "conservative", "{label}");
        assert!(
            imported
                .credentials
                .iter()
                .any(|credential| credential.secret == "mask-secret"),
            "{label}"
        );
    }
    let defaults =
        import_subscription_document(&clash("    obfs: gecko\n    obfs-password: mask-secret\n"))
            .expect("gecko with the runtime packet sizes");
    let profile: Value = serde_json::from_str(defaults.profile.as_json()).expect("profile");
    assert!(
        profile["outbounds"][0]["obfs"]
            .get("min_packet_size")
            .is_none()
    );

    for (label, document, expected) in [
        (
            "Clash unknown BBR profile",
            clash("    bbr-profile: fast\n"),
            "bbr-profile",
        ),
        (
            "Clash BBR profile beside Brutal upload",
            clash("    up: 100\n    bbr-profile: standard\n"),
            "bbr_profile is ignored when up_mbps selects Brutal",
        ),
        (
            "Clash salamander packet size",
            clash(
                "    obfs: salamander\n    obfs-password: mask-secret\n    obfs-min-packet-size: 400\n",
            ),
            "unsupported keys",
        ),
        (
            "Clash gecko packet size beyond the wire limit",
            clash(
                "    obfs: gecko\n    obfs-password: mask-secret\n    obfs-max-packet-size: 4096\n",
            ),
            "gecko packet sizes",
        ),
        (
            "sing-box Chrome parrot switch",
            sing_box(json!({"disable_chrome_parrot": true})),
            "disable_chrome_parrot is unsupported",
        ),
    ] {
        let error = import_subscription_document(&document).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("mask-secret"), "{label}: {error}");
    }
}

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
fn imports_clash_h2_httpupgrade_and_quic_transport_matrix() {
    let document = r#"
proxies:
  - name: H2
    type: vless
    server: v.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    network: h2
    h2-opts:
      path: /h2
      host: [one.example, two.example]
  - name: Upgrade
    type: trojan
    server: t.example
    port: 443
    password: TopSecretValue!
    network: httpupgrade
    http-upgrade-opts:
      path: /up
      host: edge.example
  - name: QUIC
    type: vmess
    server: q.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    alterId: 0
    network: quic
    tls: true
    servername: q.example
"#;
    let imported = import_subscription_document(document).expect("Clash transport matrix");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical Clash transports");
    assert_eq!(profile["outbounds"][0]["transport"]["type"], "http");
    assert_eq!(profile["outbounds"][1]["transport"]["type"], "http_upgrade");
    assert_eq!(profile["outbounds"][2]["transport"]["type"], "quic");
    assert!(!imported.profile.as_json().contains("TopSecretValue!"));
}

#[test]
fn imports_mihomo_vmess_http_options_and_closed_framing_flags() {
    let document = r#"
proxies:
  - name: HTTP
    type: vmess
    server: vm.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    alterId: 0
    cipher: auto
    global-padding: false
    authenticated-length: false
    network: http
    http-opts:
      method: GET
      path: [/tunnel]
      headers:
        Host: [edge.example]
"#;
    let imported = import_subscription_document(document).expect("Mihomo VMess HTTP options");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical Mihomo profile");
    let transport = &profile["outbounds"][0]["transport"];
    assert_eq!(transport["type"], "http");
    assert_eq!(transport["method"], "GET");
    assert_eq!(transport["path"], "/tunnel");
    assert_eq!(transport["host"], json!(["edge.example"]));

    let projected = imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("Mihomo HTTP runtime projection");
    let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime Mihomo profile");
    assert_eq!(runtime["outbounds"][0]["transport"]["method"], "GET");

    for flag in ["global-padding", "authenticated-length"] {
        let rejected = document.replace(&format!("{flag}: false"), &format!("{flag}: true"));
        let error = import_subscription_document(&rejected).expect_err("active VMess framing");
        assert!(error.contains("not represented by the pinned runtime schema"));
    }

    let secret_header = document.replace(
        "Host: [edge.example]",
        "TopSecretValue123: [TopSecretValue123]",
    );
    let error =
        import_subscription_document(&secret_header).expect_err("unsupported custom header");
    assert!(error.contains("unsupported keys"));
    assert!(!error.contains("TopSecretValue123"));
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
fn imports_clash_meta_yaml_across_all_supported_types() {
    let document = r#"
mixed-port: 7890
dns:
  enable: true
  nameserver: [https://1.1.1.1/dns-query]
proxies:
  - name: "SS Tokyo"
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "0123"
    udp: true
  - name: VMess Edge
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    servername: vmess.example.com
    client-fingerprint: chrome
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: edge.example.com
  - name: Reality
    type: vless
    server: vless.example.com
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    flow: xtls-rprx-vision
    encryption: ""
    packet-encoding: xudp
    tls: true
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
      short-id: 0123456789abcdef
  - name: Work
    type: trojan
    server: trojan.example.com
    port: 443
    password: hunter2
    sni: trojan.example.com
    alpn:
      - h2
      - http/1.1
    network: grpc
    grpc-opts:
      grpc-service-name: tunnel
  - name: Work-2
    type: hysteria2
    server: hy2.example.com
    port: 8443
    password: supersecret
    sni: hy2.example.com
    up: "100 Mbps"
    down: "200"
    obfs: salamander
    obfs-password: mask
  - name: AnyTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: anytls-secret
    tls: true
    sni: front.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
      short-id: 0123456789abcdef
  - name: TUIC
    type: tuic
    server: tuic.example.com
    port: 10443
    uuid: 33333333-3333-4333-8333-333333333333
    password: tuic-secret
    sni: tuic.example.com
    alpn: [h3]
    congestion-controller: new_reno
    udp-relay-mode: quic
    reduce-rtt: false
    udp-over-stream: false
    disable-sni: false
proxy-groups:
  - name: PROXY
    type: select
    proxies: [SS Tokyo, VMess Edge]
rules:
  - MATCH,PROXY
"#;
    let imported = import_subscription_document(document).expect("Clash Meta YAML");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    let outbounds = profile["outbounds"].as_array().expect("outbounds array");
    assert_eq!(outbounds.len(), 8);
    assert_eq!(outbounds[7]["type"], "selector");
    assert_eq!(outbounds[7]["tag"], "PROXY");
    assert_eq!(outbounds[7]["outbounds"], json!(["SS Tokyo", "VMess Edge"]));
    assert_eq!(profile["route"]["final"], "PROXY");

    assert_eq!(profile["dns"]["servers"][0]["type"], "https");

    assert_eq!(outbounds[0]["type"], "shadowsocks");
    assert_eq!(outbounds[0]["tag"], "SS Tokyo");
    assert_eq!(outbounds[0]["method"], "aes-256-gcm");

    assert_eq!(outbounds[1]["type"], "vmess");
    assert_eq!(outbounds[1]["tls"]["server_name"], "vmess.example.com");
    assert_eq!(outbounds[1]["tls"]["utls"]["fingerprint"], "chrome");
    assert_eq!(outbounds[1]["transport"]["type"], "ws");
    assert_eq!(outbounds[1]["transport"]["path"], "/ws");
    assert_eq!(
        outbounds[1]["transport"]["headers"]["Host"],
        "edge.example.com"
    );
    assert!(
        outbounds[1].get("security").is_none(),
        "auto is the default"
    );

    assert_eq!(outbounds[2]["type"], "vless");
    assert_eq!(outbounds[2]["flow"], "xtls-rprx-vision");
    assert_eq!(outbounds[2]["packet_encoding"], "xudp");
    assert_eq!(outbounds[2]["tls"]["server_name"], "www.example.com");
    assert_eq!(outbounds[2]["tls"]["reality"]["enabled"], true);
    assert_eq!(
        outbounds[2]["tls"]["reality"]["public_key"],
        "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
    );
    assert_eq!(
        outbounds[2]["tls"]["reality"]["short_id"],
        "0123456789abcdef"
    );

    assert_eq!(outbounds[3]["type"], "trojan");
    assert_eq!(outbounds[3]["tag"], "Work");
    assert_eq!(outbounds[3]["tls"]["alpn"][0], "h2");
    assert_eq!(outbounds[3]["transport"]["type"], "grpc");
    assert_eq!(outbounds[3]["transport"]["service_name"], "tunnel");

    assert_eq!(outbounds[4]["type"], "hysteria2");
    assert_eq!(
        outbounds[4]["tag"], "Work-2",
        "duplicate names get suffixes"
    );
    assert_eq!(outbounds[4]["up_mbps"], 100);
    assert_eq!(outbounds[4]["down_mbps"], 200);
    assert_eq!(outbounds[4]["obfs"]["type"], "salamander");

    assert_eq!(outbounds[5]["type"], "anytls");
    assert_eq!(outbounds[5]["tls"]["server_name"], "front.example.com");
    assert_eq!(outbounds[5]["tls"]["utls"]["fingerprint"], "chrome");
    assert_eq!(outbounds[5]["tls"]["reality"]["enabled"], true);

    assert_eq!(outbounds[6]["type"], "tuic");
    assert_eq!(outbounds[6]["congestion_control"], "new_reno");
    assert_eq!(outbounds[6]["udp_relay_mode"], "quic");
    assert_eq!(outbounds[6]["tls"]["alpn"], json!(["h3"]));

    let secrets: Vec<&str> = imported
        .credentials
        .iter()
        .map(|credential| credential.secret.as_str())
        .collect();
    assert_eq!(
        secrets,
        [
            "0123",
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "hunter2",
            "supersecret",
            "mask",
            "anytls-secret",
            "33333333-3333-4333-8333-333333333333",
            "tuic-secret",
        ],
        "secrets keep exact source bytes, including leading zeros"
    );
    assert_eq!(
        imported.credentials[5].reference.kind(),
        CredentialKind::Hysteria2ObfsPassword
    );
    assert_eq!(
        imported.credentials[6].reference.kind(),
        CredentialKind::AnyTlsPassword
    );
    assert_eq!(
        imported.credentials[7].reference.kind(),
        CredentialKind::TuicUuid
    );
    assert_eq!(
        imported.credentials[8].reference.kind(),
        CredentialKind::TuicPassword
    );
    let stored = imported.profile.as_json();
    for secret in [
        "hunter2",
        "supersecret",
        "mask",
        "anytls-secret",
        "33333333-3333-4333-8333-333333333333",
        "tuic-secret",
    ] {
        assert!(
            !stored.contains(secret),
            "stored profile must not embed secrets"
        );
    }
}

#[test]
fn reality_imports_without_utls_fail_at_import_instead_of_engine_start() {
    const PUBLIC_KEY: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
    let clash_vless = |fingerprint: &str| {
        format!(
            "proxies:\n  - name: Reality\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    tls: true\n    servername: www.example.com\n{fingerprint}    reality-opts:\n      public-key: {PUBLIC_KEY}\n      short-id: 0123456789abcdef\n"
        )
    };
    let clash_anytls = format!(
        "proxies:\n  - name: AnyTLS\n    type: anytls\n    server: anytls.example.com\n    port: 443\n    password: TopSecretValue!\n    sni: front.example.com\n    reality-opts:\n      public-key: {PUBLIC_KEY}\n      short-id: 0123456789abcdef\n"
    );
    let vless_uri = |fingerprint: &str| {
        format!(
            "vless://22222222-2222-4222-8222-222222222222@vless.example.com:443?security=reality&sni=www.example.com&pbk={PUBLIC_KEY}&sid=0123456789abcdef{fingerprint}&encryption=none#Reality"
        )
    };
    let sing_box = |utls: Value| {
        let mut tls = json!({
            "enabled": true,
            "server_name": "www.example.com",
            "reality": {"enabled": true, "public_key": PUBLIC_KEY, "short_id": "0123456789abcdef"},
        });
        if !utls.is_null() {
            tls["utls"] = utls;
        }
        json!({"outbounds": [{
            "type": "vless", "tag": "Reality", "server": "vless.example.com",
            "server_port": 443, "uuid": "22222222-2222-4222-8222-222222222222", "tls": tls,
        }]})
        .to_string()
    };

    for (label, document) in [
        ("Clash VLESS without client-fingerprint", clash_vless("")),
        (
            "Clash VLESS with an empty client-fingerprint",
            clash_vless("    client-fingerprint: \"\"\n"),
        ),
        ("Clash AnyTLS without client-fingerprint", clash_anytls),
        ("VLESS URI without fp", vless_uri("")),
        ("VLESS URI with an empty fp", vless_uri("&fp=")),
        ("sing-box JSON without utls", sing_box(Value::Null)),
        (
            "sing-box JSON with an empty disabled utls",
            sing_box(json!({"enabled": false})),
        ),
    ] {
        let error = import_subscription_document(&document).expect_err(label);
        assert_eq!(
            error,
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS",
            "{label}"
        );
    }

    let accepted = [
        clash_vless("    client-fingerprint: chrome\n"),
        vless_uri("&fp=chrome"),
        sing_box(json!({"enabled": true, "fingerprint": "chrome"})),
    ];
    for document in accepted {
        let imported = import_subscription_document(&document).expect("Reality with uTLS");
        let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
        assert_eq!(
            profile["outbounds"][0]["tls"]["utls"],
            json!({"enabled": true, "fingerprint": "chrome"})
        );
        assert_eq!(profile["outbounds"][0]["tls"]["reality"]["enabled"], true);
    }
}

const GLOBAL_FINGERPRINT_NAMESPACE: &str = "cccccccc-cccc-5ccc-8ccc-cccccccccccc";

/// One Clash proxy of every type Mihomo before v1.19.27 gave its
/// `global-client-fingerprint`: TLS VMess, VLESS with and without Reality,
/// Trojan and AnyTLS. `fingerprint` is inserted into each entry verbatim.
fn clash_tls_stream_proxies(fingerprint: &str) -> String {
    const PUBLIC_KEY: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
    format!(
        "proxies:
  - name: VMess
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    network: ws
{fingerprint}  - name: VLESS
    type: vless
    server: vless.example.com
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    tls: true
{fingerprint}  - name: Reality
    type: vless
    server: reality.example.com
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    tls: true
    servername: www.example.com
{fingerprint}    reality-opts:
      public-key: {PUBLIC_KEY}
      short-id: 0123456789abcdef
  - name: Trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: TopSecretValue!
{fingerprint}  - name: AnyTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: TopSecretValue!
{fingerprint}"
    )
}

fn import_with_stable_references(document: &str) -> ImportedSubscription {
    import_subscription_document_with_credential_namespace(
        document,
        GLOBAL_FINGERPRINT_NAMESPACE.parse().expect("namespace"),
    )
    .expect("Clash import")
}

fn imported_outbounds(imported: &ImportedSubscription) -> Vec<Value> {
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    profile["outbounds"].as_array().expect("outbounds").clone()
}

fn projected_json(imported: &ImportedSubscription) -> String {
    imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("runtime projection")
        .as_json()
        .to_owned()
}

#[test]
fn clash_global_client_fingerprint_is_written_onto_tls_stream_nodes_without_their_own() {
    let explicit = import_with_stable_references(&clash_tls_stream_proxies(
        "    client-fingerprint: chrome\n",
    ));
    for (label, document) in [
        (
            "absent per-node value",
            format!(
                "{}global-client-fingerprint: Chrome\n",
                clash_tls_stream_proxies("")
            ),
        ),
        (
            "empty per-node value",
            format!(
                "global-client-fingerprint: chrome\n{}",
                clash_tls_stream_proxies("    client-fingerprint: \"\"\n")
            ),
        ),
        (
            "null per-node value",
            format!(
                "global-client-fingerprint: chrome\n{}",
                clash_tls_stream_proxies("    client-fingerprint: ~\n")
            ),
        ),
    ] {
        let inherited = import_with_stable_references(&document);
        let outbounds = imported_outbounds(&inherited);
        assert_eq!(outbounds.len(), 5, "{label}");
        for outbound in &outbounds {
            assert_eq!(
                outbound["tls"]["utls"],
                json!({"enabled": true, "fingerprint": "chrome"}),
                "{label}: {}",
                outbound["tag"]
            );
        }
        assert_eq!(outbounds[2]["tls"]["reality"]["enabled"], true, "{label}");
        assert_eq!(
            inherited.profile.as_json(),
            explicit.profile.as_json(),
            "{label}: the stored profile equals one that names chrome on every node"
        );
        assert_eq!(
            projected_json(&inherited),
            projected_json(&explicit),
            "{label}: the runtime projection is byte-identical"
        );
    }
}

#[test]
fn clash_node_client_fingerprint_takes_precedence_over_the_global_one() {
    let trojan = |name: &str, fingerprint: &str| {
        format!(
            "  - name: {name}\n    type: trojan\n    server: trojan.example.com\n    port: 443\n    password: TopSecretValue!\n{fingerprint}"
        )
    };
    let document = format!(
        "global-client-fingerprint: chrome\nproxies:\n{}{}{}{}",
        trojan("own", "    client-fingerprint: firefox\n"),
        trojan("none", "    client-fingerprint: none\n"),
        trojan("upper-none", "    client-fingerprint: NONE\n"),
        trojan("inherits", ""),
    );
    let outbounds = imported_outbounds(&import_with_stable_references(&document));
    assert_eq!(
        outbounds[0]["tls"]["utls"],
        json!({"enabled": true, "fingerprint": "firefox"})
    );
    for outbound in &outbounds[1..3] {
        assert_eq!(outbound["tls"]["enabled"], true, "{}", outbound["tag"]);
        assert!(
            outbound["tls"].get("utls").is_none(),
            "`none` keeps standard TLS for {}",
            outbound["tag"]
        );
    }
    assert_eq!(
        outbounds[3]["tls"]["utls"],
        json!({"enabled": true, "fingerprint": "chrome"})
    );

    let standalone_none = import_with_stable_references(&format!(
        "proxies:\n{}",
        trojan("none", "    client-fingerprint: none\n")
    ));
    assert!(
        imported_outbounds(&standalone_none)[0]["tls"]
            .get("utls")
            .is_none()
    );

    let reality_with_none = "global-client-fingerprint: chrome\nproxies:\n  - name: Reality\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    tls: true\n    client-fingerprint: none\n    reality-opts:\n      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0\n";
    assert_eq!(
        import_subscription_document(reality_with_none).expect_err("Reality over standard TLS"),
        "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
    );
}

#[test]
fn clash_global_client_fingerprint_none_empty_or_null_sets_no_default() {
    let trojan = "proxies:\n  - name: Trojan\n    type: trojan\n    server: trojan.example.com\n    port: 443\n    password: TopSecretValue!\n";
    let reality = "proxies:\n  - name: Reality\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    tls: true\n    reality-opts:\n      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0\n";
    let without_key = import_with_stable_references(trojan);
    for global in [
        "global-client-fingerprint: none\n",
        "global-client-fingerprint: None\n",
        "global-client-fingerprint: \"\"\n",
        "global-client-fingerprint: ~\n",
        "global-client-fingerprint:\n",
    ] {
        let imported = import_with_stable_references(&format!("{global}{trojan}"));
        assert_eq!(
            imported.profile.as_json(),
            without_key.profile.as_json(),
            "{global}"
        );
        assert_eq!(
            import_subscription_document(&format!("{global}{reality}")).expect_err(global),
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
        );
    }
}

#[test]
fn clash_global_client_fingerprint_rejects_unsupported_and_non_scalar_values() {
    // Only a Shadowsocks node: the value is refused even where it would apply
    // to nothing, because the document names a fingerprint this app lacks.
    let shadowsocks = "proxies:\n  - name: SS\n    type: ss\n    server: ss.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue!\n";
    for (global, expected) in [
        (
            "chrome120",
            "Clash profile.global-client-fingerprint: uTLS fingerprint is unsupported: <redacted>",
        ),
        (
            "TopSecretValue!",
            "Clash profile.global-client-fingerprint: uTLS fingerprint is unsupported: <redacted>",
        ),
        (
            "[chrome]",
            "Clash profile.global-client-fingerprint must be a scalar value",
        ),
        (
            "{name: chrome}",
            "Clash profile.global-client-fingerprint must be a scalar value",
        ),
    ] {
        let error = import_subscription_document(&format!(
            "global-client-fingerprint: {global}\n{shadowsocks}"
        ))
        .expect_err(global);
        assert_eq!(error, expected, "{global}");
    }
}

#[test]
fn clash_global_client_fingerprint_skips_types_mihomo_never_gave_it() {
    let document = "global-client-fingerprint: chrome
proxies:
  - name: HTTPS
    type: http
    server: http.example.com
    port: 443
    tls: true
  - name: HTTPS own
    type: http
    server: http.example.com
    port: 443
    tls: true
    client-fingerprint: firefox
  - name: Hysteria2
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: TopSecretValue!
  - name: TUIC
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    password: TopSecretValue!
  - name: VMess plain
    type: vmess
    server: vmess.example.com
    port: 80
    uuid: 22222222-2222-4222-8222-222222222222
  - name: VMess tls false
    type: vmess
    server: vmess.example.com
    port: 80
    uuid: 33333333-3333-4333-8333-333333333333
    tls: false
  - name: VLESS plain
    type: vless
    server: vless.example.com
    port: 80
    uuid: 44444444-4444-4444-8444-444444444444
";
    let outbounds = imported_outbounds(&import_with_stable_references(document));
    assert_eq!(outbounds.len(), 7);
    assert_eq!(
        outbounds[1]["tls"]["utls"],
        json!({"enabled": true, "fingerprint": "firefox"})
    );
    for outbound in [&outbounds[0], &outbounds[2], &outbounds[3]] {
        assert_eq!(outbound["tls"]["enabled"], true, "{}", outbound["tag"]);
        assert!(
            outbound["tls"].get("utls").is_none(),
            "{} keeps standard TLS",
            outbound["tag"]
        );
    }
    for outbound in &outbounds[4..] {
        assert!(
            outbound.get("tls").is_none(),
            "{} gains no TLS",
            outbound["tag"]
        );
    }

    // A V2Ray QUIC transport cannot carry uTLS. Mihomo has no such transport
    // and gave these nodes the global value over TCP, so the request fails
    // closed exactly like a per-node client-fingerprint does.
    let quic = |global: &str, fingerprint: &str| {
        format!(
            "{global}proxies:\n  - name: QUIC\n    type: vmess\n    server: vmess.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    tls: true\n    network: quic\n{fingerprint}"
        )
    };
    for document in [
        quic("global-client-fingerprint: chrome\n", ""),
        quic("", "    client-fingerprint: chrome\n"),
    ] {
        let error = import_subscription_document(&document).expect_err("uTLS over V2Ray QUIC");
        assert!(error.contains("uTLS is unavailable for QUIC"), "{error}");
    }
    import_subscription_document(&quic("global-client-fingerprint: none\n", ""))
        .expect("standard TLS over V2Ray QUIC");
}

#[test]
fn none_fingerprint_stays_unsupported_outside_clash_documents() {
    let uri = "vless://22222222-2222-4222-8222-222222222222@vless.example.com:443?security=tls&sni=vless.example.com&fp=none&encryption=none#TLS";
    let sing_box = json!({"outbounds": [{
        "type": "vless", "tag": "TLS", "server": "vless.example.com", "server_port": 443,
        "uuid": "22222222-2222-4222-8222-222222222222",
        "tls": {"enabled": true, "server_name": "vless.example.com",
                "utls": {"enabled": true, "fingerprint": "none"}},
    }]})
    .to_string();
    for document in [uri.to_owned(), sing_box] {
        assert_eq!(
            import_subscription_document(&document).expect_err("`none` is Clash-only"),
            "uTLS fingerprint is unsupported: <redacted>"
        );
    }
}

#[test]
fn clash_import_preserves_groups_process_geoip_and_ordered_rules() {
    let source = r#"
proxies:
  - {name: Node A, type: socks5, server: edge.example.com, port: 1080}
  - {name: Node B, type: socks5, server: backup.example.com, port: 1080}
proxy-groups:
  - {name: PROXY, type: select, proxies: [Node A, Node B, DIRECT]}
rules:
  - PROCESS-NAME,Example Client,PROXY
  - DOMAIN-SUFFIX,example.com,PROXY
  - IP-CIDR,192.0.2.1/32,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;
    let imported = import_subscription_document(source).expect("complete Clash policy");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(profile["outbounds"][3]["tag"], "PROXY");
    assert_eq!(
        profile["outbounds"][3]["outbounds"],
        json!(["Node A", "Node B", "DIRECT"])
    );
    assert_eq!(profile["route"]["final"], "PROXY");
    assert_eq!(
        profile["route"]["rules"].as_array().expect("rules").len(),
        4
    );
    assert_eq!(profile["route"]["rules"][0]["type"], "process_name");
    assert_eq!(profile["route"]["rules"][2]["no_resolve"], true);
    assert_eq!(profile["route"]["rules"][3]["type"], "geo_ip");
    for broken in [
        source.replace("[Node A, Node B, DIRECT]", "[Node A, absent]"),
        source.replace("[Node A, Node B, DIRECT]", "[PROXY]"),
        source.replace("GEOIP,CN,DIRECT", "UNKNOWN,CN,DIRECT"),
        source.replace("type: select", "type: unsupported"),
    ] {
        assert!(
            import_subscription_document(&broken).is_err(),
            "invalid policy cannot become nodes-only import"
        );
    }
}

#[test]
fn clash_automatic_groups_and_detours_keep_their_source_semantics() {
    let source = "proxies:\n  - {name: Entry, type: socks5, server: entry.example.com, port: 1080}\n  - {name: Exit, type: socks5, server: exit.example.com, port: 1080, dialer-proxy: Entry}\nproxy-groups:\n  - {name: Auto, type: url-test, proxies: [Exit, Entry], url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 150}\nrules:\n  - MATCH,Auto\n";
    let imported = import_subscription_document(source).expect("automatic and multihop");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(profile["outbounds"][2]["type"], "urltest");
    assert_eq!(profile["outbounds"][2]["tolerance_ms"], 150);
    assert_eq!(profile["outbounds"][2]["interval_seconds"], 300);
    assert_eq!(profile["detours"]["Exit"], "Entry");
    for bad in [
        source.replace("interval: 300", "interval: 0"),
        source.replace("dialer-proxy: Entry", "dialer-proxy: Auto"),
        source.replace("type: url-test", "type: fallback"),
    ] {
        assert!(import_subscription_document(&bad).is_err());
    }
}

#[test]
fn clash_fallback_preserves_order_and_rejects_latency_selection_fields() {
    let source = "proxies:\n  - {name: Primary, type: socks5, server: primary.example.com, port: 1080}\n  - {name: Backup, type: socks5, server: backup.example.com, port: 1080}\nproxy-groups:\n  - {name: Failover, type: fallback, proxies: [Primary, Backup], url: 'https://example.com/probe', interval: 300}\nrules:\n  - MATCH,Failover\n";
    let imported = import_subscription_document(source).unwrap();
    let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
    assert_eq!(profile["outbounds"][2]["type"], "fallback");
    assert_eq!(
        profile["outbounds"][2]["outbounds"],
        json!(["Primary", "Backup"])
    );
    assert!(profile["outbounds"][2].get("tolerance_ms").is_none());
    assert!(
        import_subscription_document(
            &source.replace("interval: 300", "interval: 300, tolerance: 50")
        )
        .is_err()
    );
    assert!(
        import_subscription_document(&source.replace("[Primary, Backup]", "[Failover]")).is_err()
    );
}

#[test]
fn clash_wireguard_import_keeps_keys_only_in_the_vault_batch() {
    let key = STANDARD.encode([1u8; 32]);
    let source = format!(
        "proxies:\n  - {{name: VPN, type: wireguard, server: edge.example.com, port: 51820, ip: 10.1.0.2, private-key: '{key}', public-key: '{key}', pre-shared-key: '{key}'}}\n"
    );
    let imported = import_subscription_document(&source).expect("WireGuard import");
    assert_eq!(imported.credentials.len(), 2);
    assert_eq!(
        imported.credentials[0].reference.kind(),
        CredentialKind::WireGuardPrivateKey
    );
    assert_eq!(
        imported.credentials[1].reference.kind(),
        CredentialKind::WireGuardPreSharedKey
    );
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(
        profile["outbounds"][0]["local_addresses"],
        json!(["10.1.0.2/32"])
    );
    assert!(profile["outbounds"][0].get("private-key").is_none());
    assert!(profile["outbounds"][0].get("private_key").is_none());
    assert!(profile["outbounds"][0].get("pre_shared_key").is_none());
}

#[test]
fn clash_yaml_conversion_fails_closed_without_echoing_secrets() {
    let unsupported_type = "proxies:\n  - name: node\n    type: wireguard\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n";
    let error = import_subscription_document(unsupported_type).expect_err("unsupported proxy type");
    assert!(error.contains("proxies[0]"), "{error}");
    assert!(!error.contains("wireguard"), "{error}");
    assert!(!error.contains("TopSecretValue!"), "{error}");

    let insecure = "proxies:\n  - name: node\n    type: trojan\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    skip-cert-verify: true\n";
    let error = import_subscription_document(insecure).expect_err("skip-cert-verify");
    assert!(
        error.contains("disabling TLS certificate verification"),
        "{error}"
    );
    assert!(!error.contains("TopSecretValue!"), "{error}");

    let multiplexed = "proxies:\n  - name: node\n    type: trojan\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    smux:\n      enabled: true\n";
    let error = import_subscription_document(multiplexed).expect_err("smux");
    assert!(
        error.contains("uses stream multiplexing (smux), which is not supported"),
        "{error}"
    );
    assert!(!error.contains("TopSecretValue!"), "{error}");

    let unknown_key = "proxies:\n  - name: node\n    type: ss\n    server: a.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue!\n    TopSecretValue123: 5\n";
    let error = import_subscription_document(unknown_key).expect_err("unknown key");
    assert!(error.contains("unsupported keys"), "{error}");
    assert!(!error.contains("TopSecretValue123"), "{error}");
    assert!(!error.contains("TopSecretValue!"), "{error}");

    let alias_bomb = "proxies: &a\n  - name: node\nmore: *a\n";
    let error = import_subscription_document(alias_bomb).expect_err("aliases rejected");
    assert!(error.contains("anchors are not supported"), "{error}");

    let missing_proxies = "mixed-port: 7890\n";
    let error = import_subscription_document(missing_proxies).expect_err("no proxies");
    assert!(error.contains("no proxies list"), "{error}");

    let overlapping_ports = "proxies:\n  - name: node\n    type: hysteria2\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    ports: 20000-30000,25000-31000\n";
    let error =
        import_subscription_document(overlapping_ports).expect_err("overlapping port ranges");
    assert!(error.contains("overlapping"), "{error}");
    assert!(!error.contains("TopSecretValue!"), "{error}");

    for (label, document, expected) in [
        (
            "TUIC 0-RTT",
            "proxies:\n  - name: node\n    type: tuic\n    server: a.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    password: TopSecretValue!\n    reduce-rtt: true\n",
            "0-RTT",
        ),
        (
            "TUIC uTLS",
            "proxies:\n  - name: node\n    type: tuic\n    server: a.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    password: TopSecretValue!\n    client-fingerprint: chrome\n",
            "does not support uTLS",
        ),
        (
            "Hysteria2 uTLS",
            "proxies:\n  - name: node\n    type: hysteria2\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    client-fingerprint: chrome\n",
            "does not support uTLS",
        ),
    ] {
        let error = import_subscription_document(document).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }
}

#[test]
fn rejects_unsupported_uri_schemes() {
    let error = import_subscription_document("shadowtls://token@example.com:443#ShadowTLS")
        .expect_err("unsupported scheme");
    assert!(error.contains("unsupported"));
}

#[test]
fn uri_bundle_errors_never_echo_line_content() {
    let error = import_subscription_document("not json and not a uri TopSecretValue!")
        .expect_err("unrecognized document");
    assert!(!error.contains("TopSecretValue!"), "{error}");
    assert!(error.contains("subscription line 1"), "{error}");
}

/// Byte-identity goldens for stored imports, captured on the 0.5 line before
/// Hysteria2 links accepted `pinSHA256` and before every importer emitted its
/// certificate pins through `TlsParts`. A mismatch writes the actual output to
/// `target/tmp/import-goldens/` and fails; the goldens are never rewritten
/// automatically. Secrets appear only as SHA-256 digests.
mod import_goldens {
    use std::path::PathBuf;

    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};

    use super::import_with_stable_references;

    const CASES: &[(&str, &str)] = &[
        (
            "clash-mooring-shape",
            r#"proxies:
  - name: "lon1-reality"
    type: "vless"
    server: "45.67.89.10"
    port: 443
    uuid: "6d6f6f72-0101-4001-8000-000000010101"
    flow: "xtls-rprx-vision"
    packet-encoding: "xudp"
    tls: true
    servername: "www.example.com"
    client-fingerprint: "chrome"
    reality-opts:
      public-key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
      short-id: "0123456789abcdef"
  - name: "lon1-hy2"
    type: "hysteria2"
    server: "45.67.89.10"
    port: 61000
    ports: "61000-62999"
    hop-interval: 30
    password: "Hy2PasswordValue1"
    obfs: "salamander"
    obfs-password: "ObfsPasswordValue1"
    sni: "n0123456789abcdef.internal"
    fingerprint: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
"#,
        ),
        (
            "clash-trojan-colon-fingerprint",
            "proxies:\n  - name: trojan-pinned\n    type: trojan\n    server: trojan.example.com\n    port: 443\n    password: TrojanPasswordValue1\n    sni: trojan.example.com\n    fingerprint: \"FF:FE:FD:FC:FB:FA:F9:F8:F7:F6:F5:F4:F3:F2:F1:F0:EF:EE:ED:EC:EB:EA:E9:E8:E7:E6:E5:E4:E3:E2:E1:E0\"\n",
        ),
        (
            "sing-box-mooring-shape",
            r#"{"outbounds":[
  {"type":"vless","tag":"lon1-reality","server":"45.67.89.10","server_port":443,
   "uuid":"6d6f6f72-0101-4001-8000-000000010101","flow":"xtls-rprx-vision","packet_encoding":"xudp",
   "tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},
          "reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}},
  {"type":"hysteria2","tag":"lon1-hy2","server":"45.67.89.10","server_ports":["61000:62999"],"hop_interval":"30s",
   "password":"Hy2PasswordValue1","obfs":{"type":"salamander","password":"ObfsPasswordValue1"},
   "tls":{"enabled":true,"server_name":"n0123456789abcdef.internal",
          "certificate_public_key_sha256":["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]}}]}"#,
        ),
        (
            "sing-box-der-pins",
            r#"{"outbounds":[
  {"type":"hysteria2","tag":"hy2-pinned","server":"hy2.example.com","server_port":443,"password":"Hy2PasswordValue2",
   "tls":{"enabled":true,"server_name":"hy2.example.com",
          "certificate_sha256":["//////////////////////////////////////////8=","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]}},
  {"type":"trojan","tag":"trojan-pinned","server":"trojan.example.com","server_port":443,"password":"TrojanPasswordValue2",
   "tls":{"enabled":true,"server_name":"trojan.example.com",
          "certificate_sha256":["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]}}]}"#,
        ),
        (
            "uri-bundle",
            "hy2://Hy2PasswordValue3@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=ObfsPasswordValue3#HY2\n\
hysteria2://Hy2PasswordValue4@hop.example.com:443,5000-5002?sni=hop.example.com&hop-interval=30#HOP\n\
vless://6d6f6f72-0101-4001-8000-000000010102@vless.example.com:443?security=reality&sni=www.example.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&flow=xtls-rprx-vision&type=tcp#VLESS\n\
trojan://TrojanPasswordValue3@trojan.example.com:443?sni=trojan.example.com#TROJAN\n",
        ),
    ];

    fn golden_directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/subscription_import/goldens")
    }

    fn actual_directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/import-goldens")
    }

    fn snapshot(document: &str) -> String {
        let imported = import_with_stable_references(document);
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("stored profile");
        let credentials = imported
            .credentials
            .iter()
            .map(|credential| {
                json!({
                    "id": credential.reference.id(),
                    "kind": credential.reference.kind(),
                    "secret_sha256": Sha256::digest(credential.secret.as_bytes())
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                })
            })
            .collect::<Vec<_>>();
        let mut text = serde_json::to_string_pretty(&json!({
            "credentials": credentials,
            "digest": imported.profile.digest(),
            "profile": profile,
        }))
        .expect("golden text");
        text.push('\n');
        text
    }

    #[test]
    fn stored_imports_match_the_goldens_captured_before_link_pins() {
        let mut mismatched = Vec::new();
        for (name, document) in CASES {
            let actual = snapshot(document);
            let path = golden_directory().join(format!("{name}.json"));
            if std::fs::read_to_string(&path).ok().as_deref() != Some(actual.as_str()) {
                let output = actual_directory();
                std::fs::create_dir_all(&output).expect("actual output directory");
                std::fs::write(output.join(format!("{name}.json")), &actual)
                    .expect("actual output");
                mismatched.push(*name);
            }
        }
        let mut stored = std::fs::read_dir(golden_directory())
            .map(|entries| {
                entries
                    .map(|entry| {
                        entry
                            .expect("golden entry")
                            .file_name()
                            .into_string()
                            .expect("UTF-8 golden name")
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        stored.sort();
        let mut expected = CASES
            .iter()
            .map(|(name, _)| format!("{name}.json"))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(stored, expected, "no stray or missing golden");
        assert!(
            mismatched.is_empty(),
            "stored imports differ from the goldens: {mismatched:?}; actual output in {}",
            actual_directory().display()
        );
    }
}

const ASCENDING_PIN_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ASCENDING_PIN_BASE64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

#[test]
fn tls_parts_emit_certificate_sha256_only_when_present() {
    let parts = || build_tls_parts(true, "pinned.example.com".into(), Vec::new(), None, None);
    assert_eq!(
        tls_json(parts()),
        json!({"enabled":true,"server_name":"pinned.example.com"})
    );
    let pinned = tls_json(TlsParts {
        certificate_sha256: vec!["first".into(), "second".into()],
        ..parts()
    });
    assert_eq!(
        pinned,
        json!({"enabled":true,"server_name":"pinned.example.com","certificate_sha256":["first","second"]})
    );
}

#[test]
fn hysteria2_share_links_import_pin_sha256_as_a_certificate_pin() {
    let upper_colons = ASCENDING_PIN_HEX
        .to_ascii_uppercase()
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).expect("ASCII hex"))
        .collect::<Vec<_>>()
        .join(":");
    let dashes = upper_colons.to_ascii_lowercase().replace(':', "-");
    for (label, uri) in [
        (
            "hy2 scheme, OpenSSL form",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&pinSHA256={upper_colons}#HY2"
            ),
        ),
        (
            "hysteria2 scheme, dashes",
            format!(
                "hysteria2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&pinSHA256={dashes}#HY2"
            ),
        ),
        (
            "percent-encoded colons",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&pinSHA256={}#HY2",
                upper_colons.replace(':', "%3A")
            ),
        ),
        (
            "explicit insecure=0",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&insecure=0&pinSHA256={ASCENDING_PIN_HEX}#HY2"
            ),
        ),
        (
            // Upstream pairs insecure=1 with a pin for self-signed servers. CFM
            // verifies the pin with the name and validity checks and never
            // emits insecure.
            "insecure=1 beside a pin",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&insecure=1&pinSHA256={ASCENDING_PIN_HEX}#HY2"
            ),
        ),
        (
            "every insecure alias beside a pin",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&allowInsecure=1&allow_insecure=true&skip-cert-verify=1&pinSHA256={ASCENDING_PIN_HEX}#HY2"
            ),
        ),
    ] {
        let imported =
            import_subscription_document(&uri).unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_eq!(
            imported_outbounds(&imported)[0]["tls"],
            json!({"enabled":true,"server_name":"hy2.example.com","certificate_sha256":[ASCENDING_PIN_BASE64]}),
            "{label}"
        );
        // The pin is profile data: the vault receives only the password.
        assert_eq!(imported.credentials.len(), 1, "{label}");
        let runtime: Value = serde_json::from_str(&projected_json(&imported)).expect("runtime");
        let tls = &runtime["outbounds"][0]["tls"];
        assert_eq!(
            tls["certificate_sha256"],
            json!([ASCENDING_PIN_BASE64]),
            "{label}"
        );
        assert_eq!(tls["server_name"], "hy2.example.com", "{label}");
        assert!(tls.get("insecure").is_none(), "{label}");
        assert!(
            tls.get("certificate_public_key_sha256").is_none(),
            "{label}"
        );
    }
    let hopping = import_subscription_document(&format!(
        "hysteria2://TopSecretValue%21@hop.example.com:443,5000-5002?sni=hop.example.com&obfs=salamander&obfs-password=ObfsSecret&hop-interval=30&pinSHA256={ASCENDING_PIN_HEX}#HOP"
    ))
    .expect("pinned port-hopping link");
    let outbound = &imported_outbounds(&hopping)[0];
    assert_eq!(
        outbound["tls"]["certificate_sha256"],
        json!([ASCENDING_PIN_BASE64])
    );
    assert_eq!(outbound["server_ports"], json!(["443", "5000:5002"]));
    assert_eq!(outbound["hop_interval_seconds"], json!(30));
    assert_eq!(hopping.credentials.len(), 2);
    let pinned_to = |hex: &str| {
        import_subscription_document(&format!(
            "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&pinSHA256={hex}#HY2"
        ))
        .expect("pinned link")
        .profile
        .digest()
        .to_owned()
    };
    assert_ne!(pinned_to(ASCENDING_PIN_HEX), pinned_to(&"ff".repeat(32)));
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

#[test]
fn clash_geosite_rules_import_as_lowercase_dataset_rules() {
    let source = r#"
proxies:
  - {name: Node A, type: socks5, server: edge.example.com, port: 1080}
proxy-groups:
  - {name: PROXY, type: select, proxies: [Node A, DIRECT]}
rules:
  - GEOSITE,Geolocation-!CN,PROXY
  - GEOSITE,CN,DIRECT
  - GEOSITE,google@!cn,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;
    let imported = import_subscription_document(source).expect("GEOSITE policy");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(
        profile["route"]["rules"],
        json!([
            {"type":"geo_site","value":"geolocation-!cn","outbound":"PROXY","no_resolve":false},
            {"type":"geo_site","value":"cn","outbound":"DIRECT","no_resolve":false},
            {"type":"geo_site","value":"google@!cn","outbound":"PROXY","no_resolve":false},
            {"type":"geo_ip","value":"CN","outbound":"DIRECT","no_resolve":false}
        ])
    );
    let runtime: Value = serde_json::from_str(&projected_json(&imported)).expect("runtime");
    assert_eq!(
        runtime["route"]["rule_set"]
            .as_array()
            .expect("rule sets")
            .iter()
            .map(|resource| resource["tag"].clone())
            .collect::<Vec<_>>(),
        [
            json!("cfw-geoip-cn"),
            json!("cfw-geosite-cn"),
            json!("cfw-geosite-geolocation-!cn"),
            json!("cfw-geosite-google@!cn")
        ]
    );
    for (broken, expected) in [
        ("GEOSITE,CN,DIRECT,no-resolve", "no_resolve is only valid"),
        (
            "GEOSITE,../cn,DIRECT",
            "rule value does not match its declared type",
        ),
        (
            "GEOSITE,a@b@c,DIRECT",
            "rule value does not match its declared type",
        ),
    ] {
        let error = import_subscription_document(&source.replace("GEOSITE,CN,DIRECT", broken))
            .expect_err(broken);
        assert!(error.contains(expected), "{broken}: {error}");
    }
}

/// Mihomo verifies a node that carries a `fingerprint` against the pin alone,
/// whatever `skip-cert-verify` says, so a redundant `skip-cert-verify: true`
/// beside a pin imports as the pin, as `insecure=1` beside `pinSHA256` does
/// for share links. Without a usable pin it still fails closed.
#[test]
fn clash_skip_cert_verify_beside_a_pin_imports_as_the_pin() {
    let colons = ASCENDING_PIN_HEX
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).expect("ASCII hex"))
        .collect::<Vec<_>>()
        .join(":");
    let hysteria2 = |extra: &str| {
        format!(
            "proxies:\n  - name: node\n    type: hysteria2\n    server: hy2.example.com\n    port: 443\n    password: TopSecretValue!\n    sni: hy2.example.com\n{extra}"
        )
    };
    let trojan = |extra: &str| {
        format!(
            "proxies:\n  - name: node\n    type: trojan\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    sni: a.example.com\n{extra}"
        )
    };
    for (label, document, server_name) in [
        (
            "hysteria2",
            hysteria2(&format!(
                "    skip-cert-verify: true\n    fingerprint: {ASCENDING_PIN_HEX}\n"
            )),
            "hy2.example.com",
        ),
        (
            "hysteria2, pin first",
            hysteria2(&format!(
                "    fingerprint: \"{colons}\"\n    skip-cert-verify: true\n"
            )),
            "hy2.example.com",
        ),
        (
            "trojan",
            trojan(&format!(
                "    skip-cert-verify: true\n    fingerprint: {ASCENDING_PIN_HEX}\n"
            )),
            "a.example.com",
        ),
    ] {
        let imported = import_subscription_document(&document)
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        let tls = &imported_outbounds(&imported)[0]["tls"];
        assert_eq!(
            tls["certificate_sha256"],
            json!([ASCENDING_PIN_BASE64]),
            "{label}"
        );
        assert_eq!(tls["server_name"], server_name, "{label}");
        assert!(tls.get("insecure").is_none(), "{label}");
        let runtime: Value = serde_json::from_str(&projected_json(&imported)).expect("runtime");
        assert!(
            runtime["outbounds"][0]["tls"].get("insecure").is_none(),
            "{label}"
        );
    }
    for (label, document, reason) in [
        (
            "no pin",
            hysteria2("    skip-cert-verify: true\n"),
            "disabling TLS certificate verification",
        ),
        (
            "an empty pin",
            hysteria2("    skip-cert-verify: true\n    fingerprint: \"\"\n"),
            "disabling TLS certificate verification",
        ),
        (
            "a null pin",
            hysteria2("    skip-cert-verify: true\n    fingerprint: null\n"),
            "disabling TLS certificate verification",
        ),
        (
            "a malformed pin",
            hysteria2("    skip-cert-verify: true\n    fingerprint: not-a-pin\n"),
            "TLS certificate fingerprint must be a SHA256 hex value",
        ),
        (
            "a pin without TLS",
            format!(
                "proxies:\n  - name: node\n    type: vmess\n    server: a.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    alterId: 0\n    cipher: auto\n    tls: false\n    skip-cert-verify: true\n    fingerprint: {ASCENDING_PIN_HEX}\n"
            ),
            "certificate pin requires TLS",
        ),
        (
            "a type without TLS",
            format!(
                "proxies:\n  - name: node\n    type: ss\n    server: a.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue!\n    skip-cert-verify: true\n    fingerprint: {ASCENDING_PIN_HEX}\n"
            ),
            "unsupported keys",
        ),
    ] {
        let error = import_subscription_document(&document).expect_err(label);
        assert!(error.contains(reason), "{label}: {error}");
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
