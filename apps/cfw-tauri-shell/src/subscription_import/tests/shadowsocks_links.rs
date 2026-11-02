//! Shadowsocks: SIP008 documents, SIP002 links, and Shadowsocks 2022 keys.

use super::*;

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
fn sip008_requires_version_one_and_a_bounded_list_of_usable_servers() {
    let server = |key: &str, value: Value| {
        let mut server = json!({
            "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
            "remarks": "Synthetic",
            "server": "ss.example.com",
            "server_port": 8388,
            "password": "TopSecretValue!",
            "method": "aes-256-gcm"
        });
        server[key] = value;
        server
    };
    let valid = server("remarks", json!("Synthetic"));
    for (document, expected) in [
        (
            json!({ "version": 2, "servers": [valid.clone()] }),
            "SIP008 JSON version is unsupported".to_owned(),
        ),
        (
            json!({ "version": 1, "servers": [] }),
            "SIP008 JSON contains no servers".to_owned(),
        ),
        (
            json!({
                "version": 1,
                "servers": vec![valid.clone(); cfw_singbox_config::MAX_OUTBOUNDS + 1],
            }),
            format!(
                "SIP008 JSON has more than {} servers",
                cfw_singbox_config::MAX_OUTBOUNDS
            ),
        ),
        (
            // At the bound the list is read, and its repeated ids are refused.
            json!({
                "version": 1,
                "servers": vec![valid.clone(); cfw_singbox_config::MAX_OUTBOUNDS],
            }),
            "SIP008 server ids must be unique non-nil UUIDs".to_owned(),
        ),
        (
            json!({ "version": 1, "servers": [server("server_port", json!(0))] }),
            "SIP008 server port is invalid".to_owned(),
        ),
        (
            json!({ "version": 1, "servers": [server("password", json!(""))] }),
            "SIP008 server password is empty".to_owned(),
        ),
    ] {
        assert_eq!(
            import_subscription_document(&document.to_string()).map(|_| ()),
            Err(expected)
        );
    }
}

#[test]
fn shadowsocks_links_refuse_plugins_and_undecodable_credentials() {
    for (uri, expected) in [
        (
            "ss://YWVzLTI1Ni1nY206VG9wU2VjcmV0VmFsdWUh@ss.example.com:8388?plugin=obfs-local#S",
            "Shadowsocks plugins are unsupported in subscription imports",
        ),
        (
            "ss://Top*Secret#S",
            "Shadowsocks URI credentials are invalid base64: input is not valid base64",
        ),
        (
            "ss://Top*Secret@ss.example.com:8388#S",
            "Shadowsocks URI method/password envelope is invalid base64: input is not valid base64",
        ),
    ] {
        assert_eq!(
            import_subscription_document(uri).map(|_| ()),
            Err(expected.into()),
            "{uri}"
        );
    }
}
