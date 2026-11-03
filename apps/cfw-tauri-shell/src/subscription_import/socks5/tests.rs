use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cfw_singbox_config::{EngineSettings, ProjectionMode};
use uuid::Uuid;

use super::super::{
    ImportedSubscription, MAX_SUBSCRIPTION_DOCUMENT_BYTES, import_subscription_document,
    import_subscription_document_with_credential_namespace,
    import_subscription_document_with_reusable_references,
};
use super::*;

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn assert_authentication(imported: &ImportedSubscription, username: &str, password: &str) {
    assert_eq!(imported.credentials.len(), 2);
    assert_eq!(
        imported.credentials[0].reference.kind(),
        CredentialKind::Socks5Username
    );
    assert_eq!(imported.credentials[0].secret, username);
    assert_eq!(
        imported.credentials[1].reference.kind(),
        CredentialKind::Socks5Password
    );
    assert_eq!(imported.credentials[1].secret, password);
    assert!(!imported.profile.as_json().contains(username));
    assert!(!imported.profile.as_json().contains(password));
    assert!(!format!("{imported:?}").contains(password));
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projection = imported
            .profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("SOCKS5 projection");
        let wire: Value = serde_json::from_str(projection.as_json()).expect("runtime JSON");
        assert_eq!(wire["outbounds"][0]["type"], "socks");
        assert_eq!(wire["outbounds"][0]["username"], "");
        assert_eq!(wire["outbounds"][0]["password"], "");
        assert_eq!(projection.credential_slots().len(), 2);
    }
}

#[test]
fn socks5_uri_authentication_preserves_plain_percent_and_base64_bytes() {
    let username = " synthetic user ";
    let password = " p@ss:word+/?#% ";
    let pair = format!("{username}:{password}");
    for scheme in ["socks", "socks5", "SOCKS5"] {
        for userinfo in [
            format!(
                "{}:{}",
                urlencoding::encode(username),
                urlencoding::encode(password)
            ),
            STANDARD.encode(&pair),
            URL_SAFE_NO_PAD.encode(&pair),
        ] {
            let imported = import_subscription_document(&format!(
                "{scheme}://{userinfo}@proxy.example.com:29177#Imported%20SOCKS5"
            ))
            .expect("authenticated SOCKS5 URI");
            assert_authentication(&imported, username, password);
        }
    }
    let encoded = STANDARD.encode("synthetic-user:???");
    assert!(
        encoded.contains('/'),
        "fixture must exercise a base64 slash before @"
    );
    let imported =
        import_subscription_document(&format!("socks://{encoded}@proxy.example.com:1080"))
            .expect("standard base64 userinfo may contain a slash");
    assert_authentication(&imported, "synthetic-user", "???");
}

#[test]
fn socks5_anonymous_uris_support_domain_ipv4_and_ipv6_endpoints() {
    for (authority, expected) in [
        ("proxy.example.com", "proxy.example.com"),
        ("9.9.9.9", "9.9.9.9"),
        ("[2606:4700:4700::1111]", "2606:4700:4700::1111"),
    ] {
        let imported = import_subscription_document(&format!("socks5://{authority}:1080/"))
            .expect("anonymous SOCKS5 URI");
        let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
        assert_eq!(profile["outbounds"][0]["server"], expected);
        assert!(profile["outbounds"][0].get("authentication").is_none());
        assert!(imported.credentials.is_empty());
    }
}

#[test]
fn socks5_uri_rejects_invalid_authentication_extensions_and_endpoints_without_echoing_secrets() {
    for uri in [
        "socks5://synthetic-user@proxy.example.com:1080",
        "socks5://synthetic-user:@proxy.example.com:1080",
        "socks5://:synthetic-secret@proxy.example.com:1080",
        "socks5://@proxy.example.com:1080",
        "socks5://synthetic-user:synthetic-secret@extra@proxy.example.com:1080",
        "socks5://synthetic-user:%GG@proxy.example.com:1080",
        "socks5://synthetic-user:bad%0Asecret@proxy.example.com:1080",
        "socks5://synthetic-user:synthetic-secret@proxy.example.com:0",
        "socks5://synthetic-user:synthetic-secret@proxy.example.com:65536",
        "socks5://synthetic-user:synthetic-secret@proxy.example.com",
        "socks5://synthetic-user:synthetic-secret@proxy.example.com:1080/path",
        "socks5://synthetic-user:synthetic-secret@proxy.example.com:1080?tls=true",
        "socks5://synthetic-user:synthetic-secret@proxy.example.com:1080?udp-over-tcp=true",
        "socks5://synthetic-user:synthetic-secret@127.0.0.1:1080",
        "socks5://synthetic-user:synthetic-secret@[::1]:1080",
        "socks4://synthetic-user:synthetic-secret@proxy.example.com:1080",
    ] {
        let error = import_subscription_document(uri).expect_err("unsupported SOCKS source");
        assert!(!error.contains("synthetic-user"));
        assert!(!error.contains("synthetic-secret"));
    }
    for pair in [
        "missing-separator".to_owned(),
        "synthetic-user:".to_owned(),
        format!("synthetic-user:{}", "x".repeat(256)),
    ] {
        let uri = format!("socks://{}@proxy.example.com:1080", STANDARD.encode(pair));
        assert!(import_subscription_document(&uri).is_err());
    }
}

#[test]
fn socks5_clash_import_preserves_authentication_and_udp_policy() {
    for (udp, expected_network) in [
        ("", Some("tcp")),
        ("    udp: false\n", Some("tcp")),
        ("    udp: true\n", None),
    ] {
        let body = format!(
            "proxies:\n  - name: SOCKS5\n    type: socks5\n    server: proxy.example.com\n    port: 29177\n    username: '012345'\n    password: ' synthetic-secret '\n{udp}"
        );
        let imported = import_subscription_document(&body).expect("Clash SOCKS5");
        assert_authentication(&imported, "012345", " synthetic-secret ");
        let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
        assert_eq!(
            profile["outbounds"][0]
                .get("network")
                .and_then(Value::as_str),
            expected_network
        );
    }
    let anonymous = "proxies:\n  - { name: SOCKS5, type: socks5, server: proxy.example.com, port: 1080, udp: true }";
    assert!(
        import_subscription_document(anonymous)
            .expect("anonymous Clash SOCKS5")
            .credentials
            .is_empty()
    );
    for extra in [
        "username: synthetic-user",
        "password: synthetic-secret",
        "tls: true",
        "udp-over-tcp: true",
        "udp: 'true'",
        "unexpected: synthetic-secret",
    ] {
        let body = format!(
            "proxies:\n  - name: SOCKS5\n    type: socks5\n    server: proxy.example.com\n    port: 1080\n    {extra}\n"
        );
        let error =
            import_subscription_document(&body).expect_err("unsupported Clash SOCKS5 option");
        assert!(!error.contains("synthetic-secret"));
    }
}

#[test]
fn socks5_sing_box_import_maps_only_version_five_and_preserves_network() {
    for network in [None, Some("tcp"), Some("udp")] {
        let mut node = json!({"type":"socks","tag":"SOCKS5","server":"proxy.example.com","server_port":1080,"username":"synthetic-user","password":"synthetic-secret"});
        if let Some(network) = network {
            node["network"] = json!(network);
        }
        for version in [None, Some("5")] {
            if let Some(version) = version {
                node["version"] = json!(version);
            }
            let imported =
                import_subscription_document(&json!({"outbounds":[node.clone()]}).to_string())
                    .expect("sing-box SOCKS5");
            assert_authentication(&imported, "synthetic-user", "synthetic-secret");
            let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
            assert_eq!(
                profile["outbounds"][0]
                    .get("network")
                    .and_then(Value::as_str),
                network
            );
        }
    }
    let node =
        json!({"type":"socks","tag":"SOCKS5","server":"proxy.example.com","server_port":1080});
    assert!(
        import_subscription_document(&json!({"outbounds":[node.clone()]}).to_string())
            .expect("anonymous sing-box SOCKS5")
            .credentials
            .is_empty()
    );
    for (field, value) in [
        ("version", json!("4")),
        ("version", json!("4a")),
        ("username", json!("synthetic-user")),
        ("password", json!("synthetic-secret")),
        ("network", json!("tcp,udp")),
        ("udp_over_tcp", json!(true)),
        ("tls", json!({"enabled":true})),
    ] {
        let mut invalid = node.clone();
        invalid[field] = value;
        let error = import_subscription_document(&json!({"outbounds":[invalid]}).to_string())
            .expect_err("unsupported sing-box SOCKS5 option");
        assert!(!error.contains("synthetic-secret"));
    }
}

#[test]
fn socks5_bundles_keep_credential_identity_across_preview_and_update() {
    let uri = "socks://synthetic-user:synthetic-secret@proxy.example.com:1080#SOCKS5";
    let namespace = Uuid::parse_str(PROFILE_ID).expect("namespace");
    let first =
        import_subscription_document_with_credential_namespace(uri, namespace).expect("preview");
    let replay = import_subscription_document_with_credential_namespace(uri, namespace)
        .expect("commit reconstruction");
    assert_eq!(first, replay);
    let updated = import_subscription_document_with_reusable_references(
        uri,
        first.profile.credential_references_in_outbound_order(),
    )
    .expect("unchanged update");
    assert_eq!(first, updated);
    let bundle = STANDARD.encode(format!("{uri}\n{uri}"));
    let imported = import_subscription_document(&bundle).expect("base64 SOCKS5 bundle");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(profile["outbounds"][0]["tag"], "SOCKS5");
    assert_eq!(profile["outbounds"][1]["tag"], "SOCKS5-2");
    assert_eq!(imported.credentials.len(), 4);
}

#[test]
fn source_documents_are_bounded_before_parsing_or_base64_expansion() {
    let body = "x".repeat(MAX_SUBSCRIPTION_DOCUMENT_BYTES + 1);
    assert!(
        import_subscription_document(&body)
            .expect_err("oversized source")
            .contains("byte limit")
    );
}

#[test]
fn socks_links_refuse_control_characters_and_other_versions() {
    assert_eq!(
        import_subscription_document("socks5://user:pa\tss@proxy.example.com:1080").map(|_| ()),
        Err("SOCKS5 URI must not contain control characters".into())
    );
    // The bundle reader routes only SOCKS5 schemes here; the parser still
    // refuses any other version.
    assert_eq!(
        OutboundCollector::default()
            .parse_socks5("socks4://proxy.example.com:1080", 0)
            .map(|_| ()),
        Err("SOCKS5 URI has an unsupported version".into())
    );
}
