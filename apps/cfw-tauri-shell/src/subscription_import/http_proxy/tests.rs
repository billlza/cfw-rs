use super::super::import_subscription_document;
use cfw_singbox_config::{CredentialKind, EngineSettings, ProjectionMode};
use serde_json::{Value, json};

#[test]
fn http_sources_keep_transport_and_protocol_specific_private_credentials() {
    for body in [
        "https://alice:p%3Ass@proxy.example.com:8443#Office".to_owned(),
        "proxies:\n  - name: Office\n    type: http\n    server: proxy.example.com\n    port: 8443\n    tls: true\n    username: alice\n    password: p:ss\n".to_owned(),
        json!({"outbounds":[{"type":"http","tag":"Office","server":"proxy.example.com","server_port":8443,"username":"alice","password":"p:ss","tls":{"enabled":true,"server_name":"proxy.example.com"}}]}).to_string(),
    ] {
        let imported=import_subscription_document(&body).unwrap();
        assert_eq!(imported.credentials.len(),2);
        assert_eq!(imported.credentials[0].reference.kind(),CredentialKind::HttpProxyUsername);
        assert_eq!(imported.credentials[1].reference.kind(),CredentialKind::HttpProxyPassword);
        assert_eq!(imported.credentials[1].secret,"p:ss");
        assert!(!imported.profile.as_json().contains("alice"));
        let projected=imported.profile.project("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",ProjectionMode::SystemProxy,&EngineSettings::default()).unwrap();
        let config:Value=serde_json::from_str(projected.as_json()).unwrap();
        assert_eq!(config["outbounds"][0]["type"],"http");
        assert_eq!(config["outbounds"][0]["tls"]["server_name"],"proxy.example.com");
        assert_eq!(projected.credential_slots().len(),2);
    }
}

#[test]
fn http_anonymous_empty_password_and_unsafe_options_remain_distinct() {
    for (source, slots) in [
        ("http://proxy.example.com:8080#Anonymous", 0),
        ("http://alice:@proxy.example.com:8080#Empty", 1),
    ] {
        let imported = import_subscription_document(source).unwrap();
        assert_eq!(imported.credentials.len(), slots);
    }
    for source in [
        "https://a%3Ab:secret@proxy.example.com/#Bad",
        "https://alice:%00@proxy.example.com/#Bad",
        "https://proxy.example.com/?insecure=true#Bad",
        "http://proxy.example.com/?sni=other.example#Bad",
        "http://proxy.example.com/a#Bad",
    ] {
        assert!(import_subscription_document(source).is_err());
    }
}

#[test]
fn http_links_refuse_control_characters_and_other_schemes() {
    assert_eq!(
        import_subscription_document("http://alice:p\tss@proxy.example.com:8080#Bad").map(|_| ()),
        Err("HTTP proxy URI contains control characters".into())
    );
    // The bundle reader routes only HTTP schemes here; the parser still
    // refuses any other.
    assert_eq!(
        super::super::OutboundCollector::default()
            .parse_http_proxy("ftp://proxy.example.com:21", 0)
            .map(|_| ()),
        Err("HTTP proxy URI scheme is invalid".into())
    );
}
